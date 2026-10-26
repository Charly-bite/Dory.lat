/**
 * Cloudflare Email Worker: dory-email-router
 * 
 * Flujo de Ingesta Inteligente Directa:
 * Transmite el correo en bruto (RFC822) al motor de IA de Dory vía Cloudflare Tunnel (engine.dory.mx)
 * para análisis y entrega inmediata al buzón de Stalwart / Thunderbird.
 *
 * Variables (wrangler secret / vars):
 *   DORY_SECRET_KEY        (obligatoria) mismo valor que DORY_WEBHOOK_SECRET en el motor
 *   DORY_INBOUND_URL       (opcional) endpoint del motor
 *   DORY_FALLBACK_FORWARD  (opcional) dirección verificada a la que reenviar si el motor no responde
 *
 * Cambios v4:
 *   - Sin secreto por defecto en el código (estaba publicado en el repo).
 *   - Reintentos con backoff solo ante errores transitorios (red / 5xx / 429 / 403 WAF).
 *   - Si el motor no responde, el correo ya no se pierde en silencio: se reenvía a
 *     DORY_FALLBACK_FORWARD o se rechaza para que el remitente reciba el aviso de no entrega.
 */

const MAX_ATTEMPTS = 3;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function failSafe(message, env, reason) {
  console.error(`[Dory Router] ${reason} | from='${message.from}' to='${message.to}'`);
  if (env.DORY_FALLBACK_FORWARD) {
    try {
      await message.forward(env.DORY_FALLBACK_FORWARD);
      console.warn(`[Dory Router] Fallback: reenviado sin análisis a ${env.DORY_FALLBACK_FORWARD}`);
      return;
    } catch (err) {
      console.error("[Dory Router] Fallback forward failed:", err);
    }
  }
  message.setReject("Dory: servicio de análisis temporalmente no disponible, intente más tarde");
}

export default {
  async email(message, env, ctx) {
    const doryInboundUrl = env.DORY_INBOUND_URL || "https://engine.dory.mx/api/mail/inbound";
    const dorySecretKey = env.DORY_SECRET_KEY;

    if (!dorySecretKey) {
      await failSafe(message, env, "DORY_SECRET_KEY no configurado en el Worker");
      return;
    }

    console.log(`[Dory Router] Inbound email from '${message.from}' to '${message.to}'`);

    // 1. Leer el flujo de bytes MIME en bruto (RFC822)
    let rawEmailBuffer;
    try {
      rawEmailBuffer = await new Response(message.raw).arrayBuffer();
    } catch (err) {
      await failSafe(message, env, `Error reading message.raw stream: ${err}`);
      return;
    }

    // 2. Despachar al motor autónomo de Dory vía Cloudflare Tunnel
    //    NOTA: User-Agent es obligatorio para evitar bloqueo por Cloudflare WAF (error 1010)
    const fetchHeaders = {
      "Content-Type": "message/rfc822",
      "X-Dory-Key": dorySecretKey,
      "X-Dory-Sender": message.from,
      "X-Dory-Recipient": message.to,
      "User-Agent": "Dory-Email-Router/1.1 (Cloudflare Worker)",
      "Accept": "application/json"
    };

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      let transient = true;
      try {
        const res = await fetch(doryInboundUrl, {
          method: "POST",
          headers: fetchHeaders,
          body: rawEmailBuffer
        });
        const resText = (await res.text()).slice(0, 300);
        console.log(`[Dory Router] Attempt ${attempt} | Dory Engine response: ${res.status} | Body: ${resText}`);
        if (res.ok) {
          return;
        }
        // 403 puede ser WAF (transitorio) o clave inválida; 400 = payload inválido (no reintentar)
        transient = res.status >= 500 || res.status === 429 || res.status === 403;
      } catch (err) {
        console.error(`[Dory Router] Attempt ${attempt} failed:`, err);
      }
      if (!transient || attempt === MAX_ATTEMPTS) break;
      await sleep(500 * 2 ** (attempt - 1)); // 0.5s, 1s
    }

    await failSafe(message, env, "All delivery attempts to Dory Engine failed");
  }
};
