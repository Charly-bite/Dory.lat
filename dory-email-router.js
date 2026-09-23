/**
 * Cloudflare Email Worker: dory-email-router
 * 
 * Flujo Dual de Ingesta Inteligente:
 * 1. Envía copia de supervisión al buzón UDG de Mr. Dev (carlos.aceves6195@alumnos.udg.mx) durante 2 semanas de pruebas.
 * 2. Transmite el correo en bruto (RFC822) al motor de IA de Dory vía Cloudflare Zero Trust Tunnel (engine.dory.mx).
 */

export default {
  async email(message, env, ctx) {
    const supervisoryAddress = "carlos.aceves6195@alumnos.udg.mx";
    const doryInboundUrl = env.DORY_INBOUND_URL || "https://engine.dory.mx/api/mail/inbound";
    const dorySecretKey = env.DORY_SECRET_KEY || "dory-sec-defense-key-2026";

    console.log(`[Dory Router] Inbound email from '${message.from}' to '${message.to}'`);

    // 1. Leer el flujo de bytes MIME en bruto (RFC822) antes de que se consuma
    let rawEmailBuffer;
    try {
      rawEmailBuffer = await new Response(message.raw).arrayBuffer();
    } catch (err) {
      console.error("[Dory Router] Error reading message.raw stream:", err);
    }

    // 2. Despachar copia de supervisión a Carlos UDG (2 semanas de pruebas)
    const forwardTask = (async () => {
      try {
        await message.forward(supervisoryAddress);
        console.log(`[Dory Router] Supervisory copy forwarded successfully to ${supervisoryAddress}`);
      } catch (err) {
        console.error(`[Dory Router] Failed to forward supervisory copy to ${supervisoryAddress}:`, err);
      }
    })();

    // 3. Despachar al motor autónomo de Dory vía Cloudflare Tunnel
    const webhookTask = (async () => {
      if (!rawEmailBuffer) {
        console.warn("[Dory Router] No raw buffer available to send to Dory engine");
        return;
      }
      try {
        const res = await fetch(doryInboundUrl, {
          method: "POST",
          headers: {
            "Content-Type": "message/rfc822",
            "X-Dory-Key": dorySecretKey,
            "X-Dory-Sender": message.from,
            "X-Dory-Recipient": message.to
          },
          body: rawEmailBuffer
        });
        const resText = await res.text();
        console.log(`[Dory Router] Dory Engine response code: ${res.status} | Body: ${resText}`);
      } catch (err) {
        console.error("[Dory Router] Failed to push email to Dory Engine:", err);
      }
    })();

    // Esperar la culminación de ambas operaciones de forma resiliente
    await Promise.allSettled([forwardTask, webhookTask]);
  }
};
