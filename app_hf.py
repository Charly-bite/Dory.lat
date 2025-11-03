"""
Flask app using HuggingFace Inference API instead of local models.
Ultra-lightweight - no heavy ML libraries loaded locally.
"""
import os
import re
import logging
from flask import Flask, request, render_template, jsonify
import requests

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# --- Flask App ---
app = Flask(__name__)

# --- HuggingFace Configuration ---
# You'll need to set this as an environment variable in Render
HF_API_TOKEN = os.environ.get('HF_API_TOKEN', '')  # Get from Render env vars
HF_API_URL = "https://api-inference.huggingface.co/models/"

# Model endpoints (you can upload your model or use similar ones)
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"  # For text embeddings
# For your Keras model, you'd need to convert it or use a similar classifier

# --- Simple feature extraction (lightweight, no NLTK needed for basic version) ---
def extract_basic_features(text):
    """Extract comprehensive features for phishing detection."""
    if not text or not isinstance(text, str):
        text = ""
    
    text_lower = text.lower()
    
    # Extract URLs for detailed analysis
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.download', '.bid']
    has_suspicious_tld = any(any(tld in url.lower() for tld in suspicious_tlds) for url in urls)
    
    # URL shorteners
    url_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    has_url_shortener = any(any(shortener in url.lower() for shortener in url_shorteners) for url in urls)
    
    # Check for IP addresses in URLs
    has_ip_in_url = any(re.search(r'https?://\d+\.\d+\.\d+\.\d+', url) for url in urls)
    
    # Phishing keywords in Spanish and English
    phishing_keywords_es = ['urgente', 'verificar', 'suspender', 'bloquead', 'confirm', 'actualiz', 
                            'caduc', 'expir', 'inmediatamente', 'premio', 'ganador', 'ganaste',
                            'reclam', 'haga clic', 'click aqui', 'alert', 'seguridad', 'cuenta',
                            'tarjeta', 'contraseña', 'clave', 'pin']
    
    phishing_keywords_en = ['urgent', 'verify', 'suspend', 'blocked', 'confirm', 'update',
                           'expire', 'immediately', 'prize', 'winner', 'won', 'claim',
                           'click here', 'alert', 'security', 'account', 'card', 'password', 'pin']
    
    all_keywords = phishing_keywords_es + phishing_keywords_en
    keyword_matches = sum(1 for keyword in all_keywords if keyword in text_lower)
    
    # Check for social engineering tactics
    urgency_phrases = ['24 hours', '24 horas', 'immediately', 'inmediatamente', 'right now', 
                      'ahora mismo', 'expire today', 'expira hoy', 'final notice', 'aviso final',
                      'last chance', 'última oportunidad', 'act now', 'actúa ahora']
    has_urgency = any(phrase in text_lower for phrase in urgency_phrases)
    
    # Financial/credential requests
    credential_words = ['password', 'contraseña', 'social security', 'ssn', 'credit card', 
                       'tarjeta', 'bank account', 'cuenta bancaria', 'pin', 'cvv']
    requests_credentials = any(word in text_lower for word in credential_words)
    
    # Too-good-to-be-true offers
    offer_words = ['free iphone', 'iphone gratis', 'won', 'ganaste', 'winner', 'ganador',
                  'prize', 'premio', 'lottery', 'lotería', '$1,000', '1000 USD']
    has_unrealistic_offer = any(word in text_lower for word in offer_words)
    
    # Emoji spam (common in phishing)
    emoji_pattern = re.compile("["
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map symbols
        u"\U0001F1E0-\U0001F1FF"  # flags
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE)
    emoji_count = len(emoji_pattern.findall(text))
    
    # Excessive punctuation
    multiple_exclamation = len(re.findall(r'!{2,}', text))
    multiple_question = len(re.findall(r'\?{2,}', text))
    
    # Greeting mismatch (generic greetings are suspicious)
    generic_greetings = ['dear customer', 'estimado cliente', 'dear user', 'estimado usuario',
                        'dear sir', 'estimado señor', 'valued customer', 'cliente valorado']
    has_generic_greeting = any(greeting in text_lower for greeting in generic_greetings)
    
    # Misspellings of common brands (typosquatting)
    brand_typos = ['paypa1', 'g00gle', 'micros0ft', 'amaz0n', 'facebok', 'faceb00k', 
                   'appl3', 'netfIix', 'netfl1x']
    has_brand_typo = any(typo in text_lower for typo in brand_typos)
    
    # Basic text metrics
    features = {
        'length': len(text),
        'word_count': len(text.split()),
        'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
        'digit_count': sum(1 for c in text if c.isdigit()),
        'exclamation_count': text.count('!'),
        'question_count': text.count('?'),
        'url_count': len(urls),
        'email_count': len(re.findall(r'\S+@\S+', text)),
        
        # Advanced features
        'has_suspicious_tld': has_suspicious_tld,
        'has_url_shortener': has_url_shortener,
        'has_ip_in_url': has_ip_in_url,
        'keyword_matches': keyword_matches,
        'has_urgency': has_urgency,
        'requests_credentials': requests_credentials,
        'has_unrealistic_offer': has_unrealistic_offer,
        'emoji_count': emoji_count,
        'multiple_exclamation': multiple_exclamation,
        'multiple_question': multiple_question,
        'has_generic_greeting': has_generic_greeting,
        'has_brand_typo': has_brand_typo,
    }
    
    return features

def get_hf_embeddings(text):
    """Get text embeddings from HuggingFace API."""
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    
    response = requests.post(
        f"{HF_API_URL}{EMBEDDING_MODEL}",
        headers=headers,
        json={"inputs": text}
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"HF API error: {response.status_code} - {response.text}")
        return None

def predict_phishing_hf(text):
    """
    Enhanced prediction using comprehensive heuristics.
    
    Scoring system based on multiple phishing indicators.
    Returns probability score from 0 (legitimate) to 1 (phishing).
    """
    
    # Extract comprehensive features
    features = extract_basic_features(text)
    
    # Get embeddings from HF (optional, for future ML model)
    # embeddings = get_hf_embeddings(text)
    
    # Advanced scoring system with weighted factors
    risk_score = 0
    max_score = 0
    
    # URL-based indicators (high weight)
    if features['url_count'] > 0:
        max_score += 25
        if features['url_count'] > 3:
            risk_score += 25  # Multiple URLs is very suspicious
        elif features['url_count'] > 1:
            risk_score += 15
        else:
            risk_score += 5
    
    if features['has_suspicious_tld']:
        risk_score += 20
        max_score += 20
    
    if features['has_url_shortener']:
        risk_score += 15
        max_score += 15
    
    if features['has_ip_in_url']:
        risk_score += 25  # IP in URL is highly suspicious
        max_score += 25
    
    # Keyword-based indicators (medium-high weight)
    max_score += 20
    if features['keyword_matches'] > 5:
        risk_score += 20
    elif features['keyword_matches'] > 3:
        risk_score += 15
    elif features['keyword_matches'] > 0:
        risk_score += 10
    
    # Social engineering tactics (high weight)
    if features['has_urgency']:
        risk_score += 20
        max_score += 20
    
    if features['requests_credentials']:
        risk_score += 25  # Asking for credentials is major red flag
        max_score += 25
    
    if features['has_unrealistic_offer']:
        risk_score += 20
        max_score += 20
    
    # Typosquatting (high weight)
    if features['has_brand_typo']:
        risk_score += 25
        max_score += 25
    
    # Generic greeting (medium weight)
    if features['has_generic_greeting']:
        risk_score += 10
        max_score += 10
    
    # Formatting indicators (medium weight)
    max_score += 15
    if features['uppercase_ratio'] > 0.4:
        risk_score += 15  # Excessive caps
    elif features['uppercase_ratio'] > 0.3:
        risk_score += 10
    elif features['uppercase_ratio'] > 0.2:
        risk_score += 5
    
    max_score += 10
    if features['exclamation_count'] > 5:
        risk_score += 10
    elif features['exclamation_count'] > 3:
        risk_score += 7
    elif features['exclamation_count'] > 1:
        risk_score += 3
    
    if features['multiple_exclamation'] > 0:
        risk_score += 8
        max_score += 8
    
    if features['multiple_question'] > 0:
        risk_score += 5
        max_score += 5
    
    # Emoji spam (low-medium weight)
    max_score += 10
    if features['emoji_count'] > 5:
        risk_score += 10
    elif features['emoji_count'] > 3:
        risk_score += 6
    
    # Ensure max_score is never zero
    if max_score == 0:
        max_score = 100
    
    # Normalize to 0-1 probability
    probability = min(risk_score / max_score, 1.0)
    
    # Apply threshold with some wiggle room
    # Very low scores (<0.2) are clearly legitimate
    # Very high scores (>0.7) are clearly phishing
    # Middle range (0.2-0.7) is uncertain but we lean towards caution
    
    if probability < 0.2:
        is_phishing = False
        confidence_boost = 0.1  # Boost confidence for clear legitimate emails
    elif probability > 0.7:
        is_phishing = True
        confidence_boost = 0.1  # Boost confidence for clear phishing
    else:
        # Uncertain range - classify as phishing if > 0.5, but with lower confidence
        is_phishing = probability > 0.5
        confidence_boost = -0.1  # Reduce confidence for uncertain cases
    
    final_confidence = min(max(probability + confidence_boost, 0.0), 1.0)
    
    return {
        'is_phishing': is_phishing,
        'confidence': final_confidence,
        'features': features,
        'risk_score': risk_score,
        'max_possible_score': max_score
    }

# --- Routes ---
@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Render."""
    return jsonify({
        'status': 'healthy',
        'service': 'dory-phishing-detector-hf',
        'version': '2.1-enhanced-heuristics'
    }), 200

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict if email is phishing using HuggingFace API.
    
    Accepts both JSON and form data:
    - JSON: {"subject": "...", "body": "..."}
    - Form: subject=...&body=...
    """
    try:
        # Check if JSON or form data
        if request.is_json:
            data = request.get_json()
            # Combine subject and body from JSON
            subject = data.get('subject', '')
            body = data.get('body', '')
            full_text = f"{subject}\n{body}".strip()
        else:
            # Handle form data from HTML form
            # The form sends 'email_text' as a single field
            full_text = request.form.get('email_text', '').strip()
            
            # Also check for separate subject/body fields (for API compatibility)
            if not full_text:
                subject = request.form.get('subject', '')
                body = request.form.get('body', '')
                full_text = f"{subject}\n{body}".strip()
        
        if not full_text:
            return jsonify({'error': 'No text provided'}), 400
        
        logger.info("Processing prediction request...")
        
        # Get prediction from HuggingFace
        result = predict_phishing_hf(full_text)
        
        # Calculate confidence based on prediction
        # If it's phishing, confidence = probability of phishing
        # If it's legitimate, confidence = probability of legitimate
        is_phishing = result['is_phishing']
        phishing_prob = float(result['confidence'])
        legitimate_prob = float(1 - result['confidence'])
        
        # Confidence is the probability of the predicted class
        confidence = phishing_prob if is_phishing else legitimate_prob
        
        # Build list of detected threats
        threats_detected = []
        if result['features']['has_suspicious_tld']:
            threats_detected.append('Suspicious domain extension')
        if result['features']['has_url_shortener']:
            threats_detected.append('URL shortener detected')
        if result['features']['has_ip_in_url']:
            threats_detected.append('IP address in URL')
        if result['features']['has_urgency']:
            threats_detected.append('Urgent language tactics')
        if result['features']['requests_credentials']:
            threats_detected.append('Requests credentials')
        if result['features']['has_unrealistic_offer']:
            threats_detected.append('Too-good-to-be-true offer')
        if result['features']['has_brand_typo']:
            threats_detected.append('Brand name misspelling')
        if result['features']['has_generic_greeting']:
            threats_detected.append('Generic greeting')
        if result['features']['uppercase_ratio'] > 0.3:
            threats_detected.append('Excessive capitalization')
        if result['features']['keyword_matches'] > 3:
            threats_detected.append(f'{result["features"]["keyword_matches"]} phishing keywords')
        
        response = {
            'prediction': 'PHISHING' if is_phishing else 'LEGITIMATE',
            'confidence': confidence,
            'probability_phishing': phishing_prob,
            'probability_legitimate': legitimate_prob,
            'threats_detected': threats_detected,
            'analysis': {
                'text_length': result['features']['length'],
                'word_count': result['features']['word_count'],
                'url_count': result['features']['url_count'],
                'uppercase_ratio': round(result['features']['uppercase_ratio'], 3),
                'exclamation_marks': result['features']['exclamation_count'],
                'question_marks': result['features']['question_count'],
                'emoji_count': result['features']['emoji_count'],
                'phishing_keywords': result['features']['keyword_matches'],
                'risk_score': f"{result['risk_score']}/{result['max_possible_score']}"
            },
            'flags': {
                'suspicious_tld': result['features']['has_suspicious_tld'],
                'url_shortener': result['features']['has_url_shortener'],
                'ip_in_url': result['features']['has_ip_in_url'],
                'urgency_tactics': result['features']['has_urgency'],
                'credential_request': result['features']['requests_credentials'],
                'unrealistic_offer': result['features']['has_unrealistic_offer'],
                'brand_typo': result['features']['has_brand_typo'],
                'generic_greeting': result['features']['has_generic_greeting']
            },
            'model': 'enhanced-heuristics',
            'version': '2.1'
        }
        
        logger.info(f"Prediction: {response['prediction']} (confidence: {confidence:.2f})")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Prediction failed',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    # Development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
