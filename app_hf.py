"""
Flask app using HuggingFace Inference API instead of local models.
Ultra-lightweight - no heavy ML libraries loaded locally.
"""
import os
import re
import logging
import sqlite3
import json
from datetime import datetime
from flask import Flask, request, render_template, jsonify
from functools import wraps
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

# --- Google Safe Browsing Configuration ---
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# --- Database Configuration ---
DATABASE_PATH = os.path.join(APP_ROOT, 'feedback.db')

def init_database():
    """Initialize SQLite database for user feedback."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            email_text TEXT NOT NULL,
            prediction TEXT NOT NULL,
            user_feedback TEXT NOT NULL,
            confidence REAL,
            risk_score TEXT,
            threats_detected TEXT,
            google_safe_browsing_checked BOOLEAN,
            google_safe_browsing_safe BOOLEAN,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DATABASE_PATH}")

# Initialize database on startup
init_database()

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

def check_urls_with_safe_browsing(urls):
    """
    Check URLs against Google Safe Browsing API.
    
    Args:
        urls: List of URLs to check
        
    Returns:
        dict: {
            'malicious_urls': list of malicious URLs found,
            'threats_found': list of threat types,
            'is_safe': bool
        }
    """
    if not urls or not GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': bool(GOOGLE_SAFE_BROWSING_API_KEY)
        }
    
    # Prepare the request payload
    threat_entries = [{"url": url} for url in urls]
    
    payload = {
        "client": {
            "clientId": "dory-phishing-detector",
            "clientVersion": "2.1"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }
    
    try:
        response = requests.post(
            f"{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Parse the response
            matches = result.get('matches', [])
            malicious_urls = []
            threats_found = []
            
            for match in matches:
                url = match.get('threat', {}).get('url', '')
                threat_type = match.get('threatType', '')
                
                if url and url not in malicious_urls:
                    malicious_urls.append(url)
                
                if threat_type and threat_type not in threats_found:
                    # Convert threat type to user-friendly name
                    threat_mapping = {
                        'MALWARE': 'Malware',
                        'SOCIAL_ENGINEERING': 'Phishing/Social Engineering',
                        'UNWANTED_SOFTWARE': 'Unwanted Software',
                        'POTENTIALLY_HARMFUL_APPLICATION': 'Harmful Application'
                    }
                    threats_found.append(threat_mapping.get(threat_type, threat_type))
            
            return {
                'malicious_urls': malicious_urls,
                'threats_found': threats_found,
                'is_safe': len(malicious_urls) == 0,
                'api_available': True
            }
        else:
            logger.error(f"Google Safe Browsing API error: {response.status_code}")
            return {
                'malicious_urls': [],
                'threats_found': [],
                'is_safe': True,
                'api_available': True,
                'error': f"API returned {response.status_code}"
            }
            
    except requests.exceptions.Timeout:
        logger.warning("Google Safe Browsing API timeout")
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': True,
            'error': 'API timeout'
        }
    except Exception as e:
        logger.error(f"Google Safe Browsing API error: {str(e)}")
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': True,
            'error': str(e)
        }

def predict_phishing_hf(text):
    """
    Enhanced prediction using comprehensive heuristics + Google Safe Browsing.
    
    Scoring system based on multiple phishing indicators.
    Returns probability score from 0 (legitimate) to 1 (phishing).
    """
    
    # Extract comprehensive features
    features = extract_basic_features(text)
    
    # Extract URLs from text for Google Safe Browsing check
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    # Check URLs with Google Safe Browsing API
    safe_browsing_result = check_urls_with_safe_browsing(urls)
    
    # Get embeddings from HF (optional, for future ML model)
    # embeddings = get_hf_embeddings(text)
    
    # Advanced scoring system with weighted factors
    # Weights optimized based on real-world effectiveness (v2.3 stable)
    risk_score = 0
    max_score = 0
    
    # === TIER 1: Critical Indicators (50-30 points) ===
    # These are highly reliable and rarely give false positives
    
    # Google Safe Browsing check (HIGHEST PRIORITY - 50 points)
    if not safe_browsing_result['is_safe']:
        risk_score += 50  # Confirmed malicious by Google's database
        max_score += 50
    elif safe_browsing_result['api_available']:
        max_score += 50  # Add to max_score even if safe (for normalization)
    
    # IP address in URL (35 points) - Extremely suspicious
    if features['has_ip_in_url']:
        risk_score += 35
        max_score += 35
    
    # Credential request (30 points) - Major phishing indicator
    if features['requests_credentials']:
        risk_score += 30
        max_score += 30
    
    # === TIER 2: Strong Indicators (25-15 points) ===
    # These are very good indicators but can occasionally appear in legitimate emails
    
    # Brand name typosquatting (25 points)
    if features['has_brand_typo']:
        risk_score += 25
        max_score += 25
    
    # Multiple URLs (20-25 points based on count)
    if features['url_count'] > 0:
        max_score += 25
        if features['url_count'] > 4:
            risk_score += 25  # Many URLs is very suspicious
        elif features['url_count'] > 2:
            risk_score += 18
        elif features['url_count'] > 1:
            risk_score += 12
        else:
            risk_score += 6  # Single URL is slightly suspicious
    
    # Suspicious TLD (20 points)
    if features['has_suspicious_tld']:
        risk_score += 20
        max_score += 20
    
    # Urgency tactics (20 points)
    if features['has_urgency']:
        risk_score += 20
        max_score += 20
    
    # Too-good-to-be-true offers (18 points)
    if features['has_unrealistic_offer']:
        risk_score += 18
        max_score += 18
    
    # === TIER 3: Moderate Indicators (15-10 points) ===
    # Useful but can appear in both legitimate and phishing emails
    
    # URL shorteners (15 points)
    if features['has_url_shortener']:
        risk_score += 15
        max_score += 15
    
    # Phishing keywords (12-20 points based on count)
    max_score += 20
    if features['keyword_matches'] > 6:
        risk_score += 20
    elif features['keyword_matches'] > 4:
        risk_score += 16
    elif features['keyword_matches'] > 2:
        risk_score += 12
    elif features['keyword_matches'] > 0:
        risk_score += 8
    
    # Generic greeting (10 points)
    if features['has_generic_greeting']:
        risk_score += 10
        max_score += 10
    
    # === TIER 4: Minor Indicators (8-3 points) ===
    # Weak signals that add up when combined
    
    # Excessive capitalization (5-12 points)
    max_score += 12
    if features['uppercase_ratio'] > 0.5:
        risk_score += 12  # More than 50% caps is very unusual
    elif features['uppercase_ratio'] > 0.35:
        risk_score += 8
    elif features['uppercase_ratio'] > 0.25:
        risk_score += 5
    elif features['uppercase_ratio'] > 0.15:
        risk_score += 3
    
    # Excessive exclamation marks (3-8 points)
    max_score += 8
    if features['exclamation_count'] > 6:
        risk_score += 8
    elif features['exclamation_count'] > 4:
        risk_score += 6
    elif features['exclamation_count'] > 2:
        risk_score += 4
    elif features['exclamation_count'] > 0:
        risk_score += 2
    
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
    probability = min(risk_score / max_score, 1.0) if max_score > 0 else 0.0
    
    # Apply calibrated thresholds (optimized for v2.3)
    # Thresholds designed to minimize false positives while catching real threats
    
    if probability < 0.15:
        # Very low risk - clearly legitimate
        is_phishing = False
        confidence_boost = 0.15  # High confidence in legitimate classification
    elif probability < 0.35:
        # Low-medium risk - likely legitimate but some red flags
        is_phishing = False
        confidence_boost = 0.05  # Moderate confidence
    elif probability < 0.55:
        # Medium risk - uncertain, could go either way
        # Default to SAFE (legitimate) to avoid false alarms
        is_phishing = False
        confidence_boost = -0.10  # Low confidence, borderline case
    elif probability < 0.75:
        # Medium-high risk - likely phishing
        is_phishing = True
        confidence_boost = 0.0  # Neutral confidence
    else:
        # High risk - very likely phishing
        is_phishing = True
        confidence_boost = 0.12  # High confidence in phishing classification
    
    # Ensure confidence stays in valid range [0, 1]
    final_confidence = min(max(probability + confidence_boost, 0.0), 1.0)
    
    return {
        'is_phishing': is_phishing,
        'confidence': final_confidence,
        'features': features,
        'risk_score': risk_score,
        'max_possible_score': max_score,
        'safe_browsing': safe_browsing_result
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
        'version': '2.5-history-system',
        'features': {
            'enhanced_heuristics': True,
            'google_safe_browsing': bool(GOOGLE_SAFE_BROWSING_API_KEY),
            'bilingual_support': True,
            'user_feedback_system': True,
            'light_dark_theme': True,
            'analysis_history': True
        }
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
        # Debug logging
        print(f"DEBUG: Request content type: {request.content_type}")
        if request.is_json:
            print(f"DEBUG: JSON data: {request.get_json()}")
        else:
            print(f"DEBUG: Form data: {request.form}")

        # Check if JSON or form data
        if request.is_json:
            data = request.get_json()
            
            # Robustness: Handle case where get_json() returns None
            if data is None:
                try:
                    import json
                    data = json.loads(request.get_data(as_text=True))
                    print(f"DEBUG: Manually parsed JSON: {data}")
                except Exception as e:
                    print(f"DEBUG: Failed to manually parse JSON: {e}")
                    data = {}

            # Try to get email_text first (standard for this app)
            if 'email_text' in data:
                full_text = data['email_text'].strip()
            else:
                # Fallback to subject/body (for API compatibility)
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
            received_keys = list(data.keys()) if request.is_json and data else list(request.form.keys())
            return jsonify({'error': f'No text provided. Received keys: {received_keys}. Content-Type: {request.content_type}'}), 400
        
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
        
        # Google Safe Browsing threats (highest priority)
        if result.get('safe_browsing') and not result['safe_browsing']['is_safe']:
            for threat in result['safe_browsing']['threats_found']:
                threats_detected.append(f'Google Safe Browsing: {threat}')
        
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
        
        # Prepare Google Safe Browsing info
        safe_browsing_info = result.get('safe_browsing', {})
        google_verdict = {
            'checked': safe_browsing_info.get('api_available', False),
            'is_safe': safe_browsing_info.get('is_safe', True),
            'malicious_urls': safe_browsing_info.get('malicious_urls', []),
            'threats_found': safe_browsing_info.get('threats_found', [])
        }
        
        response = {
            'prediction': 'PHISHING' if is_phishing else 'LEGITIMATE',
            'confidence': confidence,
            'probability_phishing': phishing_prob,
            'probability_legitimate': legitimate_prob,
            'threats_detected': threats_detected,
            'google_safe_browsing': google_verdict,
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
            'model': 'enhanced-heuristics-with-safe-browsing',
            'version': '2.3'
        }
        
        logger.info(f"Prediction: {response['prediction']} (confidence: {confidence:.2f})")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Prediction failed',
            'details': str(e)
        }), 500

# --- Feedback Endpoint ---
@app.route('/feedback', methods=['POST'])
def submit_feedback():
    """Store user feedback about prediction accuracy."""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email_text', 'prediction', 'user_feedback']
        if not all(field in data for field in required_fields):
            return jsonify({
                'error': 'Missing required fields',
                'required': required_fields
            }), 400
        
        # Validate user_feedback value
        if data['user_feedback'] not in ['correct', 'incorrect']:
            return jsonify({
                'error': 'Invalid user_feedback value',
                'allowed': ['correct', 'incorrect']
            }), 400
        
        # Get client info
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Store in database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO feedback (
                email_text, prediction, user_feedback, confidence, 
                risk_score, threats_detected, google_safe_browsing_checked,
                google_safe_browsing_safe, ip_address, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['email_text'],
            data['prediction'],
            data['user_feedback'],
            data.get('confidence'),
            data.get('risk_score'),
            json.dumps(data.get('threats_detected', [])),
            data.get('google_safe_browsing_checked', False),
            data.get('google_safe_browsing_safe', True),
            ip_address,
            user_agent
        ))
        
        conn.commit()
        feedback_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"Feedback received: {data['user_feedback']} for prediction {data['prediction']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Feedback recorded successfully',
            'feedback_id': feedback_id
        }), 200
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to record feedback',
            'details': str(e)
        }), 500

# --- Admin Dashboard ---
def check_auth(username, password):
    """Check if username/password is valid."""
    # Simple authentication - in production, use environment variables
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'dory2024')
    return username == admin_user and password == admin_pass

def authenticate():
    """Send 401 response for authentication."""
    return jsonify({'error': 'Authentication required'}), 401, {
        'WWW-Authenticate': 'Basic realm="Admin Access"'
    }

def requires_auth(f):
    """Decorator for routes that require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/feedback', methods=['GET'])
@requires_auth
def view_feedback():
    """Admin endpoint to view feedback statistics and data."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_feedback,
                SUM(CASE WHEN user_feedback = 'correct' THEN 1 ELSE 0 END) as correct_predictions,
                SUM(CASE WHEN user_feedback = 'incorrect' THEN 1 ELSE 0 END) as incorrect_predictions,
                SUM(CASE WHEN prediction = 'PHISHING' THEN 1 ELSE 0 END) as phishing_predictions,
                SUM(CASE WHEN prediction = 'LEGITIMATE' THEN 1 ELSE 0 END) as legitimate_predictions
            FROM feedback
        ''')
        stats = dict(cursor.fetchone())
        
        # Calculate accuracy
        total = stats['total_feedback']
        if total > 0:
            stats['accuracy'] = round((stats['correct_predictions'] / total) * 100, 2)
        else:
            stats['accuracy'] = 0
        
        # Get recent feedback (last 100)
        cursor.execute('''
            SELECT 
                id, timestamp, email_text, prediction, user_feedback, 
                confidence, risk_score, threats_detected,
                google_safe_browsing_checked, google_safe_browsing_safe
            FROM feedback
            ORDER BY timestamp DESC
            LIMIT 100
        ''')
        
        recent_feedback = []
        for row in cursor.fetchall():
            feedback_item = dict(row)
            # Parse JSON fields
            if feedback_item['threats_detected']:
                try:
                    feedback_item['threats_detected'] = json.loads(feedback_item['threats_detected'])
                except:
                    feedback_item['threats_detected'] = []
            recent_feedback.append(feedback_item)
        
        conn.close()
        
        return jsonify({
            'statistics': stats,
            'recent_feedback': recent_feedback
        }), 200
        
    except Exception as e:
        logger.error(f"Admin feedback error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to retrieve feedback',
            'details': str(e)
        }), 500

@app.route('/admin/feedback/export', methods=['GET'])
@requires_auth
def export_feedback():
    """Export all feedback data as JSON."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM feedback ORDER BY timestamp DESC')
        
        feedback_data = []
        for row in cursor.fetchall():
            feedback_item = dict(row)
            # Parse JSON fields
            if feedback_item['threats_detected']:
                try:
                    feedback_item['threats_detected'] = json.loads(feedback_item['threats_detected'])
                except:
                    feedback_item['threats_detected'] = []
            feedback_data.append(feedback_item)
        
        conn.close()
        
        return jsonify({
            'total_records': len(feedback_data),
            'export_date': datetime.now().isoformat(),
            'data': feedback_data
        }), 200
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to export feedback',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    # Development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
