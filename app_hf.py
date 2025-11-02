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
    """Extract simple features without heavy NLP libraries."""
    if not text or not isinstance(text, str):
        text = ""
    
    # Basic text metrics
    features = {
        'length': len(text),
        'word_count': len(text.split()),
        'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
        'digit_count': sum(1 for c in text if c.isdigit()),
        'exclamation_count': text.count('!'),
        'question_count': text.count('?'),
        'url_count': len(re.findall(r'http[s]?://', text)),
        'email_count': len(re.findall(r'\S+@\S+', text)),
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
    Simplified prediction using HuggingFace models.
    
    Option 1: Use HF hosted classification model
    Option 2: Use embeddings + simple heuristics
    Option 3: Upload your trained model to HF and call it
    """
    
    # Extract basic features
    features = extract_basic_features(text)
    
    # Get embeddings from HF
    embeddings = get_hf_embeddings(text)
    
    # Simple heuristic-based scoring (replace with actual HF model call)
    # This is a placeholder - you'd call your actual model on HF
    risk_score = 0
    
    # Heuristic rules (temporary until you upload your model)
    if features['url_count'] > 2:
        risk_score += 30
    if features['uppercase_ratio'] > 0.3:
        risk_score += 20
    if features['exclamation_count'] > 3:
        risk_score += 15
    if 'urgent' in text.lower() or 'verify' in text.lower():
        risk_score += 25
    if features['email_count'] > 0:
        risk_score += 10
    
    # Normalize to 0-1
    probability = min(risk_score / 100, 1.0)
    
    return {
        'is_phishing': probability > 0.5,
        'confidence': probability,
        'features': features
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
        'version': '2.0-huggingface'
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
        
        response = {
            'prediction': 'PHISHING' if result['is_phishing'] else 'LEGITIMATE',
            'confidence': float(result['confidence']),
            'probability_phishing': float(result['confidence']),
            'probability_legitimate': float(1 - result['confidence']),
            'analysis': {
                'text_length': result['features']['length'],
                'word_count': result['features']['word_count'],
                'suspicious_patterns': {
                    'urls': result['features']['url_count'],
                    'excessive_caps': result['features']['uppercase_ratio'] > 0.3,
                    'urgent_language': result['features']['exclamation_count'] > 3
                }
            },
            'model': 'huggingface-inference',
            'version': '2.0'
        }
        
        logger.info(f"Prediction: {response['prediction']} (confidence: {response['confidence']:.2f})")
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
