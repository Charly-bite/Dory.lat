"""
Optimized Flask app for Render with LAZY MODEL LOADING.
Models are loaded on first prediction request, not during import.
This allows Gunicorn to start and bind to port immediately.
"""
import os
import logging
import time
from collections import defaultdict
from flask import Flask, request, render_template
from threading import Lock, Thread
import signal

# --- Basic Setup (Fast, no heavy imports yet) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# --- Flask App Initialization (FAST) ---
app = Flask(__name__)

# --- Rate Limiting Configuration (Simple in-memory) ---
# For production, use Redis-backed Flask-Limiter
class SimpleRateLimiter:
    """Simple in-memory rate limiter for development."""
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self, key, max_requests=10, window_seconds=60):
        """Check if request is allowed under rate limit."""
        with self.lock:
            now = time.time()
            # Clean old requests outside window
            self.requests[key] = [req_time for req_time in self.requests[key] 
                                  if now - req_time < window_seconds]
            
            # Check if under limit
            if len(self.requests[key]) >= max_requests:
                return False
            
            # Add current request
            self.requests[key].append(now)
            return True
    
    def get_retry_after(self, key, window_seconds=60):
        """Get seconds until rate limit resets."""
        with self.lock:
            if not self.requests[key]:
                return 0
            oldest = min(self.requests[key])
            return max(0, int(window_seconds - (time.time() - oldest)))

rate_limiter = SimpleRateLimiter()

# --- Prediction Cache Configuration ---
import hashlib
from collections import OrderedDict

class PredictionCache:
    """Simple LRU cache for prediction results."""
    def __init__(self, max_size=100):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.lock = Lock()
    
    def get_cache_key(self, email_text):
        """Generate MD5 hash of email text for cache key."""
        return hashlib.md5(email_text.encode('utf-8')).hexdigest()
    
    def get(self, email_text):
        """Get cached prediction if exists."""
        with self.lock:
            key = self.get_cache_key(email_text)
            if key in self.cache:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
            return None
    
    def set(self, email_text, result):
        """Store prediction result in cache."""
        with self.lock:
            key = self.get_cache_key(email_text)
            
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)  # Remove oldest (FIFO)
            
            self.cache[key] = {
                'result': result,
                'timestamp': time.time()
            }
    
    def clear(self):
        """Clear all cache."""
        with self.lock:
            self.cache.clear()
    
    def size(self):
        """Get current cache size."""
        with self.lock:
            return len(self.cache)

prediction_cache = PredictionCache(max_size=100)


# --- Timeout Exception and Helper ---
class TimeoutException(Exception):
    """Custom exception for timeout."""
    pass


def run_with_timeout(func, args=(), kwargs=None, timeout_seconds=10):
    """
    Execute a function with a timeout using threading.
    
    Args:
        func: Function to execute
        args: Tuple of positional arguments
        kwargs: Dict of keyword arguments
        timeout_seconds: Maximum time to wait in seconds
        
    Returns:
        Result of the function if completed within timeout
        
    Raises:
        TimeoutException: If function takes longer than timeout_seconds
    """
    if kwargs is None:
        kwargs = {}
    
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
    
    thread = Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)
    
    if thread.is_alive():
        # Thread is still running - timeout occurred
        logger.warning(f"Function {func.__name__} timed out after {timeout_seconds} seconds")
        raise TimeoutException(f"Operation timed out after {timeout_seconds} seconds")
    
    if exception[0]:
        raise exception[0]
    
    return result[0]


# --- Security Headers Configuration ---
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Enable XSS protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Force HTTPS (only in production)
    # Uncomment for production with HTTPS:
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy (basic)
    # Allow inline styles and scripts for now (due to template structure)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# --- Global variables for lazy-loaded models ---
models_loaded = False
models_lock = Lock()
loaded_keras_model = None
numeric_preprocessor = None
embedding_model = None
EXPECTED_NUMERIC_COLS = None
EMBEDDING_DIM = 0
model_load_error_str = None

def load_models():
    """Lazy load all ML models on first prediction request."""
    global models_loaded, loaded_keras_model, numeric_preprocessor, embedding_model
    global EXPECTED_NUMERIC_COLS, EMBEDDING_DIM, model_load_error_str
    
    with models_lock:
        if models_loaded:
            return True
            
        logger.info("==> LAZY LOADING MODELS (first request)...")
        
        try:
            # Now import heavy libraries
            import sys
            import json
            import numpy as np
            import pandas as pd
            import joblib
            from scipy.sparse import issparse
            
            # TensorFlow setup
            os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
            os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
            import tensorflow as tf
            tf.get_logger().setLevel('ERROR')
            from tensorflow.keras.models import load_model as load_keras_model
            
            # Sentence transformers
            from sentence_transformers import SentenceTransformer
            
            # NLTK setup
            import nltk
            nltk_data_env = os.environ.get('NLTK_DATA', '/opt/render/nltk_data')
            if os.path.exists(nltk_data_env):
                nltk.data.path.insert(0, nltk_data_env)
            
            # Paths to model files
            MODELS_DIR = os.path.join(APP_ROOT, "saved_data", "models")
            NUMERIC_PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "numeric_preprocessor.pkl")
            NUMERIC_COLS_INFO_PATH = os.path.join(MODELS_DIR, "numeric_cols_info.json")
            EMBEDDING_MODEL_INFO_PATH = os.path.join(MODELS_DIR, "embedding_model_info.json")
            KERAS_MODEL_PATH = os.path.join(MODELS_DIR, "HybridNN.keras")
            
            # Load numeric preprocessor
            logger.info(f"Loading numeric preprocessor from {NUMERIC_PREPROCESSOR_PATH}")
            numeric_preprocessor = joblib.load(NUMERIC_PREPROCESSOR_PATH)
            
            # Load numeric columns info
            logger.info(f"Loading numeric columns info from {NUMERIC_COLS_INFO_PATH}")
            with open(NUMERIC_COLS_INFO_PATH, 'r') as f:
                numeric_info = json.load(f)
                EXPECTED_NUMERIC_COLS = numeric_info['numeric_columns']
            
            # Load embedding model info
            logger.info(f"Loading embedding model info from {EMBEDDING_MODEL_INFO_PATH}")
            with open(EMBEDDING_MODEL_INFO_PATH, 'r') as f:
                embedding_info = json.load(f)
                EMBEDDING_MODEL_NAME = embedding_info['model_name']
                EMBEDDING_DIM = embedding_info['embedding_dimension']
            
            # Load sentence transformer
            logger.info(f"Loading sentence transformer model '{EMBEDDING_MODEL_NAME}'...")
            embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
            
            # Load Keras model
            logger.info(f"Loading Keras model from {KERAS_MODEL_PATH}")
            loaded_keras_model = load_keras_model(KERAS_MODEL_PATH)
            
            models_loaded = True
            logger.info("==> ALL MODELS LOADED SUCCESSFULLY!")
            return True
            
        except FileNotFoundError as e:
            # Specific error for missing model files
            model_load_error_str = "Model files not found. Please ensure models are properly installed."
            logger.error(f"Model files missing: {e}", exc_info=True)
            return False
        except ImportError as e:
            # Specific error for missing dependencies
            model_load_error_str = "Required libraries not installed. Please check dependencies."
            logger.error(f"Import error during model loading: {e}", exc_info=True)
            return False
        except Exception as e:
            # Generic error - don't expose technical details to user
            model_load_error_str = "Failed to load models. Please contact support."
            # Log full error details for debugging
            logger.error(f"Unexpected error loading models: {type(e).__name__}: {str(e)}", exc_info=True)
            return False


@app.route('/')
def home():
    """Renders the main input page."""
    return render_template('index.html', model_error=model_load_error_str)


@app.route('/health')
def health():
    """Health check endpoint - returns immediately without loading models."""
    return {'status': 'healthy', 'models_loaded': models_loaded}, 200


@app.route('/predict', methods=['POST'])
def predict():
    """Handles the prediction request - loads models on first call."""
    
    # RATE LIMITING: Check if request is allowed
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip, max_requests=10, window_seconds=60):
        retry_after = rate_limiter.get_retry_after(client_ip, window_seconds=60)
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return render_template('index.html',
                               prediction_text=f'Rate limit exceeded. Please try again in {retry_after} seconds.',
                               email_text='',
                               model_error=None), 429
    
    # Lazy load models on first prediction
    if not models_loaded:
        logger.info("First prediction request - loading models...")
        if not load_models():
            return render_template('index.html',
                                   prediction_text='Error: Models failed to load. Check server logs.',
                                   email_text=request.form.get('email_text', ''),
                                   model_error=model_load_error_str)
    
    try:
        # Import preprocessing functions (lightweight)
        from app import clean_email_input, extract_features_input, compute_embeddings
        import numpy as np
        import pandas as pd
        from scipy.sparse import issparse
        import html
        
        # SECURITY: Get and validate email_text
        email_text = request.form.get('email_text', '')
        
        # Validate type
        if not isinstance(email_text, str):
            logger.warning("Invalid input type received")
            return render_template('index.html',
                                   prediction_text='Invalid input format.',
                                   email_text='',
                                   model_error=model_load_error_str), 400
        
        # Validate length (maximum 50KB = 50,000 characters)
        MAX_INPUT_LENGTH = 50000
        if len(email_text) > MAX_INPUT_LENGTH:
            logger.warning(f"Input too long: {len(email_text)} characters")
            return render_template('index.html',
                                   prediction_text=f'Input too long. Maximum {MAX_INPUT_LENGTH} characters allowed.',
                                   email_text='',
                                   model_error=model_load_error_str), 400
        
        # Sanitize for logging (prevent log injection)
        safe_preview = html.escape(email_text[:100].replace('\n', ' ').replace('\r', ''))
        
        # Check if empty after stripping
        if not email_text or not email_text.strip():
            return render_template('index.html',
                                   prediction_text='Please provide email content to analyze.',
                                   email_text='',
                                   model_error=model_load_error_str)
        
        # CACHE: Check if we have cached result for this email
        cached_result = prediction_cache.get(email_text)
        if cached_result:
            cache_age = int(time.time() - cached_result['timestamp'])
            logger.info(f"Returning cached prediction (age: {cache_age}s)")
            return render_template('index.html',
                                   prediction_text=cached_result['result'],
                                   email_text=email_text,
                                   model_error=model_load_error_str)
        
        logger.info(f"Processing new prediction ({len(email_text)} chars): '{safe_preview}...'")
        
        # Preprocess
        cleaned_text = clean_email_input(email_text)
        if not cleaned_text:
            return render_template('index.html',
                                   prediction_text='Input email is empty after cleaning.',
                                   email_text=email_text,
                                   model_error=model_load_error_str)
        
        # Extract features
        raw_numeric_features_dict = extract_features_input(email_text, cleaned_text)
        raw_numeric_df = pd.DataFrame([raw_numeric_features_dict], columns=EXPECTED_NUMERIC_COLS)
        
        # Compute embeddings
        embedding_features = compute_embeddings([cleaned_text], embedding_model)
        
        # Scale numeric features
        scaled_numeric_features = numeric_preprocessor.transform(raw_numeric_df)
        if issparse(scaled_numeric_features):
            scaled_numeric_features = scaled_numeric_features.toarray()
        
        # Prepare inputs for Keras
        embedding_features = embedding_features.astype(np.float32)
        scaled_numeric_features = scaled_numeric_features.astype(np.float32)
        
        if embedding_features.shape[0] != 1:
            embedding_features = np.expand_dims(embedding_features, axis=0)
        if scaled_numeric_features.shape[0] != 1:
            scaled_numeric_features = np.expand_dims(scaled_numeric_features, axis=0)
        
        keras_input_list = [embedding_features, scaled_numeric_features]
        
        # Predict with timeout protection
        logger.info("Predicting with Keras model...")
        try:
            # Run prediction with 10-second timeout
            pred_proba_array = run_with_timeout(
                loaded_keras_model.predict,
                args=(keras_input_list,),
                kwargs={'verbose': 0},
                timeout_seconds=10
            )
        except TimeoutException as te:
            logger.error(f"Prediction timeout: {te}")
            return render_template('index.html',
                                   prediction_text='Prediction took too long. Please try with a shorter email or try again later.',
                                   email_text=email_text,
                                   model_error=model_load_error_str), 408
        
        proba_phishing = pred_proba_array[0][0]
        
        final_prediction = 1 if proba_phishing >= 0.5 else 0
        result_text = "Phishing" if final_prediction == 1 else "Legitimate"
        confidence = proba_phishing if final_prediction == 1 else (1 - proba_phishing)
        
        result_message = f'Result: {result_text} (Confidence: {confidence:.2%})'
        
        # CACHE: Store result for future requests
        prediction_cache.set(email_text, result_message)
        logger.info(f"Cached prediction. Cache size: {prediction_cache.size()}/{prediction_cache.max_size}")
        
        return render_template('index.html',
                               prediction_text=result_message,
                               email_text=email_text,
                               model_error=model_load_error_str)
    
    except ValueError as e:
        # Specific error for invalid data format
        logger.error(f"Value error during prediction: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text='Invalid input format. Please check your email text.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str), 400
    except MemoryError as e:
        # Specific error for memory issues
        logger.error(f"Memory error during prediction: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text='Input too large to process. Please try with shorter text.',
                               email_text='',
                               model_error=model_load_error_str), 413
    except Exception as e:
        # Generic error - don't expose technical details
        logger.error(f"Unexpected error during prediction: {type(e).__name__}: {str(e)}", exc_info=True)
        return render_template('index.html',
                               prediction_text='An error occurred during analysis. Please try again or contact support.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
