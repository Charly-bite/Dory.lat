"""
Optimized Flask app for Render with LAZY MODEL LOADING.
Models are loaded on first prediction request, not during import.
This allows Gunicorn to start and bind to port immediately.
"""
import os
import logging
from flask import Flask, request, render_template
from threading import Lock

# --- Basic Setup (Fast, no heavy imports yet) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# --- Flask App Initialization (FAST) ---
app = Flask(__name__)

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
            
        except Exception as e:
            model_load_error_str = f"Failed to load models: {str(e)}"
            logger.error(model_load_error_str, exc_info=True)
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
        
        email_text = request.form.get('email_text', '')
        logger.info(f"Received prediction request (first 100 chars): '{email_text[:100]}...'")
        
        if not email_text or not email_text.strip():
            return render_template('index.html',
                                   prediction_text='Please provide email content to analyze.',
                                   email_text='',
                                   model_error=model_load_error_str)
        
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
        
        # Predict
        logger.info("Predicting with Keras model...")
        pred_proba_array = loaded_keras_model.predict(keras_input_list, verbose=0)
        proba_phishing = pred_proba_array[0][0]
        
        final_prediction = 1 if proba_phishing >= 0.5 else 0
        result_text = "Phishing" if final_prediction == 1 else "Legitimate"
        confidence = proba_phishing if final_prediction == 1 else (1 - proba_phishing)
        
        return render_template('index.html',
                               prediction_text=f'Result: {result_text} (Confidence: {confidence:.2%})',
                               email_text=email_text,
                               model_error=model_load_error_str)
    
    except Exception as e:
        logger.error(f"Error during prediction: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text=f'Error during prediction. Check server logs.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
