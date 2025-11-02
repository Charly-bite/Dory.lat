# --- Ensemble app.py for Render Deployment ---

import os
import re
import sys # For exit on critical error
import numpy as np
import pandas as pd
import joblib # For loading sklearn models/preprocessor
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings # Make sure this is imported correctly (it is)
import textstat # For readability
import json # Needed to load numeric_cols_info and embedding_model_info
from scipy.sparse import issparse # Might be needed if preprocessor outputs sparse data (less likely with StandardScaler)

# --- NLTK Imports and Setup (Copied/Adapted from main_script.py) ---
try:
    import nltk
    # Add multiple possible NLTK data paths for Render
    possible_paths = [
        '/opt/render/nltk_data',
        '/opt/render/project/nltk_data',
        os.path.expanduser('~/nltk_data'),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            nltk.data.path.insert(0, path)
            print(f"--- Added NLTK path: {path} ---", file=sys.stderr)
    
    print(f"--- NLTK search paths: {nltk.data.path[:3]} ---", file=sys.stderr)
    
    # Check for resources, attempt download if missing
    try:
        nltk.data.find('corpora/stopwords')
        nltk.data.find('tokenizers/punkt')
        print("--- NLTK data found. OK. ---")
        
        # Load stopwords immediately after finding them
        stop_words_en = set(nltk.corpus.stopwords.words('english'))
        print("--- NLTK stopwords loaded. ---")
        
    except LookupError as e:
        print(f"--- NLTK resource missing: {e}. Attempting programmatic download... ---", file=sys.stderr)
        # It's better to handle NLTK download in the build phase in Render settings
        # but we keep the attempt here as a fallback.
        try: 
            nltk.download('stopwords', quiet=True)
            nltk.download('punkt', quiet=True)
            stop_words_en = set(nltk.corpus.stopwords.words('english'))
            print("--- NLTK data downloaded and loaded. ---")
        except Exception as download_e: 
            print(f"--- WARNING: Failed to download NLTK data: {download_e} ---", file=sys.stderr)
            stop_words_en = set() # Use empty set if download fails
    except Exception as e:
         print(f"--- WARNING: Error loading NLTK stopwords: {e} ---", file=sys.stderr)
         stop_words_en = set()

except ImportError:
    nltk = None
    print("--- WARNING: NLTK not found. Readability score might be less accurate. ---", file=sys.stderr)
    stop_words_en = set() # Ensure stop_words_en exists even if nltk fails


# --- TensorFlow / Keras Configuration and Import ---
try:
    # Set TF environment variables BEFORE importing TensorFlow
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' # Suppress INFO and WARNING logs from TF
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR') # Suppress errors from TF logger specifically
    from tensorflow.keras.models import load_model as load_keras_model # Import Keras load function
    # from tensorflow.keras.layers import Input # Only needed if redefining the model architecture, not for loading
    # from tensorflow.keras.models import Model as KerasModel # Only needed for isinstance checks if desired
    TF_AVAILABLE = True
    print(f"--- TensorFlow Loaded for App (Version: {tf.__version__}) ---")
except ImportError:
    TF_AVAILABLE = False
    load_keras_model = None
    # Define dummy KerasModel class for type checking if TF is not available
    class KerasModel: pass
    print("--- WARNING: TensorFlow not found. Keras model cannot be loaded or used. ---", file=sys.stderr)


# --- Sentence Transformer Configuration and Import ---
try:
    from sentence_transformers import SentenceTransformer # Import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
    print("--- Sentence Transformers Loaded for App ---")
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    SentenceTransformer = None # Define dummy class/value
    print("--- WARNING: Sentence Transformers not found. Embedding model cannot be loaded or used. ---", file=sys.stderr)


import logging
from flask import Flask, request, render_template
from scipy.sparse import issparse


# --- Global Configuration & Setup ---
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=FutureWarning) # Corrected typo here already
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Basic Logging Setup ---
# Use basicConfig only if handlers are not already configured (e.g., by Render)
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Set logging level to DEBUG temporarily for troubleshooting Keras load ---
# Remove or change this back to logging.INFO once the issue is resolved
# logger.setLevel(logging.DEBUG) # Uncomment this line to see the DEBUG logs


# --- Constants ---
# Get the absolute path of the directory where this script is located
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(APP_ROOT, "saved_data") # Directory where artifacts were saved by main_script.py
MODELS_DIR = os.path.join(OUTPUT_DIR, "models")

# --- ARTIFACT FILENAMES (MUST match main_script.py saving) ---
NUMERIC_PREPROCESSOR_FILENAME = "numeric_preprocessor.pkl" # Corrected filename
NUMERIC_COLS_INFO_FILENAME = "numeric_cols_info.json"
EMBEDDING_MODEL_INFO_FILENAME = "embedding_model_info.json"
KERAS_MODEL_FILENAME = "HybridNN.keras" # Filename of the saved Keras model
# The actual embedding model name is loaded from embedding_model_info.json


# Construct full paths
NUMERIC_PREPROCESSOR_PATH = os.path.join(MODELS_DIR, NUMERIC_PREPROCESSOR_FILENAME)
NUMERIC_COLS_INFO_PATH = os.path.join(MODELS_DIR, NUMERIC_COLS_INFO_FILENAME)
EMBEDDING_MODEL_INFO_PATH = os.path.join(MODELS_DIR, EMBEDDING_MODEL_INFO_FILENAME)
KERAS_MODEL_PATH = os.path.join(MODELS_DIR, KERAS_MODEL_FILENAME)

# --- Global Variables for Loaded Artifacts ---
# We will load the specific components, not necessarily pipelines
loaded_keras_model = None
numeric_preprocessor = None # This will hold the fitted numeric preprocessor
embedding_model = None # This will hold the loaded Sentence Transformer model
EXPECTED_NUMERIC_COLS = None # Loaded from json
EMBEDDING_DIM = 0 # Loaded from json
EMBEDDING_MODEL_NAME = None # Loaded from json

model_load_errors = [] # List to store loading errors

logger.info("--- Loading Models and Preprocessor for App ---")
logger.info(f"App directory (Current Working Directory): {os.getcwd()}")
logger.info(f"Expecting artifacts in: {MODELS_DIR}")


# --- Load Numeric Preprocessor ---
logger.info(f"Attempting to load Numeric Preprocessor from: {NUMERIC_PREPROCESSOR_PATH}")
if os.path.exists(NUMERIC_PREPROCESSOR_PATH):
    try:
        numeric_preprocessor = joblib.load(NUMERIC_PREPROCESSOR_PATH)
        logger.info("Numeric Preprocessor loaded successfully.")
    except Exception as e:
        error_msg = f"Error loading numeric preprocessor from {NUMERIC_PREPROCESSOR_PATH}: {e}"
        logger.error(error_msg, exc_info=True)
        model_load_errors.append(error_msg)
else:
    error_msg = f"Numeric Preprocessor file not found at: {NUMERIC_PREPROCESSOR_PATH}"
    logger.error(error_msg)
    model_load_errors.append(error_msg)


# --- Load Numeric Columns Info ---
logger.info(f"Attempting to load Numeric Columns Info from: {NUMERIC_COLS_INFO_PATH}")
if os.path.exists(NUMERIC_COLS_INFO_PATH):
    try:
        with open(NUMERIC_COLS_INFO_PATH, 'r') as f:
            numeric_info = json.load(f)
            # Check if the expected key exists
            if 'numeric_columns' in numeric_info and isinstance(numeric_info['numeric_columns'], list):
                 EXPECTED_NUMERIC_COLS = numeric_info['numeric_columns']
                 logger.info(f"Expected numeric columns loaded: {EXPECTED_NUMERIC_COLS}")
            else:
                 error_msg = f"Numeric columns key ('numeric_columns') not found or invalid format in {NUMERIC_COLS_INFO_PATH}"
                 logger.error(error_msg)
                 model_load_errors.append(error_msg)
                 EXPECTED_NUMERIC_COLS = [] # Use empty list if info is bad
        if not EXPECTED_NUMERIC_COLS:
             logger.warning("No expected numeric columns found in info file.")
    except Exception as e:
        error_msg = f"Error loading numeric columns info from {NUMERIC_COLS_INFO_PATH}: {e}"
        logger.error(error_msg, exc_info=True)
        model_load_errors.append(error_msg)
        EXPECTED_NUMERIC_COLS = [] # Ensure it's a list even on error
else:
    error_msg = f"Numeric Columns Info file not found at: {NUMERIC_COLS_INFO_PATH}"
    logger.error(error_msg)
    model_load_errors.append(error_msg)
    EXPECTED_NUMERIC_COLS = [] # Ensure it's a list even on error


# --- Load Embedding Model Info and the Embedding Model ---
logger.info(f"Attempting to load Embedding Model Info from: {EMBEDDING_MODEL_INFO_PATH}")
if os.path.exists(EMBEDDING_MODEL_INFO_PATH):
    try:
        with open(EMBEDDING_MODEL_INFO_PATH, 'r') as f:
            embedding_info = json.load(f)
            # Check if keys exist and have correct types
            if 'model_name' in embedding_info and isinstance(embedding_info['model_name'], str):
                 EMBEDDING_MODEL_NAME = embedding_info['model_name']
                 logger.info(f"Embedding model name loaded: {EMBEDDING_MODEL_NAME}")
            else:
                 error_msg = f"Embedding model name key ('model_name') not found or invalid format in {EMBEDDING_MODEL_INFO_PATH}"
                 logger.error(error_msg)
                 model_load_errors.append(error_msg)
            if 'embedding_dimension' in embedding_info and isinstance(embedding_info['embedding_dimension'], int):
                 EMBEDDING_DIM = embedding_info['embedding_dimension']
                 logger.info(f"Embedding dimension loaded: {EMBEDDING_DIM}")
            else:
                 error_msg = f"Embedding dimension key ('embedding_dimension') not found or invalid format in {EMBEDDING_MODEL_INFO_PATH}"
                 logger.error(error_msg)
                 model_load_errors.append(error_msg)
                 EMBEDDING_DIM = 0 # Use 0 if info is bad

        # Now attempt to load the actual embedding model using the name
        if EMBEDDING_MODEL_NAME and SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.info(f"Attempting to load Sentence Transformer model '{EMBEDDING_MODEL_NAME}'...")
            try:
                embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
                # Cross-check loaded dimension if possible
                if hasattr(embedding_model, 'get_sentence_embedding_dimension') and embedding_model.get_sentence_embedding_dimension() != EMBEDDING_DIM:
                     logger.warning(f"Loaded embedding model dimension ({embedding_model.get_sentence_embedding_dimension()}) mismatches info file ({EMBEDDING_DIM}). Using loaded model's dimension.")
                     EMBEDDING_DIM = embedding_model.get_sentence_embedding_dimension() # Trust loaded model's dimension
                logger.info("Sentence Transformer model loaded successfully.")
            except Exception as e:
                error_msg = f"Error loading Sentence Transformer model '{EMBEDDING_MODEL_NAME}': {e}. Ensure internet access or local files."
                logger.error(error_msg, exc_info=True)
                model_load_errors.append(error_msg)
                embedding_model = None # Ensure None on failure
                EMBEDDING_DIM = 0 # Reset dimension if model failed to load
        elif EMBEDDING_MODEL_NAME and not SENTENCE_TRANSFORMERS_AVAILABLE:
            error_msg = f"Sentence Transformers library not available. Cannot load embedding model '{EMBEDDING_MODEL_NAME}'."
            logger.error(error_msg)
            model_load_errors.append(error_msg)
            embedding_model = None
            EMBEDDING_DIM = 0
        else: # EMBEDDING_MODEL_NAME was not loaded from json
             logger.warning("Embedding model name not available from info file. Skipping embedding model load.")
             embedding_model = None
             EMBEDDING_DIM = 0


    except Exception as e:
        error_msg = f"Error loading embedding model info from {EMBEDDING_MODEL_INFO_PATH}: {e}"
        logger.error(error_msg, exc_info=True)
        model_load_errors.append(error_msg)
        EMBEDDING_DIM = 0 # Ensure 0 on error
        embedding_model = None # Ensure None on error
        EMBEDDING_MODEL_NAME = None # Ensure None on error

else:
    error_msg = f"Embedding Model Info file not found at: {EMBEDDING_MODEL_INFO_PATH}"
    logger.error(error_msg)
    model_load_errors.append(error_msg)
    EMBEDDING_DIM = 0 # Ensure 0 on error
    embedding_model = None # Ensure None on error
    EMBEDDING_MODEL_NAME = None # Ensure None on error


# --- Load Keras Model ---
logger.info(f"Attempting to load Keras model from: {KERAS_MODEL_PATH}")
logger.debug(f"TF_AVAILABLE: {TF_AVAILABLE}, KERAS_MODEL_PATH exists: {os.path.exists(KERAS_MODEL_PATH)}") # Added Debug Log 1
if TF_AVAILABLE:
    if os.path.exists(KERAS_MODEL_PATH):
        logger.debug(f"KERAS_MODEL_PATH: {KERAS_MODEL_PATH}") # Added Debug Log Path Check
        logger.debug(f"Proceeding to load Keras model using load_keras_model from {tf.keras.models.__name__}") # Added Debug Log 2
        try:
            # Add debugging logs just before the load call
            logger.debug("Calling load_keras_model...")
            loaded_keras_model = load_keras_model(KERAS_MODEL_PATH)
            # Add debugging logs just after the load call
            logger.debug("load_keras_model call finished.")

            logger.info("Keras model loaded successfully.") # Existing log, but should appear now if successful
            logger.debug("Keras model object assigned.") # Added Debug Log 3 (after success)
        except Exception as e:
            error_msg = f"Error loading Keras model from {KERAS_MODEL_PATH}: {e}"
            logger.error(error_msg, exc_info=True)
            model_load_errors.append(error_msg)
            loaded_keras_model = None # Ensure None on failure
            logger.debug("Keras model loading failed, loaded_keras_model set to None.") # Added Debug Log 4 (after failure)
    else:
        error_msg = f"Keras model file not found at: {KERAS_MODEL_PATH}"
        logger.error(error_msg)
        model_load_errors.append(error_msg)
        loaded_keras_model = None # Ensure None if file missing
else:
    error_msg = "TensorFlow not available. Cannot load Keras model."
    logger.error(error_msg)
    model_load_errors.append(error_msg)
    loaded_keras_model = None # Ensure None if TF missing

logger.debug(f"Finished Keras load block. loaded_keras_model is: {loaded_keras_model is not None}") # Added Debug Log 5


# --- Final Loading Checks & Global Status ---
# The app can only make predictions if the Keras model, numeric preprocessor,
# numeric column names, embedding model, and embedding dimension are ALL available.
# If any is missing, it's a fatal error for prediction.
prediction_ready = (
    loaded_keras_model is not None and
    numeric_preprocessor is not None and
    EXPECTED_NUMERIC_COLS is not None and len(EXPECTED_NUMERIC_COLS) > 0 and # Need > 0 numeric columns defined
    embedding_model is not None and
    EMBEDDING_DIM > 0
)

if not prediction_ready:
    logger.critical("----- FATAL: App cannot make predictions due to missing artifacts/dependencies. -----")
    if numeric_preprocessor is None: logger.critical("  - Numeric Preprocessor missing.")
    if EXPECTED_NUMERIC_COLS is None or len(EXPECTED_NUMERIC_COLS) == 0: logger.critical("  - Expected Numeric Columns info missing or empty.")
    if embedding_model is None: logger.critical("  - Embedding Model missing or failed to load.")
    if EMBEDDING_DIM <= 0: logger.critical("  - Embedding Dimension not loaded correctly (0 or less).")
    if loaded_keras_model is None: logger.critical("  - Keras Model missing.")
    # Combine all errors for the template
    model_load_error_str = "Prediction not possible. Missing required models/data. Check logs. " + "; ".join(model_load_errors)
else:
    logger.info("--- All required models and data loaded successfully. App is ready for predictions. ---")
    model_load_error_str = "; ".join(model_load_errors) if model_load_errors else None # Use None if no errors, but keep warnings


# --- Preprocessing Helper Functions (Copied/Adapted from main_script.py) ---

# Keep as is from original app.py, assuming it calls the helpers below
def clean_email_input(text):
    # Calls the internal helper
    return _clean_text(text)

# Keep as is from original app.py, assuming it calls the helpers below
def extract_features_input(original_text, cleaned_text):
    # Calls the internal helpers for numeric features
    features = {}
    features['num_links'], features['has_suspicious_url'] = _extract_url_features(original_text)
    features['urgency_count'] = _extract_urgency(cleaned_text)
    features['readability_score'] = _calculate_readability(cleaned_text)
    # Ensure all expected columns are present in the output dictionary (using loaded EXPECTED_NUMERIC_COLS)
    # This ensures consistency even if an extraction function fails partially
    final_features = {col: features.get(col, 0) for col in EXPECTED_NUMERIC_COLS if col in features}
    return final_features

# --- Internal Preprocessing Helpers (Copied from main_script.py) ---
# clean_email: Keep as is (mostly language agnostic)
def _clean_text(text):
    # Use app logger
    current_logger = logging.getLogger(__name__)
    if pd.isna(text) or not isinstance(text, str) or text.strip() == "": return ""
    try:
        try: soup = BeautifulSoup(text, 'lxml')
        except: soup = BeautifulSoup(text, 'html.parser')
        cleaned = soup.get_text(separator=' ')
        # Keep URLs identifiable
        cleaned = re.sub(r'https?://\S+|www\.\S+', ' URL ', cleaned)
        # Allow broader range of characters including common accented letters
        cleaned = re.sub(r'[^a-zA-Z0-9\s.,!?\'`áéíóúÁÉÍÓÚñÑüÜ]', ' ', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned
    except Exception as e: current_logger.error(f"Error cleaning text: '{str(text)[:50]}...': {e}",exc_info=False); return ""

# extract_url_features: Keep patterns language-independent, update keywords
def _extract_url_features(text):
    current_logger = logging.getLogger(__name__)
    num_links, has_suspicious_url = 0, 0
    if pd.isna(text) or not isinstance(text, str): return 0, 0
    try:
        url_pattern = r'(https?://\S+|www\.\S+)'
        text_snippet_for_findall = text[:50000] # Limit search length
        urls = re.findall(url_pattern, text_snippet_for_findall)
        try: num_links = len(re.findall(url_pattern, text)) # Try full text first
        except Exception as count_e: current_logger.warning(f"URL count error: {count_e}. Using snippet count."); num_links = len(urls)

        if not urls: return num_links, has_suspicious_url

        # Combine English and Spanish keywords (can be expanded) - MUST match main_script.py
        suspicious_keywords_en = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin', 'support', 'password', 'banking', 'activity', 'credential']
        suspicious_keywords_es = ['iniciar sesion', 'verificar', 'cuenta', 'actualizar', 'confirmar', 'contraseña', 'banco', 'actividad', 'credenciales']
        suspicious_keywords = suspicious_keywords_en + suspicious_keywords_es # Use both

        shortened_domains_pattern = r'(bit\.ly/|goo\.gl/|tinyurl\.com/|t\.co/|ow\.ly/|is\.gd/|buff\.ly/|adf\.ly/|bit\.do/|soo\.gd/)'

        has_http, has_shortener, has_keywords = 0, 0, 0
        for url in urls[:100]: # Limit checks
            try:
                url_lower = url.lower()
                if url_lower.startswith('http://'): has_http = 1
                if re.search(shortened_domains_pattern, url_lower): has_shortener = 1

                # Extract path/query for keyword checking
                proto_end = url_lower.find('//')
                path_query = ''
                if proto_end > 0:
                    domain_part_end = url_lower.find('/', proto_end + 2)
                    path_query = url_lower[domain_part_end:] if domain_part_end > 0 else ''
                else: # Handle URLs without explicit protocol like www.example.com/path
                    domain_part_end = url_lower.find('/')
                    path_query = url_lower[domain_part_end:] if domain_part_end > 0 else ''

                check_string = path_query + url_lower
                # Check for *any* of the combined keywords
                if any(keyword in check_string for keyword in suspicious_keywords): has_keywords = 1

                if has_http or has_shortener or has_keywords:
                    has_suspicious_url = 1
                    break # Found a suspicious URL, no need to check others
            except Exception as url_parse_e: current_logger.debug(f"URL parse error '{url[:50]}...': {url_parse_e}"); continue
        return num_links, has_suspicious_url
    except Exception as e: current_logger.error(f"URL feature extraction failed: '{str(text)[:50]}...': {e}",exc_info=False); return 0, 0

# extract_urgency: Update keywords for Spanish
def _extract_urgency(cleaned_text):
    current_logger = logging.getLogger(__name__);
    if not cleaned_text: return 0
    try:
        # Combine English and Spanish urgency keywords (can be expanded) - MUST match main_script.py
        urgency_words_en = ['urgent', 'immediately', 'action required', 'verify', 'password', 'alert', 'warning', 'limited time', 'expire', 'suspended', 'locked', 'important', 'final notice', 'response required', 'security update', 'confirm account', 'validate', 'due date', 'restricted', 'compromised', 'unauthorized']
        urgency_words_es = ['urgente', 'inmediatamente', 'acción requerida', 'verifique', 'contraseña', 'alerta', 'advertencia', 'tiempo limitado', 'expira', 'suspendida', 'bloqueada', 'importante', 'último aviso', 'requiere respuesta', 'actualización de seguridad', 'confirmar cuenta', 'validar', 'fecha límite', 'restringido', 'comprometida', 'no autorizado']
        urgency_words = urgency_words_en + urgency_words_es # Use both

        text_lower = cleaned_text.lower();
        # Use word boundaries \b
        count = sum(len(re.findall(r'\b' + re.escape(word) + r'\b', text_lower)) for word in urgency_words)
        return count
    except Exception as e: current_logger.error(f"Urgency calculation failed: {e}", exc_info=False); return 0

# calculate_readability: Acknowledge limitation or remove. Keep for now.
# The Flesch score is less reliable for Spanish. We keep it, but its importance might decrease.
def _calculate_readability(cleaned_text):
    current_logger = logging.getLogger(__name__);
    # Check if NLTK was imported successfully and stopwords are available (needed by textstat)
    if nltk is None or not stop_words_en:
        current_logger.warning("NLTK or stopwords not available. Cannot calculate readability. Returning default.")
        return 50.0 # Return neutral default if dependencies missing

    word_count = len(cleaned_text.split())
    if not cleaned_text or word_count < 10: return 100.0 # Simple rule for very short texts
    # Avoid very long texts that might cause performance issues in textstat
    if word_count > 5000: return 0.0

    try:
        # Flesch Reading Ease is language-tuned (primarily English). Less reliable for Spanish.
        # We keep it for consistency with main_script.py
        score = textstat.flesch_reading_ease(cleaned_text);
        return max(-200, min(120, score)) if not np.isnan(score) else 50.0 # Clamp and handle NaN
    except Exception as e:
        if word_count > 5: current_logger.debug(f"Readability failed: '{cleaned_text[:50]}...': {e}", exc_info=False)
        return 50.0

# New function to compute embeddings (Copied from main_script.py)
def compute_embeddings(texts, model):
    current_logger = logging.getLogger(__name__)
    if not texts or len(texts) == 0:
        current_logger.warning("No texts provided for embedding computation.")
        # Return an array with 0 samples but correct dimension if model is loaded
        embedding_dim = model.get_sentence_embedding_dimension() if model and hasattr(model, 'get_sentence_embedding_dimension') else (EMBEDDING_DIM if EMBEDDING_DIM > 0 else 384) # Use loaded DIM or fallback
        return np.empty((0, embedding_dim), dtype=np.float32)

    current_logger.debug(f"Computing embeddings using loaded model for {len(texts)} texts...")
    # Ensure inputs are strings and handle potential NaNs
    texts = [str(t) if pd.notna(t) else "" for t in texts]
    try:
        # SentenceTransformer handles batching internally, show_progress_bar is False for app
        embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
        current_logger.debug(f"Embedding computation complete. Shape: {embeddings.shape}")
        # Ensure correct dtype for Keras
        return embeddings.astype(np.float32)
    except Exception as e:
        current_logger.error(f"Failed to compute embeddings: {e}", exc_info=False)
        # Return zeros on failure, ensuring correct dimension based on loaded info
        embedding_dim = model.get_sentence_embedding_dimension() if model and hasattr(model, 'get_sentence_embedding_dimension') else (EMBEDDING_DIM if EMBEDDING_DIM > 0 else 384)
        current_logger.warning(f"Returning array of zeros with shape ({len(texts)}, {embedding_dim}) due to embedding failure.")
        return np.zeros((len(texts), embedding_dim), dtype=np.float32)


# --- Flask App Initialization ---
app = Flask(__name__)

# --- Flask Routes ---

@app.route('/')
def home():
    """Renders the main input page."""
    # Pass the combined model_load_error string to the template
    return render_template('index.html', model_error=model_load_error_str)


@app.route('/health')
def health():
    """Health check endpoint for Render to detect the service is running."""
    return {'status': 'healthy', 'models_loaded': prediction_ready}, 200


@app.route('/predict', methods=['POST'])
def predict():
    """Handles the prediction request using the loaded Keras model."""
    # Use the global loaded artifacts
    global loaded_keras_model, numeric_preprocessor, embedding_model, EXPECTED_NUMERIC_COLS, EMBEDDING_DIM, model_load_error_str

    # 0. Check if prediction is possible based on loaded artifacts
    if not (loaded_keras_model is not None and numeric_preprocessor is not None and EXPECTED_NUMERIC_COLS is not None and len(EXPECTED_NUMERIC_COLS) > 0 and embedding_model is not None and EMBEDDING_DIM > 0):
        logger.error("App is not ready for predictions due to missing artifacts.")
        return render_template('index.html',
                               prediction_text='Error: App not fully initialized. Missing models or data. Check server logs.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str)

    try:
        email_text = request.form.get('email_text', '') # Use .get for safety
        logger.info(f"Received prediction request for email (first 100 chars): '{email_text[:100]}...'")

        # Handle empty input gracefully
        if not email_text or not email_text.strip():
             logger.warning("Received empty input text.")
             return render_template('index.html',
                                    prediction_text='Please provide email content to analyze.',
                                    email_text='',
                                    model_error=model_load_error_str)


        # 1. Preprocess input text
        cleaned_text = clean_email_input(email_text)
        if not cleaned_text or not cleaned_text.strip():
             logger.warning("Input email resulted in empty cleaned text.")
             return render_template('index.html',
                                    prediction_text='Input email content is empty or invalid after cleaning.',
                                    email_text=email_text,
                                    model_error=model_load_error_str)

        # 2. Extract raw numeric features
        raw_numeric_features_dict = extract_features_input(email_text, cleaned_text)
        # Create DataFrame with raw numeric features, ensure correct columns and order
        # Need a DataFrame primarily for the preprocessor, even if it's just one row
        raw_numeric_df = pd.DataFrame([raw_numeric_features_dict], columns=EXPECTED_NUMERIC_COLS)


        # 3. Compute Embedding features
        embedding_features = compute_embeddings([cleaned_text], embedding_model) # Compute for a list containing the single cleaned text
        if embedding_features is None or embedding_features.shape[0] == 0 or embedding_features.shape[1] != EMBEDDING_DIM:
             logger.error(f"Embedding computation failed or returned unexpected shape {embedding_features.shape}. Expected (1, {EMBEDDING_DIM}).")
             return render_template('index.html', prediction_text='Error: Failed to compute text embeddings.', email_text=email_text, model_error=model_load_error_str)


        # 4. Scale Raw Numeric features using the loaded preprocessor
        scaled_numeric_features = None
        if numeric_preprocessor is not None and not raw_numeric_df.empty and len(EXPECTED_NUMERIC_COLS) > 0:
            try:
                 scaled_numeric_features = numeric_preprocessor.transform(raw_numeric_df) # Transform the DataFrame
                 # Ensure it's a numpy array and handle sparse if needed (StandardScaler is dense)
                 if issparse(scaled_numeric_features): scaled_numeric_features = scaled_numeric_features.toarray()
                 # Ensure correct shape (1, n_numeric_features)
                 if scaled_numeric_features.shape[0] != 1 or scaled_numeric_features.shape[1] != len(EXPECTED_NUMERIC_COLS):
                      logger.error(f"Numeric scaling returned unexpected shape {scaled_numeric_features.shape}. Expected (1, {len(EXPECTED_NUMERIC_COLS)}).")
                      scaled_numeric_features = None # Treat as failure
                 else:
                      logger.debug(f"Numeric features scaled. Shape: {scaled_numeric_features.shape}")
            except Exception as e:
                 logger.error(f"Error scaling numeric features: {e}", exc_info=True)
                 scaled_numeric_features = None # Ensure None on failure

        # If numeric scaling failed or no numeric columns were expected
        if scaled_numeric_features is None:
             scaled_numeric_features = np.empty((1, 0), dtype=np.float32) # Create empty array with 1 row, 0 cols
             if len(EXPECTED_NUMERIC_COLS) > 0: # Only log warning if columns were expected but scaling failed
                  logger.warning("Numeric features could not be scaled or were not present/expected. Using empty numeric features.")


        # 5. Prepare Input for Keras Model
        # The HybridNN expects a list of inputs: [embeddings, scaled_numeric_features]
        # Ensure both arrays have shape (1, N)
        if embedding_features.shape[0] != 1: embedding_features = np.expand_dims(embedding_features, axis=0) # Ensure (1, EMBEDDING_DIM)
        if scaled_numeric_features.shape[0] != 1: scaled_numeric_features = np.expand_dims(scaled_numeric_features, axis=0) # Ensure (1, N_NUMERIC)

        # Ensure dtypes are float32 for Keras
        embedding_features = embedding_features.astype(np.float32)
        scaled_numeric_features = scaled_numeric_features.astype(np.float32)


        # Check if the Keras model expects inputs matching what we prepared
        # The model's input layer shapes are accessible. This check adds robustness.
        try:
            model_inputs = loaded_keras_model.inputs
            if len(model_inputs) != 2:
                 logger.error(f"Loaded Keras model expects {len(model_inputs)} inputs, but 2 (embeddings, numeric) are prepared.")
                 raise ValueError("Keras model input mismatch.")

            # Check shapes match (excluding batch size None)
            expected_embed_shape = model_inputs[0].shape[1:] # Should be (EMBEDDING_DIM,)
            expected_struct_shape = model_inputs[1].shape[1:] # Should be (len(EXPECTED_NUMERIC_COLS),)

            if embedding_features.shape[1:] != expected_embed_shape or scaled_numeric_features.shape[1:] != expected_struct_shape:
                 logger.error(f"Prepared Keras input shapes mismatch model expected shapes.")
                 logger.error(f"  Embeddings: Prepared {embedding_features.shape[1:]}, Model expects {expected_embed_shape}")
                 logger.error(f"  Numeric: Prepared {scaled_numeric_features.shape[1:]}, Model expects {expected_struct_shape}")
                 raise ValueError("Keras model input shape mismatch.")

        except Exception as input_check_e:
            logger.error(f"Failed Keras input check: {input_check_e}")
            # Proceeding might lead to Keras error, better to return error
            return render_template('index.html', prediction_text=f'Error: Keras input setup failed. Check logs.', email_text=email_text, model_error=model_load_error_str)


        # Prepare the final list of inputs for the Keras predict method
        keras_input_list = [embedding_features, scaled_numeric_features]


        # 6. Get Prediction from Keras Model
        logger.info("Predicting with Keras model...")
        # Keras predict on a sigmoid output returns probabilities (shape [1, 1])
        pred_proba_array = loaded_keras_model.predict(keras_input_list, verbose=0)

        # Extract the probability of the positive class (phishing), which is the single output value
        proba_phishing = pred_proba_array[0][0]
        logger.info(f"Keras model prediction proba: {proba_phishing:.4f}")

        # 7. Determine final prediction based on threshold (0.5)
        final_prediction = 1 if proba_phishing >= 0.5 else 0
        logger.info(f"Final prediction (threshold 0.5): {final_prediction}")


        # 8. Format Output
        result_text = "Phishing" if final_prediction == 1 else "Legitimate"
        # Confidence based on the probability of the predicted class
        confidence = proba_phishing if final_prediction == 1 else (1 - proba_phishing)

        return render_template('index.html',
                               prediction_text=f'Result: {result_text} (Confidence: {confidence:.2%})',
                               email_text=email_text,
                               model_error=model_load_error_str)

    except Exception as e:
        logger.error(f"Error during prediction processing: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text=f'Error during prediction processing. Check server logs.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str)


# --- Run Check (Important for Render Startup) ---
# Although Gunicorn runs 'app', Render might still check if the file can be executed.
# This check prevents the app from exiting immediately if run directly for testing.
if __name__ == '__main__':
    # Check if loading succeeded before allowing run
    # We keep the critical log but remove the sys.exit so the app doesn't stop booting
    if not prediction_ready:
         logger.critical("----- FATAL: App is not configured to run due to failed artifact loading. App will start but prediction will fail. -----")
         if model_load_error_str: logger.critical(f"----- Loading Errors: {model_load_error_str} -----")
         # Removed: sys.exit("App initialization failed.") # <--- REMOVED THIS LINE

    logger.warning("----- This script is intended to be run with Gunicorn on Render. -----")
    logger.warning("----- Running directly with 'python app.py' is for local testing ONLY. -----")
    # Start development server if run directly (for local testing)
    # In production (Render with Gunicorn), this block is not executed.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
