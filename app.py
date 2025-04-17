# --- Simplified app.py for Render Deployment with Debugging ---

import os
import re
import numpy as np
import pandas as pd
import joblib # For loading sklearn models/preprocessor
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings
import textstat # For readability
# NLTK might be needed by textstat for sentence tokenization
try:
    import nltk
    # Attempt to ensure punkt tokenizer is available (Render might need this)
    try: nltk.data.find('tokenizers/punkt')
    except: nltk.download('punkt', quiet=True)
except ImportError:
    nltk = None # Indicate NLTK is not available if import fails
    print("--- WARNING: NLTK not found. Readability score might be less accurate. ---")

import logging
from flask import Flask, request, render_template
from scipy.sparse import issparse # Needed for checking data type after transform in some cases


# --- Global Configuration & Setup ---
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
# Assumes 'saved_data' folder is in the same directory as app.py in your repo
OUTPUT_DIR = "saved_data"
MODELS_DIR = os.path.join(OUTPUT_DIR, "models")

# --- MODEL CONFIGURATION (Using Sklearn) ---
MODEL_TYPE = "sklearn"
MODEL_FILENAME = "LogisticRegression_pipeline.pkl" # MAKE SURE this is the correct filename
PREPROCESSOR_FILENAME = "preprocessor.pkl"

# Construct full paths relative to the app.py file
MODEL_PATH = os.path.join(MODELS_DIR, MODEL_FILENAME)
PREPROCESSOR_PATH = os.path.join(MODELS_DIR, PREPROCESSOR_FILENAME)

# --- Load Model and Preprocessor ---
model = None
preprocessor = None
model_load_error = None
EXPECTED_NUMERIC_COLS = None # Initialize

logger.info("--- Loading Model and Preprocessor ---")
logger.info(f"App directory (Current Working Directory): {os.getcwd()}")
logger.info(f"Looking for models directory at: {MODELS_DIR}")
logger.info(f"Looking for preprocessor file at: {PREPROCESSOR_PATH}")
logger.info(f"Looking for model file at: {MODEL_PATH}")

# --- DEBUGGING: Check file system ---
logger.info(f"Checking for existence of base directory: {OUTPUT_DIR}")
if os.path.exists(OUTPUT_DIR):
    logger.info(f"Directory {OUTPUT_DIR} exists. Contents: {os.listdir(OUTPUT_DIR)}")
else:
    logger.error(f"Directory {OUTPUT_DIR} does NOT exist.")

logger.info(f"Checking for existence of models directory: {MODELS_DIR}")
if os.path.exists(MODELS_DIR):
    logger.info(f"Directory {MODELS_DIR} exists. Contents: {os.listdir(MODELS_DIR)}")
else:
    logger.error(f"Directory {MODELS_DIR} does NOT exist.")

logger.info(f"Checking for existence of PREPROCESSOR file: {PREPROCESSOR_PATH}")
if os.path.exists(PREPROCESSOR_PATH):
    logger.info(f"File {PREPROCESSOR_PATH} exists.")
else:
    logger.error(f"File {PREPROCESSOR_PATH} does NOT exist.")

logger.info(f"Checking for existence of MODEL file: {MODEL_PATH}")
if os.path.exists(MODEL_PATH):
    logger.info(f"File {MODEL_PATH} exists.")
else:
    logger.error(f"File {MODEL_PATH} does NOT exist.")
# --- END DEBUGGING ---


try:
    # Load Preprocessor (only if file exists based on debug check)
    if os.path.exists(PREPROCESSOR_PATH):
        preprocessor = joblib.load(PREPROCESSOR_PATH)
        logger.info(f"Preprocessor loaded successfully.")
        # Extract expected numeric columns from the fitted preprocessor
        try:
            numeric_transformer_tuple = next(t for t in preprocessor.transformers_ if t[0] == 'numeric')
            EXPECTED_NUMERIC_COLS = numeric_transformer_tuple[2]
            if not isinstance(EXPECTED_NUMERIC_COLS, list): EXPECTED_NUMERIC_COLS = list(EXPECTED_NUMERIC_COLS) # Ensure list
            logger.info(f"Expected numeric columns from preprocessor: {EXPECTED_NUMERIC_COLS}")
        except Exception as e:
            logger.error(f"Error extracting numeric columns from preprocessor: {e}", exc_info=True)
            EXPECTED_NUMERIC_COLS = None # Ensure reset on error

        # Set fallback if extraction failed
        if EXPECTED_NUMERIC_COLS is None:
             EXPECTED_NUMERIC_COLS = ['num_links', 'has_suspicious_url', 'urgency_count', 'readability_score'] # Fallback
             logger.warning(f"Using fallback numeric columns: {EXPECTED_NUMERIC_COLS}")
             model_load_error = "Could not determine numeric columns from preprocessor; using defaults."

    else:
        # Error already logged by debug check, just set variable
        model_load_error = f"Preprocessor file not found at: {PREPROCESSOR_PATH}"
        preprocessor = None # Ensure it's None

    # Load Model (only if preprocessor loaded successfully AND model file exists)
    if preprocessor and not model_load_error and os.path.exists(MODEL_PATH):
        logger.info(f"Attempting to load Sklearn Model from: {MODEL_PATH}")
        try:
            model = joblib.load(MODEL_PATH)
            logger.info(f"Scikit-learn model loaded successfully.")
        except Exception as sklearn_load_e:
            model_load_error = f"Error loading scikit-learn model: {sklearn_load_e}"
            logger.error(model_load_error, exc_info=True)
            model = None
    elif preprocessor and not model_load_error and not os.path.exists(MODEL_PATH):
        # Error already logged by debug check, just set variable
         model_load_error = f"Model file not found at: {MODEL_PATH}"
         model = None

    # If anything failed, ensure model/preprocessor are None where applicable
    if model_load_error and preprocessor is None:
        model = None
        logger.warning("Setting model/preprocessor to None due to loading errors.")
    elif model_load_error and model is None:
        logger.warning("Model loading failed, preprocessor might still be available but prediction disabled.")


except Exception as e:
    model_load_error = f"An unexpected error occurred during model/preprocessor loading: {e}"
    logger.error(model_load_error, exc_info=True)
    model = None
    preprocessor = None


# --- Preprocessing Functions for New Input ---
# (Keep your clean_email_input and extract_features_input functions here - unchanged)
def clean_email_input(text):
    """Cleans a single raw email string input."""
    logger = logging.getLogger(__name__) # Get logger instance
    if pd.isna(text) or not isinstance(text, str) or text.strip() == "": return ""
    try:
        # Use 'lxml' if available, else fallback
        try: soup = BeautifulSoup(text, 'lxml')
        except: soup = BeautifulSoup(text, 'html.parser')
        cleaned = soup.get_text(separator=' ')
        cleaned = re.sub(r'https?://\S+|www\.\S+', ' URL ', cleaned)
        cleaned = re.sub(r'[^a-zA-Z0-9\s.,!?\'`]', ' ', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned
    except Exception as e: logger.error(f"Cleaning input error: {e}"); return ""

def extract_features_input(original_text, cleaned_text):
    """Extracts numeric features from original and cleaned text."""
    logger = logging.getLogger(__name__) # Get logger instance
    features = {}
    # URL Features
    num_links, has_suspicious_url = 0, 0
    if isinstance(original_text, str):
        try:
            url_pattern = r'(https?://\S+|www\.\S+)'
            text_snippet = original_text[:50000] # Limit search length
            urls = re.findall(url_pattern, text_snippet)
            num_links = len(urls) # Count from snippet is faster/safer
            if urls:
                suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin', 'support', 'password', 'banking', 'activity', 'credential']
                shortened_domains_pattern = r'(bit\.ly/|goo\.gl/|tinyurl\.com/|t\.co/|ow\.ly/|is\.gd/|buff\.ly/|adf\.ly/|bit\.do/|soo\.gd/)'
                for url in urls[:100]: # Limit checks
                    url_lower = url.lower()
                    is_http = url_lower.startswith('http://')
                    is_short = re.search(shortened_domains_pattern, url_lower)
                    proto_end = url_lower.find('//'); path_query = ''
                    if proto_end > 0: domain_part_end = url_lower.find('/', proto_end + 2); path_query = url_lower[domain_part_end:] if domain_part_end > 0 else ''
                    else: domain_part_end = url_lower.find('/'); path_query = url_lower[domain_part_end:] if domain_part_end > 0 else ''
                    has_kw = any(keyword in (path_query + url_lower) for keyword in suspicious_keywords)
                    if is_http or is_short or has_kw: has_suspicious_url = 1; break
        except Exception as e: logger.error(f"URL feature error on input: {e}")
    features['num_links'] = num_links
    features['has_suspicious_url'] = has_suspicious_url

    # Urgency Features
    urgency_count = 0
    if isinstance(cleaned_text, str) and cleaned_text:
        try:
            urgency_words = ['urgent', 'immediately', 'action required', 'verify', 'password', 'alert', 'warning', 'limited time', 'expire', 'suspended', 'locked', 'important', 'final notice', 'response required', 'security update', 'confirm account', 'validate', 'due date', 'restricted', 'compromised', 'unauthorized']
            text_lower = cleaned_text.lower(); urgency_count = sum(len(re.findall(r'\b' + re.escape(word) + r'\b', text_lower)) for word in urgency_words)
        except Exception as e: logger.error(f"Urgency feature error on input: {e}")
    features['urgency_count'] = urgency_count

    # Readability Feature
    readability_score = 50.0 # Neutral default
    if nltk and isinstance(cleaned_text, str): # Check if NLTK was imported
        word_count = len(cleaned_text.split())
        if word_count < 10: readability_score = 100.0
        elif word_count > 10000: readability_score = 0.0 # Avoid extreme calculations
        else:
            try:
                 score = textstat.flesch_reading_ease(cleaned_text);
                 readability_score = max(-200, min(120, score)) if not np.isnan(score) else 50.0
            except Exception as e: logger.debug(f"Readability error on input: {e}") # Less critical
    features['readability_score'] = readability_score

    # Ensure all expected columns are present using global/loaded list
    if EXPECTED_NUMERIC_COLS:
        final_features = {col: features.get(col, 0) for col in EXPECTED_NUMERIC_COLS}
    else:
         logger.warning("EXPECTED_NUMERIC_COLS not defined, returning extracted features directly.")
         final_features = features # Fallback

    return final_features


# --- Flask App Initialization ---
app = Flask(__name__)

# --- Flask Routes ---

@app.route('/')
def home():
    """Renders the main input page."""
    return render_template('index.html', model_error=model_load_error)

@app.route('/predict', methods=['POST'])
def predict():
    """Handles the prediction request."""
    global model, preprocessor, model_load_error, EXPECTED_NUMERIC_COLS

    # Check if the necessary components are loaded
    if model is None or preprocessor is None:
        logger.error("Model or preprocessor not loaded, cannot predict.")
        # Use the stored error message if available
        error_msg = model_load_error if model_load_error else "Model/Preprocessor not available."
        return render_template('index.html',
                               prediction_text=f'Error: {error_msg}',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error) # Pass original error too

    try:
        email_text = request.form['email_text']
        logger.info(f"Received prediction request for email: '{email_text[:100]}...'")

        cleaned_text = clean_email_input(email_text)
        if not cleaned_text:
             logger.warning("Input email resulted in empty cleaned text.")
             return render_template('index.html',
                                    prediction_text='Input email content is empty after cleaning.',
                                    email_text=email_text,
                                    model_error=model_load_error)

        numeric_features = extract_features_input(email_text, cleaned_text)

        data = {
            'cleaned_text': [cleaned_text],
            **{k: [v] for k, v in numeric_features.items()}
        }
        input_df_for_pipeline = pd.DataFrame(data)

        if EXPECTED_NUMERIC_COLS is None:
             logger.error("Numeric columns expected by preprocessor are unknown. Prediction may fail.")
             return render_template('index.html', prediction_text='Error: Preprocessor configuration missing.', email_text=email_text, model_error=model_load_error)

        expected_cols_in_order = ['cleaned_text'] + EXPECTED_NUMERIC_COLS
        try:
            input_df_for_pipeline = input_df_for_pipeline[expected_cols_in_order]
            logger.info(f"Input DataFrame for pipeline prediction (shape {input_df_for_pipeline.shape}):\n{input_df_for_pipeline.head()}")
        except KeyError as e:
            logger.error(f"Column mismatch creating input DataFrame: {e}. Expected: {expected_cols_in_order}, Got: {input_df_for_pipeline.columns.tolist()}")
            return render_template('index.html', prediction_text=f'Error: Input data preparation failed (column mismatch).', email_text=email_text, model_error=model_load_error)
        except Exception as e_df:
             logger.error(f"Error creating input DataFrame: {e_df}", exc_info=True)
             return render_template('index.html', prediction_text=f'Error: Input data preparation failed.', email_text=email_text, model_error=model_load_error)


        logger.info(f"Making prediction using {MODEL_TYPE} model...")
        pred_proba_array = model.predict_proba(input_df_for_pipeline)
        prediction_proba = pred_proba_array[0][1] # Probability of class 1 (Phishing)
        prediction = 1 if prediction_proba >= 0.5 else 0

        logger.info(f"Prediction: {prediction}, Probability (Phishing): {prediction_proba:.4f}")

        result_text = "Phishing" if prediction == 1 else "Legitimate"
        confidence = prediction_proba if prediction == 1 else 1 - prediction_proba

        return render_template('index.html',
                               prediction_text=f'Result: {result_text} (Confidence: {confidence:.2%})',
                               email_text=email_text,
                               model_error=model_load_error)

    except Exception as e:
        logger.error(f"Error during prediction processing: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text=f'Error during prediction processing.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error)

# --- IMPORTANT: NO app.run() HERE! Gunicorn will run the 'app' object. ---