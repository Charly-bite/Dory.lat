# --- Ensemble app.py for Render Deployment ---

import os
import re
import sys # For exit on critical error
import numpy as np
import pandas as pd
import joblib # For loading sklearn models/preprocessor
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings
import textstat # For readability
try:
    import nltk
    try: nltk.data.find('tokenizers/punkt')
    except: nltk.download('punkt', quiet=True)
except ImportError:
    nltk = None
    print("--- WARNING: NLTK not found. Readability score might be less accurate. ---")

import logging
from flask import Flask, request, render_template
from scipy.sparse import issparse


# --- Global Configuration & Setup ---
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
OUTPUT_DIR = "saved_data"
MODELS_DIR = os.path.join(OUTPUT_DIR, "models")

# --- MODEL CONFIGURATION (Define all models to load) ---
# We assume these are Sklearn PIPELINE files (.pkl)
# The keys ('LR', 'DT') are just identifiers used in logs
MODELS_TO_LOAD = {
    "LR": "LogisticRegression_pipeline.pkl",
    "DT": "DecisionTree_pipeline.pkl",
    # Add more sklearn pipeline files here if you have them
}
# If you want to include Keras (ensure TF is installed and needed files are pushed)
# USE_KERAS = True
# KERAS_MODEL_FILENAME = "HybridNN.keras"
USE_KERAS = False # Set to True to enable Keras loading/prediction
KERAS_MODEL_FILENAME = "HybridNN.keras" # Only used if USE_KERAS is True

PREPROCESSOR_FILENAME = "preprocessor.pkl" # Still needed if Keras is used

# Construct full paths
PREPROCESSOR_PATH = os.path.join(MODELS_DIR, PREPROCESSOR_FILENAME)
if USE_KERAS:
    KERAS_MODEL_PATH = os.path.join(MODELS_DIR, KERAS_MODEL_FILENAME)
    # --- TensorFlow / Keras Import (Conditional) ---
    try:
        # Set TF environment variables BEFORE importing TensorFlow
        os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
        import tensorflow as tf
        tf.get_logger().setLevel('ERROR')
        from tensorflow.keras.models import load_model as load_keras_model
        TF_AVAILABLE = True
        logger.info(f"--- TensorFlow Loaded for App (Version: {tf.__version__}) ---")
    except ImportError:
        TF_AVAILABLE = False
        load_keras_model = None
        logger.error("--- FATAL: USE_KERAS is True but TensorFlow not found. Keras model cannot be loaded. ---")
        # Potentially exit or disable Keras use here if critical
        USE_KERAS = False # Disable Keras if import failed

# --- Load Models and Preprocessor ---
loaded_models = {} # Dictionary to store loaded models
preprocessor = None # Will hold the standalone preprocessor if needed for Keras
model_load_errors = [] # List to store loading errors
EXPECTED_NUMERIC_COLS = None # Initialize

logger.info("--- Loading Models and Preprocessor ---")
logger.info(f"App directory (Current Working Directory): {os.getcwd()}")

# --- Load Standalone Preprocessor (Needed if Keras is used, or for column names) ---
logger.info(f"Attempting to load Preprocessor from: {PREPROCESSOR_PATH}")
try:
    if os.path.exists(PREPROCESSOR_PATH):
        preprocessor = joblib.load(PREPROCESSOR_PATH)
        logger.info("Preprocessor loaded successfully.")
        # Extract expected numeric columns (useful even without Keras)
        try:
            numeric_transformer_tuple = next(t for t in preprocessor.transformers_ if t[0] == 'numeric')
            EXPECTED_NUMERIC_COLS = numeric_transformer_tuple[2]
            if not isinstance(EXPECTED_NUMERIC_COLS, list): EXPECTED_NUMERIC_COLS = list(EXPECTED_NUMERIC_COLS) # Ensure list
            logger.info(f"Expected numeric columns from preprocessor: {EXPECTED_NUMERIC_COLS}")
        except Exception as e:
            logger.error(f"Could not extract numeric columns from preprocessor: {e}")
            EXPECTED_NUMERIC_COLS = None # Fallback handled later if needed
    else:
        logger.warning(f"Standalone preprocessor file not found at: {PREPROCESSOR_PATH}")
        # If Keras relies on it, this is an issue
        if USE_KERAS:
             model_load_errors.append(f"Keras enabled but required preprocessor not found at {PREPROCESSOR_PATH}")
        preprocessor = None # Ensure it's None

except Exception as e:
    logger.error(f"Error loading preprocessor: {e}", exc_info=True)
    model_load_errors.append(f"Error loading preprocessor: {e}")
    preprocessor = None

# --- Load Sklearn Pipeline Models ---
for model_key, model_filename in MODELS_TO_LOAD.items():
    model_path = os.path.join(MODELS_DIR, model_filename)
    logger.info(f"Attempting to load Sklearn model '{model_key}' from: {model_path}")
    if os.path.exists(model_path):
        try:
            loaded_model = joblib.load(model_path)
            loaded_models[model_key] = loaded_model
            logger.info(f"Model '{model_key}' loaded successfully.")
            # Try extracting columns if not found yet (from first loaded pipeline)
            if EXPECTED_NUMERIC_COLS is None and hasattr(loaded_model, 'steps'):
                 try:
                    pipe_preprocessor = loaded_model.steps[0][1] # Assume preprocessor is first step
                    numeric_transformer_tuple = next(t for t in pipe_preprocessor.transformers_ if t[0] == 'numeric')
                    EXPECTED_NUMERIC_COLS = numeric_transformer_tuple[2]
                    if not isinstance(EXPECTED_NUMERIC_COLS, list): EXPECTED_NUMERIC_COLS = list(EXPECTED_NUMERIC_COLS)
                    logger.info(f"Extracted numeric columns from '{model_key}' pipeline: {EXPECTED_NUMERIC_COLS}")
                 except Exception:
                     logger.warning(f"Could not extract numeric columns from pipeline '{model_key}'.")

        except Exception as e:
            error_msg = f"Error loading model '{model_key}' from {model_path}: {e}"
            logger.error(error_msg, exc_info=True)
            model_load_errors.append(error_msg)
    else:
        error_msg = f"Model file for '{model_key}' not found at: {model_path}"
        logger.error(error_msg)
        model_load_errors.append(error_msg)

# --- Load Keras Model (Conditional) ---
if USE_KERAS:
    logger.info(f"Attempting to load Keras model from: {KERAS_MODEL_PATH}")
    if not TF_AVAILABLE:
         error_msg = "Cannot load Keras model - TensorFlow not available."
         logger.error(error_msg)
         model_load_errors.append(error_msg)
    elif not preprocessor:
         error_msg = "Cannot use Keras model - Standalone preprocessor failed to load."
         logger.error(error_msg)
         model_load_errors.append(error_msg)
    elif os.path.exists(KERAS_MODEL_PATH):
        try:
            loaded_keras_model = load_keras_model(KERAS_MODEL_PATH)
            loaded_models["KerasNN"] = loaded_keras_model # Add to dict
            logger.info("Keras model 'KerasNN' loaded successfully.")
        except Exception as e:
            error_msg = f"Error loading Keras model from {KERAS_MODEL_PATH}: {e}"
            logger.error(error_msg, exc_info=True)
            model_load_errors.append(error_msg)
    else:
        error_msg = f"Keras model file not found at: {KERAS_MODEL_PATH}"
        logger.error(error_msg)
        model_load_errors.append(error_msg)

# --- Final Loading Checks ---
if not loaded_models: # Check if the dictionary is empty
    logger.critical("----- FATAL: No models loaded successfully. App cannot make predictions. -----")
    # Store combined error messages
    model_load_error_str = "Failed to load any models. Check logs. " + "; ".join(model_load_errors)
else:
    logger.info(f"--- Successfully loaded models: {list(loaded_models.keys())} ---")
    model_load_error_str = "; ".join(model_load_errors) if model_load_errors else None # Use None if no errors

# Set fallback numeric columns if still None after all loading attempts
if EXPECTED_NUMERIC_COLS is None:
    EXPECTED_NUMERIC_COLS = ['num_links', 'has_suspicious_url', 'urgency_count', 'readability_score'] # Fallback
    logger.warning(f"Using fallback numeric columns: {EXPECTED_NUMERIC_COLS}")
    if not model_load_error_str: model_load_error_str = "Could not determine numeric columns from models; using defaults."
    elif "determine numeric columns" not in model_load_error_str: model_load_error_str += " Also using default numeric columns."


# --- Preprocessing Functions (Keep as before) ---
def clean_email_input(text):
    logger = logging.getLogger(__name__)
    if pd.isna(text) or not isinstance(text, str) or text.strip() == "": return ""
    try:
        try: soup = BeautifulSoup(text, 'lxml')
        except: soup = BeautifulSoup(text, 'html.parser')
        cleaned = soup.get_text(separator=' ')
        cleaned = re.sub(r'https?://\S+|www\.\S+', ' URL ', cleaned)
        cleaned = re.sub(r'[^a-zA-Z0-9\s.,!?\'`]', ' ', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned
    except Exception as e: logger.error(f"Cleaning input error: {e}"); return ""

def extract_features_input(original_text, cleaned_text):
    logger = logging.getLogger(__name__)
    features = {}
    # ... (keep exact feature extraction logic as in previous version) ...
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
    # Ensure all expected columns are present
    if EXPECTED_NUMERIC_COLS: final_features = {col: features.get(col, 0) for col in EXPECTED_NUMERIC_COLS}
    else: logger.warning("EXPECTED_NUMERIC_COLS not defined, returning extracted features directly."); final_features = features
    return final_features

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Flask Routes ---

@app.route('/')
def home():
    """Renders the main input page."""
    # Pass the combined model_load_error string to the template
    return render_template('index.html', model_error=model_load_error_str)

@app.route('/predict', methods=['POST'])
def predict():
    """Handles the prediction request using ensemble."""
    global loaded_models, preprocessor, model_load_error_str, EXPECTED_NUMERIC_COLS

    # Check if ANY model loaded successfully
    if not loaded_models:
        logger.error("No models available for prediction.")
        return render_template('index.html',
                               prediction_text='Error: No models available for prediction.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str)

    try:
        email_text = request.form['email_text']
        logger.info(f"Received prediction request for email: '{email_text[:100]}...'")

        # 1. Preprocess input
        cleaned_text = clean_email_input(email_text)
        if not cleaned_text:
             logger.warning("Input email resulted in empty cleaned text.")
             return render_template('index.html',
                                    prediction_text='Input email content is empty after cleaning.',
                                    email_text=email_text,
                                    model_error=model_load_error_str)

        # 2. Extract features
        numeric_features = extract_features_input(email_text, cleaned_text)

        # 3. Create DataFrame for prediction input
        data = {
            'cleaned_text': [cleaned_text],
            **{k: [v] for k, v in numeric_features.items()}
        }
        input_df = pd.DataFrame(data)

        # Ensure column order matches expectations
        if EXPECTED_NUMERIC_COLS is None:
             logger.error("Numeric columns expected by preprocessor/models are unknown.")
             return render_template('index.html', prediction_text='Error: Model configuration missing.', email_text=email_text, model_error=model_load_error_str)

        expected_cols_in_order = ['cleaned_text'] + EXPECTED_NUMERIC_COLS
        try:
            input_df = input_df[expected_cols_in_order]
            logger.info(f"Input DataFrame for prediction (shape {input_df.shape}) prepared.")
        except KeyError as e:
            logger.error(f"Column mismatch creating input DataFrame: {e}.")
            return render_template('index.html', prediction_text=f'Error: Input data prep failed (columns).', email_text=email_text, model_error=model_load_error_str)
        except Exception as e_df:
             logger.error(f"Error creating input DataFrame: {e_df}", exc_info=True)
             return render_template('index.html', prediction_text=f'Error: Input data prep failed.', email_text=email_text, model_error=model_load_error_str)

        # --- 4. Get Predictions from Each Model ---
        individual_probas = {}
        keras_transformed_data = None # Store transformed data if Keras needs it

        # Pre-transform data if Keras model is loaded
        if "KerasNN" in loaded_models:
            if not preprocessor:
                 logger.error("Keras model loaded, but standalone preprocessor is missing. Cannot predict with Keras.")
            else:
                 try:
                    logger.info("Transforming data for Keras model...")
                    keras_transformed_data = preprocessor.transform(input_df)
                    if issparse(keras_transformed_data): keras_transformed_data = keras_transformed_data.toarray()
                    logger.info("Input data transformed for Keras.")
                 except Exception as e:
                    logger.error(f"Error transforming data for Keras: {e}. Keras prediction will be skipped.")
                    keras_transformed_data = None # Ensure it's None on error


        # Loop through loaded models
        for model_name, model_instance in loaded_models.items():
            try:
                logger.info(f"Predicting with model: {model_name}")
                proba_phishing = -1.0 # Default error value

                if model_name == "KerasNN":
                    if keras_transformed_data is not None:
                        # Logic to split features for Keras based on expected input shapes
                        try:
                            text_input_shape = next(inp.shape for inp in model_instance.inputs if 'text_features_input' in inp.name)
                            struct_input_shape = next(inp.shape for inp in model_instance.inputs if 'structural_features_input' in inp.name)
                            text_feature_count = text_input_shape[1]
                        except: # Fallback if names don't match or introspection fails
                            logger.warning("Could not infer Keras input shapes, assuming text_feature_count=2000.")
                            text_feature_count = 2000 # Adjust if needed

                        text_input_keras = keras_transformed_data[:, :text_feature_count].astype(np.float32)
                        struct_input_keras = keras_transformed_data[:, text_feature_count:].astype(np.float32)

                        pred_proba_array = model_instance.predict([text_input_keras, struct_input_keras], verbose=0)
                        proba_phishing = pred_proba_array[0][0]
                    else:
                         logger.warning(f"Skipping Keras prediction due to prior transform error.")
                         continue # Skip this model iteration

                # Assume Sklearn pipeline otherwise
                else:
                    pred_proba_array = model_instance.predict_proba(input_df)
                    proba_phishing = pred_proba_array[0][1] # Probability of class 1

                individual_probas[model_name] = proba_phishing
                logger.info(f"Model '{model_name}' prediction proba: {proba_phishing:.4f}")

            except Exception as e:
                logger.error(f"Error predicting with model '{model_name}': {e}", exc_info=True)
                # Optionally store -1 or skip this model for averaging
                individual_probas[model_name] = -1.0 # Indicate error

        # --- 5. Combine Probabilities (Soft Voting) ---
        valid_probas = [p for p in individual_probas.values() if p >= 0.0] # Filter out errors (-1.0)

        if not valid_probas:
            logger.error("No valid predictions obtained from any model.")
            return render_template('index.html', prediction_text='Error: Prediction failed for all models.', email_text=email_text, model_error=model_load_error_str)

        average_proba = np.mean(valid_probas)
        final_prediction = 1 if average_proba >= 0.5 else 0
        logger.info(f"Average phishing probability: {average_proba:.4f} (from {len(valid_probas)} models)")
        logger.info(f"Final ensemble prediction: {final_prediction}")


        # --- 6. Format Output ---
        result_text = "Phishing" if final_prediction == 1 else "Legitimate"
        # Confidence based on the average probability
        confidence = average_proba if final_prediction == 1 else 1 - average_proba

        # Optional: Include individual model probs in detailed output or logs
        # detail_text = ", ".join([f"{name}: {p:.2f}" for name, p in individual_probas.items() if p >= 0])

        return render_template('index.html',
                               prediction_text=f'Result: {result_text} (Avg Confidence: {confidence:.2%})',
                               # prediction_detail=f'Model Probs -> {detail_text}', # Optional detail
                               email_text=email_text,
                               model_error=model_load_error_str)

    except Exception as e:
        logger.error(f"Error during prediction processing: {e}", exc_info=True)
        return render_template('index.html',
                               prediction_text=f'Error during prediction processing.',
                               email_text=request.form.get('email_text', ''),
                               model_error=model_load_error_str)

# --- Run Check (Important for Render Startup) ---
# Although Gunicorn runs 'app', Render might still check if the file can be executed.
# This check prevents the app from exiting immediately if run directly for testing.
if __name__ == '__main__':
    # Check if loading succeeded before allowing run
    if not loaded_models:
         logger.critical("----- FATAL: No models loaded successfully. App cannot start. Check logs. -----")
         if model_load_error_str: logger.critical(f"----- Loading Errors: {model_load_error_str} -----")
         sys.exit("No models loaded.") # Exit if loading failed
    else:
         logger.warning("----- This script is intended to be run with Gunicorn on Render. -----")
         logger.warning("----- Running directly with 'python app.py' is for local testing ONLY. -----")
         # Start development server if run directly (for local testing)
         app.run(host='127.0.0.1', port=5000, debug=True) # Enable debug for local testing