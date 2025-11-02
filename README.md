# Dory-Lat Phishing Detection App

This is a web application that uses a machine learning model to detect phishing emails. The application is built with Flask and uses a trained Keras model to make predictions.

## Features

-   Analyzes email text to predict whether it's phishing or legitimate.
-   Provides a confidence score for the prediction.
-   Simple web interface for pasting email content.

## Project Structure

```
.
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── saved_data/         # Directory for saved models and data
│   └── models/
│       ├── HybridNN.keras
│       ├── embedding_model_info.json
│       ├── numeric_cols_info.json
│       └── numeric_preprocessor.pkl
└── templates/
    └── index.html      # HTML template for the web interface
```

## Setup and Usage

### Prerequisites

-   Python 3.8+
-   Pip

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Charly-bite/dory-lat-app.git
    cd dory-lat-app
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

1.  **Start the Flask server:**
    ```bash
    python app.py
    ```

2.  **Open your browser** and navigate to `http://127.0.0.1:5000`.

3.  **Paste the email content** into the text area and click "Analyze".

## Docker

You can also run this application using Docker.

1.  **Build the Docker image:**
    ```bash
    docker build -t dory-lat-app .
    ```

2.  **Run the Docker container:**
    ```bash
    docker run -p 5000:5000 dory-lat-app
    ```
The application will be available at `http://localhost:5000`.
