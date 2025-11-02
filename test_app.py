"""
Simple test Flask app to verify Gunicorn and port binding work on Render.
This is a minimal app without heavy ML model loading.
"""
from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return {'status': 'OK', 'message': 'Test app is running!'}

@app.route('/health')
def health():
    return {'status': 'healthy'}, 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
