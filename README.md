# 🔐 Dory - Phishing Email Detector

[![Version](https://img.shields.io/badge/version-2.3--stable-blue)](https://github.com/Charly-bite/dory-lat-app)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Live Demo](https://img.shields.io/badge/demo-dory.lat-brightgreen)](https://www.dory.lat)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://www.python.org/)

**Dory** is a multi-layered phishing email detection system that combines enhanced heuristics, Google Safe Browsing API, and user feedback to protect users from phishing attacks.

🌐 **Live Demo:** [www.dory.lat](https://www.dory.lat)  
📊 **Model Card:** [MODEL_CARD.md](MODEL_CARD.md)  
📝 **Roadmap:** [MEJORAS_ROADMAP.json](MEJORAS_ROADMAP.json)

---

## ✨ Features

### Core Detection (v2.3-stable)
- ✅ **Enhanced Heuristics Engine** - 20+ phishing indicators with 4-tier weighted scoring
- ✅ **Google Safe Browsing API** - Real-time malicious URL verification
- ✅ **User Feedback System** - Continuous improvement through user input
- ✅ **Bilingual Interface** - Full Spanish/English support (ES default for .lat domain)
- ✅ **Pre-loaded Examples** - 6 sample emails to test the system
- ✅ **Admin Dashboard** - View feedback statistics and export data

### Detection Layers

#### Tier 1: Critical Indicators (50-30 points)
- 🔴 Google Safe Browsing confirmation (50pts)
- 🔴 IP address in URL (35pts)
- 🔴 Credential request detected (30pts)

#### Tier 2: Strong Indicators (25-15 points)
- 🟠 Brand typosquatting (25pts)
- 🟠 Multiple URLs (6-25pts)
- 🟠 Suspicious TLD (20pts)
- 🟠 Urgency tactics (20pts)
- 🟠 Unrealistic offers (18pts)

#### Tier 3: Moderate Indicators (15-10 points)
- 🟡 URL shorteners (15pts)
- 🟡 Phishing keywords (8-20pts)
- 🟡 Generic greeting (10pts)

#### Tier 4: Minor Indicators (8-3 points)
- 🟢 Excessive capitalization (3-12pts)
- 🟢 Multiple exclamation marks (2-8pts)

---

## 📊 Performance Metrics

| Metric | v2.3-stable | Target v3.0 |
|--------|-------------|-------------|
| **Overall Accuracy** | 80-88% | 90-95% |
| **Precision** | 75-85% | 88-92% |
| **Recall** | 80-90% | 90-95% |
| **False Positive Rate** | 8-12% | 5-8% |
| **Google Safe Browsing** | 95-99%* | 95-99%* |

*When URL is in Google's database

---

## 🚀 Quick Start

### Option 1: Use Live Demo
Visit [www.dory.lat](https://www.dory.lat) and start analyzing emails immediately!

### Option 2: Run Locally

#### Prerequisites
- Python 3.11+
- pip

#### Installation

```bash
# Clone repository
git clone https://github.com/Charly-bite/dory-lat-app.git
cd dory-lat-app

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements_hf.txt

# Run application
python app_hf.py
```

Open browser to `http://127.0.0.1:5000`

### Option 3: Docker

```bash
# Build image
docker build -t dory-lat-app .

# Run container
docker run -p 5000:5000 dory-lat-app
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Required for production
PORT=10000                          # Server port (Render uses 10000)
PYTHON_VERSION=3.11.11             # Python version

# Optional but recommended
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here  # Get from Google Cloud
HF_API_TOKEN=your_token_here               # For future ML model

# Admin dashboard (defaults shown)
ADMIN_USERNAME=admin               # Change in production!
ADMIN_PASSWORD=dory2024           # Change in production!
```

### Getting Google Safe Browsing API Key

See detailed guide: [GOOGLE_SAFE_BROWSING_SETUP.md](GOOGLE_SAFE_BROWSING_SETUP.md)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create project
3. Enable "Safe Browsing API"
4. Create API key
5. Add to environment variables

---

## 📁 Project Structure

```
dory-lat-app/
├── app_hf.py                      # Main Flask application (v2.3)
├── app.py                         # Legacy app (deprecated)
├── requirements_hf.txt            # Production dependencies
├── Dockerfile                     # Docker configuration
├── render.yaml                    # Render.com deployment config
├── feedback.db                    # SQLite database (user feedback)
│
├── templates/
│   └── index.html                 # Bilingual web interface
│
├── static/                        # Static assets (CSS, JS, images)
│
├── saved_data/models/             # ML model files (for v3.0)
│   ├── HybridNN.keras            # Trained neural network
│   ├── embedding_model_info.json
│   ├── numeric_cols_info.json
│   └── numeric_preprocessor.pkl
│
├── MODEL_CARD.md                  # Complete model documentation
├── GOOGLE_SAFE_BROWSING_SETUP.md # API setup guide
├── MEJORAS_ROADMAP.json          # Feature roadmap
├── MEJORAS_IMPLEMENTADAS.md      # Implementation progress
└── README.md                      # This file
```

---

## 🎯 Usage Examples

### Example 1: Phishing Email
```
URGENT! Your PayPal account has been suspended.
Click here immediately to verify: http://paypa1-secure.tk/login
```
**Result:** ⚠️ PHISHING (85% confidence)  
**Threats:** Suspicious TLD, Urgency tactics, Brand typosquatting, Credential request

### Example 2: Legitimate Email
```
Hi John,
Thank you for your order #12345. Your package will arrive on Monday.
Track your shipment: https://www.fedex.com/tracking
Best regards,
FedEx Customer Service
```
**Result:** ✅ LEGITIMATE (92% confidence)  
**Analysis:** No suspicious indicators detected

### Example 3: Borderline Case
```
LIMITED TIME OFFER!!!
Get 50% off all products this weekend only.
Visit our store: https://bit.ly/store2024
```
**Result:** ⚠️ PHISHING (58% confidence)  
**Threats:** URL shortener, Excessive caps, Multiple exclamation marks, Urgency tactics

---

## 🔐 Admin Dashboard

Access at `/admin/feedback` with credentials:

### View Statistics
```bash
curl -u admin:dory2024 https://www.dory.lat/admin/feedback
```

**Response:**
```json
{
  "statistics": {
    "total_feedback": 150,
    "correct_predictions": 128,
    "incorrect_predictions": 22,
    "accuracy": 85.33,
    "phishing_predictions": 75,
    "legitimate_predictions": 75
  },
  "recent_feedback": [...]
}
```

### Export Data
```bash
curl -u admin:dory2024 https://www.dory.lat/admin/feedback/export > feedback_data.json
```

---

## 🛠️ API Endpoints

### `POST /predict`
Analyze email text for phishing indicators.

**Request:**
```bash
curl -X POST https://www.dory.lat/predict \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email_text=URGENT! Click here now: http://evil.tk'
```

**Response:**
```json
{
  "prediction": "PHISHING",
  "confidence": 0.87,
  "probability_phishing": 0.87,
  "probability_legitimate": 0.13,
  "threats_detected": [
    "Suspicious domain extension",
    "Urgent language tactics"
  ],
  "google_safe_browsing": {
    "checked": true,
    "is_safe": false,
    "malicious_urls": ["http://evil.tk"],
    "threats_found": ["Malware"]
  },
  "analysis": {
    "text_length": 35,
    "word_count": 5,
    "url_count": 1,
    "uppercase_ratio": 0.143,
    "phishing_keywords": 2,
    "risk_score": "65/145"
  },
  "flags": {
    "suspicious_tld": true,
    "urgency_tactics": true,
    ...
  },
  "version": "2.3"
}
```

### `POST /feedback`
Submit user feedback on prediction accuracy.

**Request:**
```bash
curl -X POST https://www.dory.lat/feedback \
  -H 'Content-Type: application/json' \
  -d '{
    "email_text": "...",
    "prediction": "PHISHING",
    "user_feedback": "correct",
    "confidence": 0.85
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Feedback recorded successfully",
  "feedback_id": 42
}
```

### `GET /health`
Check service status and features.

**Request:**
```bash
curl https://www.dory.lat/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "dory-phishing-detector-hf",
  "version": "2.3-feedback-system",
  "features": {
    "enhanced_heuristics": true,
    "google_safe_browsing": true,
    "bilingual_support": true,
    "user_feedback_system": true
  }
}
```

---

## 📈 Version History

| Version | Date | Key Features | Accuracy |
|---------|------|--------------|----------|
| **2.3-stable** | Nov 2, 2025 | Optimized weights, calibrated thresholds, complete docs | 80-88% |
| 2.2 | Nov 2, 2025 | Google Safe Browsing API integration | 75-85% |
| 2.1 | Nov 1, 2025 | Enhanced heuristics (8→20+ features) | 75-85% |
| 2.0 | Oct 2025 | User feedback system, bilingual UI | 70-80% |
| 1.0 | Sep 2025 | Basic heuristics (8 features) | 65-75% |

---

## 🚧 Roadmap

### ✅ Completed (v2.3-stable)
- [x] Enhanced heuristics engine (20+ features)
- [x] Google Safe Browsing API integration
- [x] User feedback system with SQLite
- [x] Admin dashboard with statistics
- [x] Complete bilingual support (ES/EN)
- [x] Pre-loaded example emails
- [x] Optimized weights and thresholds
- [x] Comprehensive documentation (Model Card)

### 🔄 In Progress (v3.0 - Neural Network)
- [ ] Train Keras model on collected feedback data
- [ ] Upload model to HuggingFace Hub
- [ ] Integrate HF Inference API
- [ ] Ensemble approach (ML + heuristics)
- [ ] A/B testing framework
- [ ] Active learning pipeline

### 📅 Planned Future (v3.1+)
- [ ] Multi-language support (beyond ES/EN)
- [ ] Browser extension
- [ ] Email client integration
- [ ] Real-time threat intelligence feed
- [ ] Explainable AI (SHAP values for predictions)
- [ ] Mobile app (iOS/Android)

---

## 🧪 Testing

### Run Health Check
```bash
curl https://www.dory.lat/health | jq
```

### Test Phishing Detection
```bash
# Test with known phishing email
curl -X POST https://www.dory.lat/predict \
  -d 'email_text=URGENT: Verify account at http://paypa1.tk' \
  | jq '.prediction,.confidence'
```

### Test Google Safe Browsing
```bash
# Use Google's test URL (may or may not trigger in production)
curl -X POST https://www.dory.lat/predict \
  -d 'email_text=Check this: http://testsafebrowsing.appspot.com/s/malware.html' \
  | jq '.google_safe_browsing'
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m 'Add amazing feature'`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Areas for Contribution
- 🐛 Bug fixes
- 📝 Documentation improvements
- 🌐 Translations (add new languages)
- 🧪 Test coverage
- 🎨 UI/UX improvements
- 📊 Dataset contributions (labeled emails)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Google Safe Browsing** - For malicious URL database
- **HuggingFace** - For sentence-transformers models
- **Render.com** - For free hosting
- **Contributors** - All users providing feedback at dory.lat

---

## 📞 Contact & Support

- **Website:** [www.dory.lat](https://www.dory.lat)
- **GitHub:** [Charly-bite/dory-lat-app](https://github.com/Charly-bite/dory-lat-app)
- **Issues:** [GitHub Issues](https://github.com/Charly-bite/dory-lat-app/issues)

---

## ⚠️ Disclaimer

**Dory is a detection tool, not a guarantee.** Always exercise caution with suspicious emails:
- ✅ Verify sender through official channels
- ✅ Never click links in suspicious emails
- ✅ Use multi-factor authentication
- ✅ Keep software updated
- ❌ Don't rely solely on automated tools

**This tool is for educational and personal use. Not validated for legal or forensic purposes.**

---

**Made with ❤️ by Charly-bite | Protecting users from phishing, one email at a time**
