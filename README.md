# Phishing Detection Chrome Extension

## Overview

The Phishing Detection Chrome Extension proactively protects users against phishing attacks in real time. It leverages machine learning to analyze website URLs and content, immediately warning users if a site appears suspicious or potentially malicious. This project demonstrates cybersecurity, machine learning, and browser extension development skills.

***

## Features

- **Real-time website and URL analysis** to flag phishing threats
- **Machine learning classifier** trained on large datasets
- **On-page pop-up warning system** for suspicious sites
- **User feedback reporting** to improve detection accuracy
- **Integration with blacklists/whitelists**
- **Privacy-first implementation:** All analysis is local or sent securely; no personal data is stored

***

## Tech Stack

- **Frontend:** JavaScript, HTML, CSS (Chrome Extensions API)
- **Machine Learning:** Python (scikit-learn/XGBoost), FastAPI (for optional backend serving)
- **Data:** Phishing and legitimate URLs from PhishTank, Kaggle
- **Testing:** Jest (JavaScript), pytest (Python)
- **AI Assistance:** GitHub Copilot, Cursor, or CodeRabbit for code generation, testing, and review

***

## Setup \& Installation

1. **Clone the repository:**

```bash
git clone https://github.com/MurungaOwen/alx_ai_capstone.git
```

2. **Install dependencies:**
    - For ML backend:

```bash
cd ml-model
pip install -r requirements.txt
```

    - For extension:
No install required; code runs in browser.
3. **Load the extension in Chrome:**
    - Open `chrome://extensions/`
    - Enable "Developer mode"
    - Click "Load unpacked" and select the project `extension` directory
4. **(Optional) Run ML backend:**

```bash
cd ml-model
uvicorn app:app --reload
```


***

## Usage

- Browse the web as normal.
- When a suspicious site is detected, a pop-up notifies you with a warning and recommended action.
- Users can provide feedback on false positives/negatives to enhance accuracy.

***

## Customization

- Train the ML model on your own datasets using `ml-model/train.py`.
- Modify blacklists/whitelists in the `data/` directory.
- Enhance popup UI in `extension/popup.html`.

***

## AI Usage in Development

- Used AI for code scaffolding, optimizing test coverage, and generating OpenAPI-compliant API routes.
- Prompting strategy examples are included in `prompts/`.

***

## Contribution

1. **Fork the repository**
2. Create your feature branch: `git checkout -b feature/NewFeature`
3. Commit your changes: `git commit -m "Add new feature"`
4. Push to the branch: `git push origin feature/NewFeature`
5. Open a pull request

***

## License

MIT

***

## Acknowledgments

- Public threat intelligence from PhishTank and Kaggle
- Open-source tools: scikit-learn, XGBoost, Chrome API

***

This README provides a clear introduction and quickstart for your project. Add demo images, test cases, or documentation sections as your project evolves for even broader impact and usability.

