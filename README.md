# 🔐 Password Strength Analyzer & Manager

An advanced, cryptographically secure Password Strength Analyzer and Generator. Now features both an interactive, Rich-powered **Python CLI** and a gorgeous, client-side **React + Vite Web App**.

---

## 🌟 Features

### 🖥️ Web Application (Vite + React)
- **Real-Time Analysis**: Direct visual score updates (0–100) and rating indicators (Very Weak to Very Strong) as you type.
- **Complexity Breakdown Checklist**: Visual checkmarks displaying character category counts and length requirements.
- **Entropy & Crack Time**: Evaluates Shannon entropy in bits and estimates brute-force crack times on a modern offline GPU cluster (1e12 guesses/second).
- **HaveIBeenPwned Breach Checker**: Integrates the HIBP range API with **k-Anonymity privacy protection** (your plaintext password and full hash never leave your browser).
- **Weakness Scan**: Detects keyboard patterns (`qwerty`), alphabetical and numerical sequences (`abc`, `123`), repeated characters, year ranges, palindromes, and common English names.
- **Actionable Steps**: Provides tailored, prioritized suggestions on how to strengthen your password.
- **Cryptographic Generator**: Employs secure cryptographic entropy (`window.crypto.getRandomValues`) to generate single or bulk passwords with custom character parameter settings.
- **Session Audit Logs**: Save, view, and export metadata assessments to **JSON** or **CSV** format. (Plaintext passwords are never logged).

### 🐍 Python CLI (`password_analyzer.py`)
- **Rich-Powered Interactive Menus**: Styled terminal interface with support for dark-mode.
- **Secure Masking**: Employs `getpass` to hide password inputs.
- **Offline GPU Crack Estimator**: Shannon entropy measurements and estimation tables.
- **HIBP K-Anonymity Queries**: Secure remote API checking.
- **Export Capabilities**: Saves audited CLI session metadata reports to JSON or CSV.

---

## 🚀 Getting Started

### Option 1: Running the Web Application
The web application is located in the `web-app` directory and runs completely client-side in the browser.

#### Prerequisites
- Node.js (v18+) and npm installed.

#### Installation & Startup
```bash
# Navigate to the web application directory
cd web-app

# Install dependencies
npm install

# Start the local development server
npm run dev
```

Open the local URL displayed in your terminal (typically `http://localhost:5173`) in your browser.

---

### Option 2: Running the Python CLI
The python CLI operates directly inside your shell environment.

#### Prerequisites
- Python 3.8+
- Recommended: `rich` and `requests` libraries.

#### Installation & Startup
```bash
# Install optional dependencies for rich colors and HIBP breach scanning
pip install rich requests

# Run in interactive CLI menu mode
python password_analyzer.py

# Or analyze a password directly via flags
python password_analyzer.py --analyze --show-password

# Or generate 5 secure passwords of length 24
python password_analyzer.py --generate --length 24 --count 5
```

---

## 🛡️ Security & Privacy Policy

Privacy and absolute credential safety are core design pillars of this tool:

1. **Zero plaintext transmission**: Plaintext passwords are never sent over the network, saved to disk, or logged.
2. **K-Anonymity hashing standard**: When checking HaveIBeenPwned, the password is encrypted locally using the SHA-1 algorithm. The app sends **only the first 5 characters** of the hash prefix to the API. The API returns candidate suffixes, and the final match is computed locally.
3. **Cryptographically secure randomness**: Generative engines use either Python's `secrets` module (which calls `os.urandom`) or JavaScript's `window.crypto.getRandomValues()`. No weak pseudo-random math is used.
