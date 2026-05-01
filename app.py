from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import pickle
import os
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

import google.generativeai as genai
from dotenv import load_dotenv

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from features import extract_features, FEATURE_COLUMNS

# -----------------------------
# 🔧 INIT
# -----------------------------
app = Flask(__name__)
CORS(app)

load_dotenv()

# -----------------------------
# 🔑 LOAD MODEL
# -----------------------------
model = pickle.load(open("model.pkl", "rb"))

# -----------------------------
# 🤖 GEMINI SETUP
# -----------------------------
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

gemini_model = None

if GEMINI_KEY:

    genai.configure(api_key=GEMINI_KEY)

    gemini_model = genai.GenerativeModel(
        "gemini-2.5-flash"
    )

# -----------------------------
# 🌍 TRUSTED DOMAINS
# -----------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.in",
    "github.com",
    "wikipedia.org"
]

def is_trusted(url):
    domain = urlparse(url).netloc.lower()
    return any(d in domain for d in TRUSTED_DOMAINS)

# -----------------------------
# 🚨 BLACKLIST CHECK
# -----------------------------
def check_blacklist(url):
    try:
        response = requests.get(
            "https://openphish.com/feed.txt",
            timeout=5
        )

        if response.status_code == 200:
            phishing_urls = response.text.splitlines()[:2000]

            for p in phishing_urls:
                if url.lower() in p.lower():
                    return -40, "URL found in phishing blacklist"

        return 0, None

    except:
        return 0, None

# -----------------------------
# 🔍 BASIC CHECK
# -----------------------------
def basic_url_check(url):
    score = 100
    reasons = []

    if not url.startswith("https"):
        score -= 20
        reasons.append("No HTTPS")

    if any(
        w in url.lower()
        for w in ["login", "verify", "bank", "account", "secure"]
    ):
        score -= 15
        reasons.append("Contains sensitive keywords")

    if len(url) > 75:
        score -= 10
        reasons.append("URL too long")

    if url.count("/") > 4:
        score -= 10
        reasons.append("Too many URL segments")

    return score, reasons

# -----------------------------
# 🌍 DOMAIN AGE
# -----------------------------
def get_domain_age_score(url):
    try:
        domain = urlparse(url).netloc

        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0, "Domain age unknown"

        age_days = (datetime.now() - creation_date).days

        if age_days > 365:
            return 0, "Old domain"

        elif age_days > 180:
            return -5, "Medium age domain"

        else:
            return -15, "New domain (risky)"

    except:
        return -10, None

# -----------------------------
# 🔐 LOGIN DETECTION
# -----------------------------
def detect_login_risk(driver):
    score_delta = 0
    reasons = []

    inputs = driver.find_elements("tag name", "input")

    has_password = False
    has_user = False

    for i in inputs:

        t = (i.get_attribute("type") or "").lower()

        name = (i.get_attribute("name") or "").lower()

        placeholder = (
            i.get_attribute("placeholder") or ""
        ).lower()

        if t == "password":
            has_password = True

        if any(
            x in (name + placeholder)
            for x in ["email", "user", "login"]
        ):
            has_user = True

    if has_password and has_user:

        reasons.append("Login form detected")

        if not driver.current_url.startswith("https"):
            score_delta -= 25
            reasons.append("Login form on non-HTTPS")

    return score_delta, reasons

# -----------------------------
# 🌐 SELENIUM ANALYSIS
# -----------------------------
def analyze_with_selenium(url):

    # 🔥 Disable Selenium on Render
    if os.getenv("RENDER") == "true":
        return 100, ["Selenium skipped (production mode)"], [], [], []

    score = 100
    reasons = []

    links, forms, iframes = [], [], []

    driver = None

    try:
        options = Options()

        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=options)

        driver.set_page_load_timeout(8)

        original_url = url

        driver.get(url)

        if driver.current_url != original_url:
            score -= 15
            reasons.append("Redirect detected")

        links = driver.find_elements("tag name", "a")

        forms = driver.find_elements("tag name", "form")

        iframes = driver.find_elements("tag name", "iframe")

        login_score, login_reasons = detect_login_risk(driver)

        score += login_score

        reasons.extend(login_reasons)

        if len(iframes) > 2:
            score -= 10
            reasons.append("Too many iframes")

    except:
        score -= 40
        reasons.append("Website unreachable")

    finally:
        if driver:
            driver.quit()

    return score, reasons, links, forms, iframes

# -----------------------------
# 🤖 AI SUMMARY
# -----------------------------
# -----------------------------
# 🤖 AI SUMMARY
# -----------------------------
def generate_ai_summary(url, score, status, reasons):

    if not gemini_model:

        return """
WHY:
• AI service unavailable

RISKS:
• Unable to analyze risks

ADVICE:
• Try again later
"""

    prompt = f"""
Analyze this URL for phishing risk.

URL: {url}

Threat Score: {score}/100

Status: {status}

Detected Issues:
{', '.join(reasons)}

Return STRICTLY in this format:

WHY:
• short explanation

RISKS:
• risk 1
• risk 2

ADVICE:
• advice 1
• advice 2
"""

    try:

        response = gemini_model.generate_content(prompt)

        ai_text = response.text.strip()

        ai_text = ai_text.replace("**", "")
        ai_text = ai_text.replace("* ", "• ")
        ai_text = ai_text.replace("- ", "• ")

        return ai_text

    except Exception as e:

        error_msg = str(e)

        print("AI ERROR:", error_msg)

        return f"""
WHY:
• AI generation failed

RISKS:
• {error_msg}

ADVICE:
• Check Gemini API configuration
"""

# -----------------------------
# 🏠 HOME
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")

# -----------------------------
# 🚀 ANALYZE
# -----------------------------
# -----------------------------
# 🚀 ANALYZE
# -----------------------------
@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({"error": "URL missing"}), 400

        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "Empty URL"}), 400

        if "://" not in url:
            url = "https://" + url

        # -----------------------------
        # 🔍 BASIC CHECK
        # -----------------------------
        score1, reasons1 = basic_url_check(url)

        # -----------------------------
        # 🌐 SELENIUM CHECK
        # -----------------------------
        score2, reasons2, links, forms, iframes = analyze_with_selenium(url)

        reasons = list(set(reasons1 + reasons2))

        # -----------------------------
        # 🤖 ML FEATURES
        # -----------------------------
        feature_values = extract_features(
            url,
            len(links),
            len(forms),
            len(iframes)
        )

        features = pd.DataFrame(
            [feature_values],
            columns=FEATURE_COLUMNS
        )

        # -----------------------------
        # 🤖 ML PREDICTION
        # -----------------------------
        prediction = model.predict(features)[0]

        probability = model.predict_proba(features)[0][1]

        # 1 = phishing
        danger_score = int(probability * 100)

        safe_score = 100 - danger_score

        ml_status = (
            "Dangerous"
            if danger_score >= 60
            else "Safe"
        )

        # -----------------------------
        # 🎯 BASE SCORE
        # -----------------------------
        final_score = min(score1, score2)

        # -----------------------------
        # 🚨 BLACKLIST CHECK
        # -----------------------------
        bl_score, bl_reason = check_blacklist(url)

        final_score += bl_score

        if bl_reason:
            reasons.append(bl_reason)

        # -----------------------------
        # 🌍 DOMAIN AGE
        # -----------------------------
        age_score, age_reason = get_domain_age_score(url)

        final_score += age_score

        if age_reason:
            reasons.append(age_reason)

        # -----------------------------
        # 🔐 LOGIN RISK
        # -----------------------------
        if "Login form on non-HTTPS" in reasons:
            final_score = min(final_score, 35)

        # -----------------------------
        # 🔁 REDIRECT
        # -----------------------------
        if "Redirect detected" in reasons:
            final_score -= 10

        # -----------------------------
        # 🤖 ML INFLUENCE
        # -----------------------------
        if danger_score >= 85:
            final_score = min(final_score, 25)

        elif danger_score >= 70:
            final_score = min(final_score, 40)

        elif danger_score >= 60:
            final_score = min(final_score, 55)

        # -----------------------------
        # 🧠 TRUSTED DOMAIN OVERRIDE
        # -----------------------------
        if is_trusted(url):

            final_score = max(final_score, 85)

            reasons = [
                r for r in reasons
                if r != "Contains sensitive keywords"
            ]

            ml_status = "Safe"

            safe_score = max(safe_score, 85)

            danger_score = min(danger_score, 15)

        # -----------------------------
        # 🎯 FINAL SCORE LIMIT
        # -----------------------------
        final_score = max(
            0,
            min(int(final_score), 100)
        )

        # -----------------------------
        # 🚦 FINAL STATUS
        # -----------------------------
        if danger_score >= 70:
            status = "Dangerous"

        elif danger_score >= 45:
            status = "Suspicious"

        else:
            status = "Safe"

        # -----------------------------
        # 🤖 AI SUMMARY
        # -----------------------------
        ai_summary = generate_ai_summary(
            url,
            final_score,
            status,
            reasons
        )

        # -----------------------------
        # ✅ RESPONSE
        # -----------------------------
        return jsonify({

            "url": url,

            "status": status,

            "score": safe_score,

            "safe_score": safe_score,

            "danger_score": danger_score,

            "ml_prediction": ml_status,

            "prediction_label": int(prediction),

            "reasons": reasons,

            "ai_summary": ai_summary
        })

    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "error": "Internal server error"
        }), 500

# -----------------------------
# 🚀 RUN
# -----------------------------
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )