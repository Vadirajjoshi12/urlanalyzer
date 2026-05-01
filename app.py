from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import pickle
import os
import requests

from dotenv import load_dotenv
load_dotenv()

from google import genai

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from features import extract_features, FEATURE_COLUMNS

import whois
from datetime import datetime

app = Flask(__name__)
CORS(app)

# -----------------------------
# 🔑 LOAD MODEL
# -----------------------------
model = pickle.load(open("model.pkl", "rb"))

# -----------------------------
# 🤖 GEMINI SETUP
# -----------------------------
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

# -----------------------------
# 🌍 TRUSTED DOMAINS
# -----------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "facebook.com",
    "instagram.com",
    "amazon.com",
    "amazon.in",
    "microsoft.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "paypal.com",
    "openai.com",
    "wikipedia.org"
]

def is_trusted(url):
    domain = url.split("//")[-1].split("/")[0].lower()

    return any(
        trusted == domain or domain.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    )

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
                    return -60, "URL found in phishing blacklist"

        return 0, None

    except:
        return 0, None

# -----------------------------
# 🔍 BASIC URL CHECK
# -----------------------------
def basic_url_check(url):

    score = 100
    reasons = []

    lowered = url.lower()

    if not url.startswith("https"):
        score -= 20
        reasons.append("No HTTPS")

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "account",
        "secure",
        "signin",
        "update",
        "wallet",
        "confirm"
    ]

    if any(w in lowered for w in suspicious_words):
        score -= 15
        reasons.append("Contains sensitive keywords")

    if len(url) > 75:
        score -= 10
        reasons.append("URL too long")

    if url.count("/") > 5:
        score -= 10
        reasons.append("Too many URL segments")

    if "@" in url:
        score -= 25
        reasons.append("@ symbol detected")

    if "-" in lowered:
        score -= 8
        reasons.append("Hyphenated domain")

    return score, reasons

# -----------------------------
# 🌍 DOMAIN AGE
# -----------------------------
def get_domain_age_score(url):

    try:
        domain = url.split("//")[-1].split("/")[0]

        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0, "Domain age unknown"

        age_days = (datetime.now() - creation_date).days

        if age_days > 365:
            return 10, "Old trusted domain"

        elif age_days > 180:
            return 0, "Medium age domain"

        else:
            return -20, "Very new domain"

    except:
        return -5, "Domain age unknown"

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
        placeholder = (i.get_attribute("placeholder") or "").lower()

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
        reasons.append("Selenium skipped (production mode)")

    finally:

        if driver:
            driver.quit()

    return score, reasons, links, forms, iframes

# -----------------------------
# 🤖 AI SUMMARY
# -----------------------------
def generate_ai_summary(url, score, status, reasons):

    prompt = f"""
You are a cybersecurity expert.

Analyze this URL:

URL: {url}

Threat Score: {score}/100

Status: {status}

Detected Reasons:
{', '.join(reasons)}

Respond ONLY in this format:

WHY:
short explanation

RISKS:
- risk 1
- risk 2

ADVICE:
- advice 1
- advice 2
"""

    try:

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        return response.text.strip()

    except Exception as e:

        print("AI ERROR:", str(e))

        return f"""
WHY:
AI generation failed

RISKS:
• {str(e)}

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
@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        url = data.get("url").strip()

        if not url.startswith("http"):
            url = "https://" + url

        # -----------------------------
        # BASIC CHECK
        # -----------------------------
        score1, reasons1 = basic_url_check(url)

        # -----------------------------
        # SELENIUM
        # -----------------------------
        score2, reasons2, links, forms, iframes = analyze_with_selenium(url)

        reasons = list(set(reasons1 + reasons2))

        # -----------------------------
        # ML FEATURES
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

        prediction = model.predict(features)[0]

        probability = model.predict_proba(features)[0][1]

        danger_score = int(probability * 100)

        # -----------------------------
        # BLACKLIST
        # -----------------------------
        bl_score, bl_reason = check_blacklist(url)

        danger_score += abs(bl_score)

        if bl_reason:
            reasons.append(bl_reason)

        # -----------------------------
        # DOMAIN AGE
        # -----------------------------
        age_score, age_reason = get_domain_age_score(url)

        if age_score < 0:
            danger_score += abs(age_score)

        else:
            danger_score -= age_score

        if age_reason:
            reasons.append(age_reason)

        # -----------------------------
        # LOGIN FORM
        # -----------------------------
        if "Login form on non-HTTPS" in reasons:
            danger_score += 25

        # -----------------------------
        # REDIRECT
        # -----------------------------
        if "Redirect detected" in reasons:
            danger_score += 10

        # -----------------------------
        # TRUSTED DOMAIN FIX
        # -----------------------------
        if is_trusted(url):

            danger_score = min(danger_score, 15)

            reasons = [
                r for r in reasons
                if r != "Contains sensitive keywords"
            ]

        # -----------------------------
        # LIMIT SCORE
        # -----------------------------
        danger_score = max(0, min(danger_score, 100))

        # -----------------------------
        # FINAL STATUS
        # -----------------------------
        if danger_score >= 60:
            verdict = "Dangerous"

        elif danger_score >= 35:
            verdict = "Suspicious"

        else:
            verdict = "Safe"

        # -----------------------------
        # AI SUMMARY
        # -----------------------------
        ai_summary = generate_ai_summary(
            url,
            danger_score,
            verdict,
            reasons
        )

        return jsonify({

            "url": url,

            "score": danger_score,

            "danger_score": danger_score,

            "safe_score": 100 - danger_score,

            "status": verdict,

            "reasons": reasons,

            "ai_summary": ai_summary

        })

    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500

# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)