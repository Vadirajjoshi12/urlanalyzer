from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import pickle
import os
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

from google import genai
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

client = None

if GEMINI_KEY:
    client = genai.Client(api_key=GEMINI_KEY)

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
def generate_ai_summary(url, score, status, reasons):

    if not client:
        return """
Why:
• AI service unavailable

Risks:
• Unable to analyze risks

Advice:
• Try again later
"""

    prompt = f"""
You are a cybersecurity expert.

URL: {url}
Score: {score}
Status: {status}
Issues: {', '.join(reasons)}

STRICT FORMAT:

Why:
• Explain clearly

Risks:
• List risks

Advice:
• Give actions
"""

    try:

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        text = response.text.strip()

        text = text.replace("**", "")
        text = text.replace("* ", "• ")
        text = text.replace("- ", "• ")

        return text

    except:
        return """
Why:
• Suspicious URL behavior detected.

Risks:
• Credential theft
• Phishing
• Fake login pages

Advice:
• Avoid interacting with the site
• Verify domain manually
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

        if not data or "url" not in data:
            return jsonify({"error": "URL missing"}), 400

        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "Empty URL"}), 400

        if "://" not in url:
            url = "https://" + url

        # 🔍 BASIC
        score1, reasons1 = basic_url_check(url)

        # 🌐 SELENIUM
        score2, reasons2, links, forms, iframes = analyze_with_selenium(url)

        reasons = list(set(reasons1 + reasons2))

        # 🤖 ML
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

        ml_status = "Safe" if prediction == 1 else "Dangerous"

        # 🎯 BASE SCORE
        final_score = min(score1, score2)

        # 🚨 BLACKLIST
        bl_score, bl_reason = check_blacklist(url)

        final_score += bl_score

        if bl_reason:
            reasons.append(bl_reason)

        # 🌍 DOMAIN AGE
        age_score, age_reason = get_domain_age_score(url)

        final_score += age_score

        if age_reason:
            reasons.append(age_reason)

        # 🔐 LOGIN RISK
        if "Login form on non-HTTPS" in reasons:
            final_score = min(final_score, 35)

        # 🔁 REDIRECT
        if "Redirect detected" in reasons:
            final_score -= 10

        # 🧠 TRUSTED OVERRIDE
        if is_trusted(url):

            final_score = max(final_score, 80)

            reasons = [
                r for r in reasons
                if r != "Contains sensitive keywords"
            ]

        final_score = max(
            0,
            min(int(final_score), 100)
        )

        # 🎯 STATUS
        if final_score >= 80:
            status = "Safe"

        elif final_score >= 50:
            status = "Suspicious"

        else:
            status = "Dangerous"

        if ml_status == "Dangerous" and final_score < 60:
            status = "Dangerous"

        # 🤖 AI
        ai_summary = generate_ai_summary(
            url,
            final_score,
            status,
            reasons
        )

        return jsonify({
            "url": url,
            "score": final_score,
            "status": status,
            "ml_prediction": ml_status,
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