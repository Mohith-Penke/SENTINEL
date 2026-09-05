import os
import re
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

PORT = int(os.environ.get("PORT", 5000))


# =========================================================
# HELPERS
# =========================================================

def risk_level(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def risk_summary(level):
    return {
        "LOW": "This looks relatively safe, but always verify before sharing sensitive information.",
        "MEDIUM": "Some suspicious indicators were detected. Verify the source before continuing.",
        "HIGH": "Multiple warning signs were detected. Avoid entering passwords, OTPs or payment details.",
        "CRITICAL": "This appears highly suspicious. Do not interact with the link or provide any personal information."
    }[level]


def actions(level):
    return {
        "LOW": [
            "Verify the website or sender independently.",
            "Do not share unnecessary personal information."
        ],
        "MEDIUM": [
            "Check the domain carefully.",
            "Do not enter passwords or payment information.",
            "Verify the message through an official channel."
        ],
        "HIGH": [
            "Do not open suspicious links.",
            "Do not share OTP, PIN or passwords.",
            "Report and block the suspicious sender."
        ],
        "CRITICAL": [
            "Stop interacting with the source immediately.",
            "Do not provide credentials, OTPs or payment details.",
            "Report the incident to the appropriate authority."
        ]
    }[level]


def make_result(score, reasons):
    score = max(0, min(100, int(score)))
    level = risk_level(score)

    return {
        "score": score,
        "level": level,
        "summary": risk_summary(level),
        "reasons": reasons,
        "actions": actions(level)
    }


# =========================================================
# WEBSITE SCANNER
# =========================================================

def scan_url(url):
    url = url.strip()

    if not url:
        return make_result(100, ["No website URL was provided."])

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 20
        reasons.append("The website does not use HTTPS.")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 30
        reasons.append("The URL uses an IP address instead of a normal domain.")

    if len(url) > 100:
        score += 15
        reasons.append("The URL is unusually long.")

    if "@" in url:
        score += 20
        reasons.append("The URL contains an @ symbol, which can be used for deception.")

    if "xn--" in host.lower():
        score += 25
        reasons.append("The domain contains punycode characters.")

    if host.count(".") >= 3:
        score += 10
        reasons.append("The domain contains many subdomains.")

    suspicious_words = [
        "verify", "login", "secure", "account", "update",
        "confirm", "password", "wallet", "bonus", "free",
        "claim", "urgent", "gift", "prize", "bank"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        score += min(25, len(found_words) * 5)
        reasons.append(
            "Suspicious keywords detected: " +
            ", ".join(found_words[:5])
        )

    brand_words = [
        "paypal", "google", "microsoft", "apple",
        "amazon", "instagram", "facebook",
        "sbi", "hdfc", "icici"
    ]

    if any(word in host.lower() for word in brand_words):
        if not host.lower().endswith(
            tuple("." + b + ".com" for b in brand_words)
        ):
            score += 20
            reasons.append(
                "The domain may be attempting brand impersonation."
            )

    if "-" in host:
        score += 5
        reasons.append("The domain contains hyphens.")

    if parsed.port:
        score += 15
        reasons.append("The URL uses a non-standard port.")

    if not reasons:
        reasons.append("No major suspicious URL indicators were detected.")

    return make_result(score, reasons)


# =========================================================
# MESSAGE SCANNER
# =========================================================

def scan_message(message):
    text = message.lower()
    score = 0
    reasons = []

    checks = [
        (
            ["urgent", "immediately", "act now", "within 24 hours"],
            15,
            "The message uses urgency or pressure tactics."
        ),
        (
            ["otp", "one time password", "verification code"],
            25,
            "The message asks for or references an OTP/verification code."
        ),
        (
            ["kyc", "verify your account", "account verification"],
            20,
            "The message contains account/KYC verification language."
        ),
        (
            ["password", "login", "username", "credentials"],
            20,
            "The message involves sensitive login information."
        ),
        (
            ["payment", "upi", "bank", "card", "refund"],
            20,
            "The message involves financial information or payment."
        ),
        (
            ["winner", "prize", "lottery", "free gift", "cash prize"],
            25,
            "The message contains prize/reward scam indicators."
        ),
        (
            ["job offer", "work from home", "registration fee"],
            15,
            "The message may contain job-scam indicators."
        ),
        (
            ["click here", "bit.ly", "tinyurl", "shorturl"],
            20,
            "The message contains a suspicious or shortened link."
        ),
        (
            ["police", "arrest", "legal action", "blocked"],
            20,
            "The message uses threats or intimidation."
        )
    ]

    for words, points, reason in checks:
        if any(word in text for word in words):
            score += points
            reasons.append(reason)

    links = re.findall(r"https?://\S+|www\.\S+", message)

    if links:
        score += 10
        reasons.append("A web link was detected in the message.")

    if not reasons:
        reasons.append("No major scam indicators were detected.")

    return make_result(score, reasons)


# =========================================================
# SCREENSHOT
# =========================================================

def scan_screenshot(filename):
    name = (filename or "").lower()

    score = 15
    reasons = [
        "Screenshot metadata analysis completed."
    ]

    suspicious_names = [
        "fake", "scam", "phishing", "urgent",
        "verify", "payment", "otp"
    ]

    found = [x for x in suspicious_names if x in name]

    if found:
        score += 35
        reasons.append(
            "The filename contains suspicious keywords: " +
            ", ".join(found)
        )

    return make_result(score, reasons)


# =========================================================
# AI COPILOT
# =========================================================

def local_ai(message):
    text = message.lower()

    if "phishing" in text:
        return (
            "Phishing is a scam where attackers impersonate a trusted "
            "person or organization to steal credentials, OTPs, money or data."
        )

    if "otp" in text:
        return (
            "Never share an OTP with anyone. Banks and legitimate services "
            "normally do not need you to tell another person your OTP."
        )

    if "password" in text:
        return (
            "Never share your password. Use unique passwords and enable "
            "multi-factor authentication whenever possible."
        )

    if "link" in text or "url" in text or "website" in text:
        return (
            "Check the exact domain name, HTTPS status, spelling, "
            "subdomains and suspicious words before trusting a website."
        )

    if "scam" in text or "fraud" in text:
        return (
            "If you suspect a scam, stop interacting with the sender, "
            "avoid payments, preserve evidence and report the incident."
        )

    return (
        "I am SENTINEL Cyber AI. I can help you understand phishing, "
        "fake websites, scam messages, suspicious links, OTP safety "
        "and cybersecurity awareness."
    )


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "SENTINEL"
    })


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    return jsonify(scan_url(url))


@app.route("/scan-message", methods=["POST"])
def scan_message_route():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    return jsonify(scan_message(message))


@app.route("/scan-profile", methods=["POST"])
def scan_profile():
    data = request.get_json(silent=True) or {}

    text = str(data.get("profile", ""))

    score = 10
    reasons = []

    if not text:
        score = 20
        reasons.append("No profile information was provided.")
    else:
        if len(text) < 20:
            score += 15
            reasons.append("Very little profile information was provided.")

        if any(x in text.lower() for x in ["crypto", "investment", "double money"]):
            score += 30
            reasons.append("Potential investment scam language detected.")

        if any(x in text.lower() for x in ["whatsapp", "telegram", "dm me"]):
            score += 10
            reasons.append("The profile attempts to move communication off-platform.")

    return jsonify(make_result(score, reasons))


@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    file = request.files.get("screenshot")

    if not file:
        return jsonify({
            "error": "No screenshot uploaded."
        }), 400

    return jsonify(scan_screenshot(file.filename))


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({
            "response": "Please enter a question."
        })

    return jsonify({
        "response": local_ai(message)
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found."
    }), 404


@app.errorhandler(413)
def too_large(error):
    return jsonify({
        "error": "Uploaded file is too large."
    }), 413


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "error": "Internal server error."
    }), 500


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
