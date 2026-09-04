from flask import Flask, render_template, request, jsonify
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)


# =========================================================
# HELPERS
# =========================================================

def clamp(value, minimum=0, maximum=100):
    return max(minimum, min(maximum, int(value)))


def risk_level(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Safe"


def normalize_url(url):
    url = (url or "").strip()

    if not url:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


def unique(items):
    result = []

    for item in items:
        if item and item not in result:
            result.append(item)

    return result


# =========================================================
# WEBSITE ANALYZER
# =========================================================

def analyze_website(url):
    original = (url or "").strip()
    normalized = normalize_url(original)

    if not normalized:
        return {
            "score": 0,
            "level": "Unknown",
            "summary": "Please enter a website URL.",
            "reasons": ["No URL was provided."],
            "actions": "Enter a complete website address and scan it again."
        }

    score = 0
    reasons = []

    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        full = normalized.lower()
    except Exception:
        return {
            "score": 90,
            "level": "Critical",
            "summary": "The URL structure could not be parsed normally.",
            "reasons": ["Malformed or unusual URL structure."],
            "actions": "Do not open the link. Verify the website through an official source."
        }

    # HTTPS
    if parsed.scheme != "https":
        score += 12
        reasons.append("The website is not using HTTPS.")

    # IP address
    if hostname and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        score += 28
        reasons.append("The hostname uses a raw IP address instead of a normal domain.")

    # Long URL
    if len(normalized) > 100:
        score += 10
        reasons.append("The URL is unusually long.")

    if len(normalized) > 180:
        score += 8
        reasons.append("The URL contains an extremely long address.")

    # Too many subdomains
    parts = hostname.split(".") if hostname else []

    if len(parts) >= 4:
        score += 12
        reasons.append("The domain contains many subdomain levels.")

    # Punycode
    if "xn--" in hostname:
        score += 25
        reasons.append("The domain contains punycode, which can be used in look-alike domains.")

    # @ symbol
    if "@" in normalized:
        score += 25
        reasons.append("The URL contains an @ symbol, which can hide the real destination.")

    # Hyphens
    hyphens = hostname.count("-")

    if hyphens >= 3:
        score += 10
        reasons.append("The domain contains several hyphens.")

    # Encoded characters
    if "%" in normalized:
        score += 8
        reasons.append("The URL contains encoded characters.")

    # Repeated slashes
    if "://" in normalized:
        after_scheme = normalized.split("://", 1)[1]

        if "//" in after_scheme:
            score += 8
            reasons.append("The URL contains repeated path separators.")

    # Unusual port
    if parsed.port is not None and parsed.port not in (80, 443):
        score += 15
        reasons.append("The website uses an unusual network port.")

    # Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "confirm",
        "password",
        "wallet",
        "bank",
        "banking",
        "kyc",
        "otp",
        "reward",
        "prize",
        "bonus",
        "refund",
        "claim",
        "urgent",
        "suspended",
        "unlock",
        "support",
        "customer-care",
        "customer-care",
        "payment"
    ]

    found_words = [word for word in suspicious_words if word in full]

    if len(found_words) >= 2:
        score += min(20, len(found_words) * 4)
        reasons.append(
            "The URL contains multiple sensitive or urgency-related terms: "
            + ", ".join(found_words[:6])
        )

    # Brand impersonation indicators
    brand_words = [
        "google",
        "microsoft",
        "apple",
        "amazon",
        "instagram",
        "facebook",
        "whatsapp",
        "paypal",
        "netflix",
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "phonepe",
        "paytm",
        "flipkart",
        "adobe"
    ]

    if any(brand in hostname for brand in brand_words):
        # Only an indicator; do not claim the domain is fake.
        score += 12
        reasons.append("The domain contains a recognizable brand name; verify the official domain carefully.")

    # Query length
    if len(query) > 120:
        score += 8
        reasons.append("The URL contains a large query string.")

    score = clamp(score)

    if not reasons:
        reasons.append("No major suspicious URL indicators were detected.")

    level = risk_level(score)

    if level == "Safe":
        summary = "No major suspicious indicators were detected in this URL."
        actions = "Still verify the website address before entering sensitive information."
    elif level == "Low":
        summary = "A few unusual indicators were detected. Use caution."
        actions = "Verify the domain independently before logging in or making payments."
    elif level == "Medium":
        summary = "Several suspicious indicators were detected."
        actions = "Avoid entering passwords, OTPs or payment information until the website is verified."
    elif level == "High":
        summary = "This URL shows multiple high-risk characteristics."
        actions = "Do not enter credentials or payment information. Verify the website using an official source."
    else:
        summary = "This URL contains strong indicators associated with potentially dangerous links."
        actions = "Do not open or interact with the link. Use the organization's official website or app instead."

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "reasons": unique(reasons),
        "actions": actions,
        "url": original
    }


# =========================================================
# MESSAGE ANALYZER
# =========================================================

def analyze_message(message):
    text = (message or "").strip()
    lower = text.lower()

    if not text:
        return {
            "score": 0,
            "level": "Unknown",
            "summary": "Please paste a message to analyze.",
            "reasons": ["No message was provided."],
            "actions": "Paste the suspicious SMS, email, WhatsApp message or DM."
        }

    score = 0
    reasons = []

    # Urgency
    urgency_terms = [
        "urgent",
        "immediately",
        "act now",
        "last chance",
        "within 24 hours",
        "today",
        "expire",
        "expired",
        "account will be blocked",
        "account blocked",
        "suspended",
        "verify now"
    ]

    urgency_hits = [x for x in urgency_terms if x in lower]

    if urgency_hits:
        score += min(18, len(urgency_hits) * 5)
        reasons.append("Uses urgency or fear-based language.")

    # OTP
    if re.search(r"\botp\b|\bone[- ]time password\b", lower):
        score += 22
        reasons.append("Requests or discusses an OTP.")

    # KYC
    if "kyc" in lower:
        score += 18
        reasons.append("Mentions KYC verification, a common phishing theme.")

    # Payment / UPI
    payment_terms = [
        "upi",
        "upi pin",
        "pin",
        "payment",
        "pay now",
        "send money",
        "transfer",
        "refund fee",
        "processing fee",
        "deposit",
        "bank account",
        "card number",
        "cvv"
    ]

    payment_hits = [x for x in payment_terms if x in lower]

    if payment_hits:
        score += min(24, len(payment_hits) * 5)
        reasons.append("Contains payment or financial-information signals.")

    # Links
    urls = re.findall(r"(https?://\S+|www\.\S+)", text, flags=re.I)

    if urls:
        score += 15
        reasons.append("Contains a clickable web link.")

    # Suspicious shortened links
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co/",
        "goo.gl",
        "cutt.ly",
        "is.gd",
        "rb.gy"
    ]

    if any(shortener in lower for shortener in shorteners):
        score += 15
        reasons.append("Contains a shortened link that hides the final destination.")

    # Prize / lottery
    prize_terms = [
        "lottery",
        "winner",
        "won",
        "prize",
        "reward",
        "cash prize",
        "congratulations",
        "lucky draw"
    ]

    if any(term in lower for term in prize_terms):
        score += 18
        reasons.append("Uses prize, lottery or reward bait.")

    # Job scam
    job_terms = [
        "work from home",
        "part time job",
        "part-time job",
        "job offer",
        "easy money",
        "earn daily",
        "registration fee",
        "joining fee",
        "investment required"
    ]

    if any(term in lower for term in job_terms):
        score += 16
        reasons.append("Contains patterns commonly seen in fake job or earning scams.")

    # Impersonation
    impersonation_terms = [
        "bank manager",
        "customer care",
        "customer support",
        "police",
        "income tax",
        "income tax department",
        "courier",
        "customs",
        "rbi",
        "government",
        "official team",
        "support team"
    ]

    if any(term in lower for term in impersonation_terms):
        score += 14
        reasons.append("May be impersonating an organization or authority.")

    # Secret / credential requests
    credential_terms = [
        "password",
        "username",
        "login details",
        "card details",
        "cvv",
        "atm pin",
        "upi pin",
        "security code"
    ]

    if any(term in lower for term in credential_terms):
        score += 22
        reasons.append("Requests sensitive credentials or financial information.")

    # Threats
    threat_terms = [
        "police case",
        "legal action",
        "arrest",
        "fine",
        "penalty",
        "case will be filed",
        "account closure"
    ]

    if any(term in lower for term in threat_terms):
        score += 18
        reasons.append("Uses threats or consequences to pressure the recipient.")

    # Too many exclamation marks
    if text.count("!") >= 4:
        score += 5
        reasons.append("Uses unusually strong punctuation and emotional pressure.")

    score = clamp(score)

    if not reasons:
        reasons.append("No major scam indicators were detected in the text.")

    level = risk_level(score)

    if level == "Safe":
        summary = "No major scam indicators were detected in this message."
        actions = "Still avoid sharing sensitive information unless the sender is independently verified."
    elif level == "Low":
        summary = "The message contains a few signals worth checking."
        actions = "Verify the sender through an independent channel before taking action."
    elif level == "Medium":
        summary = "Several potential scam indicators were detected."
        actions = "Do not click unknown links or share OTPs, passwords or payment information."
    elif level == "High":
        summary = "This message contains multiple strong fraud indicators."
        actions = "Do not respond or send money. Verify the claim using an official website or phone number."
    else:
        summary = "The message contains strong indicators associated with common digital fraud."
        actions = "Do not click links, share OTPs or send money. Block/report the sender and verify independently."

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "reasons": unique(reasons),
        "actions": actions
    }


# =========================================================
# SOCIAL PROFILE ANALYZER
# =========================================================

def analyze_profile(data):
    platform = str(data.get("platform", "Social Media"))
    username = str(data.get("username", "")).strip()
    name = str(data.get("name", "")).strip()
    bio = str(data.get("bio", "")).strip()
    profile_url = str(data.get("url", "")).strip()

    try:
        followers = int(data.get("followers", 0) or 0)
    except Exception:
        followers = 0

    try:
        following = int(data.get("following", 0) or 0)
    except Exception:
        following = 0

    combined = f"{username} {name} {bio} {profile_url}".lower()

    score = 0
    reasons = []

    suspicious_terms = [
        "dm for money",
        "send money",
        "investment",
        "double your money",
        "guaranteed profit",
        "crypto",
        "giveaway",
        "winner",
        "free money",
        "loan",
        "urgent",
        "whatsapp me",
        "telegram",
        "contact me",
        "recovery service",
        "account recovery",
        "official support",
        "customer care",
        "airdrop",
        "cash prize"
    ]

    hits = [term for term in suspicious_terms if term in combined]

    if hits:
        score += min(35, len(hits) * 8)
        reasons.append(
            "Bio/profile contains potentially risky terms: "
            + ", ".join(hits[:6])
        )

    # External contact / money language
    if any(x in combined for x in ["upi", "phonepe", "paytm", "bank account", "payment"]):
        score += 20
        reasons.append("Profile contains payment or financial-contact signals.")

    # Very high following compared with followers
    if followers > 0 and following >= followers * 5:
        score += 8
        reasons.append("Following count is much higher than follower count.")

    # Very low followers
    if followers and followers < 20:
        score += 5
        reasons.append("Very low follower count; this is only an indicator, not proof of fraud.")

    # Suspicious username patterns
    if username:
        if re.search(r"\d{5,}", username):
            score += 5
            reasons.append("Username contains an unusually long numeric sequence.")

        if username.count("_") >= 3:
            score += 4
            reasons.append("Username contains several separators.")

    # Profile URL
    if profile_url:
        parsed = urlparse(normalize_url(profile_url))
        host = (parsed.hostname or "").lower()

        expected = {
            "instagram": "instagram.com",
            "facebook": "facebook.com",
            "x": "x.com"
        }

        expected_host = expected.get(platform.lower())

        if expected_host and expected_host not in host:
            score += 18
            reasons.append("Profile URL does not appear to use the expected platform domain.")

    score = clamp(score)

    if not reasons:
        reasons.append("No major suspicious profile indicators were detected.")

    level = risk_level(score)

    if level == "Safe":
        summary = "No major suspicious indicators were found from the supplied profile information."
    elif level == "Low":
        summary = "A few indicators deserve caution, but they do not prove the profile is fraudulent."
    elif level == "Medium":
        summary = "Several indicators suggest that the profile should be verified carefully."
    elif level == "High":
        summary = "Multiple suspicious indicators were detected. Treat the profile with caution."
    else:
        summary = "Strong suspicious indicators were detected. Avoid financial or credential-related interactions."

    actions = (
        "Verify the account through the platform and independent official channels. "
        "Do not send money, OTPs, passwords or banking information based only on a social profile."
    )

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "reasons": unique(reasons),
        "actions": actions
    }


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

    result = analyze_website(url)

    return jsonify(result)


@app.route("/scan-message", methods=["POST"])
def scan_message():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    result = analyze_message(message)

    return jsonify(result)


@app.route("/scan-profile", methods=["POST"])
def scan_profile():
    data = request.get_json(silent=True) or {}

    result = analyze_profile(data)

    return jsonify(result)


# =========================================================
# SENTINEL AI CHAT
# =========================================================

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}

    message = str(data.get("message", "")).strip()
    lower = message.lower()

    if not message:
        return jsonify({
            "reply": "Ask me anything about phishing, scams, UPI fraud, OTP safety, fake websites or account security."
        })

    # Phishing
    if any(x in lower for x in ["phishing", "phishing attack"]):
        reply = (
            "Phishing is a scam where someone tries to trick you into "
            "opening a malicious link or sharing sensitive information. "
            "Check the domain carefully, avoid urgent login links, and "
            "verify the sender independently."
        )

    # OTP
    elif "otp" in lower:
        reply = (
            "Never share an OTP with another person. Banks and legitimate "
            "services should not ask you to disclose your OTP over calls, "
            "messages or social media."
        )

    # UPI
    elif "upi" in lower:
        reply = (
            "For UPI safety: never share your UPI PIN, never approve a "
            "collect request just because someone asks, and remember that "
            "you generally do not enter your UPI PIN simply to receive money."
        )

    # Fake website
    elif any(x in lower for x in ["fake website", "fake site", "suspicious website"]):
        reply = (
            "Check the exact domain, HTTPS, spelling, unusual subdomains, "
            "unexpected login pages and requests for OTP/payment details. "
            "When in doubt, manually type the organization's official "
            "website instead of using a message link."
        )

    # Password
    elif any(x in lower for x in ["password", "strong password"]):
        reply = (
            "Use a unique long password for every important account. "
            "A password manager can help, and enabling 2FA adds another "
            "layer of protection."
        )

    # 2FA
    elif any(x in lower for x in ["2fa", "two factor", "two-factor", "mfa"]):
        reply = (
            "2FA/MFA protects an account even if the password is compromised. "
            "Prefer an authenticator app or security key when available."
        )

    # Job scam
    elif any(x in lower for x in ["job scam", "fake job", "work from home"]):
        reply = (
            "Be careful with jobs promising unusually high income for little "
            "work, especially when they demand registration, training or "
            "security deposits. Verify the employer independently."
        )

    # Investment
    elif any(x in lower for x in ["investment scam", "crypto scam", "guaranteed profit"]):
        reply = (
            "Guaranteed returns are a major warning sign. Never send money "
            "to an investment opportunity solely because it arrived through "
            "social media or a messaging app."
        )

    # Account takeover
    elif any(x in lower for x in ["hacked", "account takeover", "account compromised"]):
        reply = (
            "If an account may be compromised, change its password from a "
            "trusted device, enable 2FA, review active sessions, remove "
            "unknown devices and contact the service through its official "
            "support channel."
        )

    # Malware
    elif any(x in lower for x in ["malware", "virus", "ransomware", "apk"]):
        reply = (
            "Avoid unknown APKs, cracked software and suspicious attachments. "
            "Keep your operating system and security software updated and "
            "download applications from trusted sources."
        )

    # Money sent
    elif any(x in lower for x in ["sent money", "transferred money", "paid scammer", "money scam"]):
        reply = (
            "If you sent money to a suspected scammer, contact your bank or "
            "payment provider immediately and report the transaction through "
            "the appropriate official fraud-reporting channel. Preserve "
            "screenshots, transaction IDs and messages."
        )

    # Suspicious link
    elif any(x in lower for x in ["suspicious link", "clicked link", "unknown link"]):
        reply = (
            "If you clicked a suspicious link, do not enter credentials or "
            "payment details. If you already entered a password, change it "
            "from the legitimate website and enable 2FA. Monitor the account "
            "for unusual activity."
        )

    # Social engineering
    elif any(x in lower for x in ["social engineering", "deepfake", "impersonation"]):
        reply = (
            "Social engineering manipulates emotions such as fear, urgency, "
            "trust or greed. Slow down, verify the person's identity through "
            "another channel and never rely on a profile, voice or message alone."
        )

    # General scam
    elif any(x in lower for x in ["scam", "fraud", "cheated", "cheat"]):
        reply = (
            "Common scam signals include urgency, secrecy, unexpected links, "
            "requests for OTPs or passwords, payment demands, fake rewards "
            "and impersonation. Stop, verify independently and avoid acting "
            "under pressure."
        )

    else:
        reply = (
            "I can help with phishing, fake websites, scam messages, UPI/OTP "
            "fraud, fake customer care, job scams, investment scams, malware, "
            "social engineering, account security, passwords and suspicious links. "
            "Tell me what happened and I'll explain the safest next steps."
        )

    return jsonify({"reply": reply})


# =========================================================
# SCREENSHOT ANALYZER
# =========================================================

@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():

    uploaded = request.files.get("screenshot")

    if not uploaded:
        return jsonify({
            "score": 0,
            "level": "Unknown",
            "summary": "No screenshot was uploaded.",
            "indicators": [
                "Please choose an image before starting analysis."
            ]
        }), 400

    filename = uploaded.filename or ""

    allowed = {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp"
    }

    extension = os.path.splitext(filename.lower())[1]

    if extension not in allowed:
        return jsonify({
            "score": 0,
            "level": "Unknown",
            "summary": "Unsupported image format.",
            "indicators": [
                "Use PNG, JPG, JPEG or WEBP images."
            ]
        }), 400

    # Limit upload size without storing it permanently.
    uploaded.seek(0, os.SEEK_END)
    size = uploaded.tell()
    uploaded.seek(0)

    if size > 5 * 1024 * 1024:
        return jsonify({
            "score": 0,
            "level": "Unknown",
            "summary": "The screenshot is larger than 5 MB.",
            "indicators": [
                "Please upload a smaller screenshot."
            ]
        }), 400

    return jsonify({
        "score": 0,
        "level": "Indicator Review",
        "summary": (
            "Screenshot received. SENTINEL uses this feature for "
            "indicator-based awareness; visual evidence alone cannot "
            "prove that an account is genuine or fraudulent."
        ),
        "indicators": [
            "Check username spelling and unusual characters.",
            "Verify whether the profile uses the platform's normal URL.",
            "Look for requests for money, OTPs, passwords or card details.",
            "Check for giveaway, investment or guaranteed-profit claims.",
            "Look for impersonation of brands, celebrities or support teams.",
            "Verify the account through an independent official channel."
        ]
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Route not found"
    }), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "error": "Internal server error"
    }), 500


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
