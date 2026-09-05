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

    host_lower = host.lower()

    for brand in brand_words:
        if brand in host_lower:
            legitimate_domains = [
                f"{brand}.com",
                f"www.{brand}.com"
            ]

            if host_lower not in legitimate_domains:
                score += 20
                reasons.append(
                    "The domain may be attempting brand impersonation."
                )
                break

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
# SENTINEL AI - KNOWLEDGE
# =========================================================

AI_INTENTS = {

    "greeting": [
        "hi", "hello", "hey", "hai", "hii",
        "good morning", "good afternoon", "good evening"
    ],

    "help": [
        "help", "what can you do", "what do you do",
        "features", "capabilities"
    ],

    "scanner": [
        "scanner", "scan website", "website scanner",
        "url scanner", "check website", "scan a link"
    ],

    "message_scanner": [
        "message scanner", "scan message",
        "check message", "sms scam", "message scam"
    ],

    "social": [
        "social analyzer", "social media analyzer",
        "instagram analyzer", "facebook analyzer",
        "x analyzer", "twitter analyzer",
        "instagram", "facebook", "twitter"
    ],

    "game": [
        "cyber game", "game", "quiz",
        "play game", "cyber quiz"
    ],

    "awareness": [
        "awareness", "learn", "learning",
        "cyber awareness", "security tips"
    ],

    "dashboard": [
        "dashboard", "score", "stats",
        "statistics", "mistakes", "history"
    ],

    "ai": [
        "ai", "copilot", "cyber ai",
        "sentinel ai", "assistant"
    ],

    "phishing": [
        "phishing", "phish", "phishing attack"
    ],

    "otp": [
        "otp", "verification code",
        "one time password"
    ],

    "upi": [
        "upi", "upi scam", "upi fraud",
        "phonepe", "gpay", "google pay",
        "paytm"
    ],

    "kyc": [
        "kyc", "kyc scam", "account verification"
    ],

    "password": [
        "password", "passcode",
        "strong password", "password safety"
    ],

    "fake_website": [
        "fake website", "fake site",
        "fake link", "website fake",
        "is this website safe",
        "is this link safe"
    ],

    "scam": [
        "scam", "fraud", "fraudulent",
        "cheated", "cheating", "scammer"
    ],

    "malware": [
        "malware", "virus", "trojan",
        "ransomware", "spyware"
    ],

    "account_hacked": [
        "hacked", "account hacked",
        "instagram hacked", "facebook hacked",
        "account stolen"
    ],

    "urgent_incident": [
        "i clicked", "clicked the link",
        "i paid", "money sent",
        "shared otp", "gave otp",
        "shared password",
        "already paid", "already clicked"
    ]
}


# =========================================================
# AI HELPERS
# =========================================================

def clean_ai_text(text):
    text = re.sub(r"\s+", " ", text).strip()
    return text


def detect_intent(text):
    text_lower = text.lower()

    # Most dangerous / specific intents first
    priority = [
        "urgent_incident",
        "fake_website",
        "account_hacked",
        "upi",
        "otp",
        "kyc",
        "phishing",
        "malware",
        "password",
        "message_scanner",
        "social",
        "scanner",
        "game",
        "awareness",
        "dashboard",
        "ai",
        "scam",
        "help",
        "greeting"
    ]

    for intent in priority:
        keywords = AI_INTENTS[intent]

        for keyword in keywords:
            if keyword in text_lower:
                return intent

    return "general"


def is_question_about_navigation(text):
    nav_words = [
        "where", "where is", "how to open",
        "how do i use", "how can i use",
        "ekkuv", "ekkada", "ela use",
        "ela open", "open cheyali"
    ]

    return any(word in text.lower() for word in nav_words)


# =========================================================
# SHARP SENTINEL AI
# =========================================================

def local_ai(message):
    text = clean_ai_text(message)
    lower = text.lower()

    intent = detect_intent(text)

    # -----------------------------------------------------
    # EMERGENCY INCIDENT
    # -----------------------------------------------------

    if intent == "urgent_incident":

        if "otp" in lower:
            return (
                "🚨 HIGH RISK — OTP was shared.\n\n"
                "1. Contact your bank/service immediately.\n"
                "2. Secure the affected account.\n"
                "3. Check for unauthorized transactions.\n"
                "4. Report the incident immediately if money was lost.\n\n"
                "Never share another OTP."
            )

        if "paid" in lower or "money" in lower:
            return (
                "🚨 ACT NOW\n\n"
                "If money was sent to a scammer:\n"
                "1. Contact your bank/UPI provider immediately.\n"
                "2. Report the transaction.\n"
                "3. Preserve screenshots and transaction details.\n"
                "4. In India, report financial cyber fraud through 1930.\n\n"
                "Do not send any more money."
            )

        if "password" in lower:
            return (
                "🚨 Secure the account immediately.\n\n"
                "Change the password from the official website/app, "
                "enable MFA, and sign out unknown sessions."
            )

        if "click" in lower:
            return (
                "⚠️ If you clicked a suspicious link:\n\n"
                "Do not enter any more information. "
                "Close the page, run a security check, "
                "and change credentials if you entered them."
            )

        return (
            "🚨 Treat this as a possible security incident.\n\n"
            "Stop interacting with the source, preserve evidence, "
            "secure affected accounts, and report any financial loss immediately."
        )

    # -----------------------------------------------------
    # GREETING
    # -----------------------------------------------------

    if intent == "greeting":
        return (
            "Hey! 👋 I'm SENTINEL Cyber AI.\n\n"
            "I can guide you through the entire SENTINEL platform, "
            "check cybersecurity situations, explain scan results, "
            "and help with phishing, scams, OTP, UPI, passwords and more.\n\n"
            "Ask me what you want to do."
        )

    # -----------------------------------------------------
    # HELP / CAPABILITIES
    # -----------------------------------------------------

    if intent == "help":
        return (
            "🛡️ SENTINEL AI can help with:\n\n"
            "• Website & URL scanning\n"
            "• Scam message detection\n"
            "• Instagram / Facebook / X analysis\n"
            "• Cyber Game\n"
            "• Cyber Awareness\n"
            "• Dashboard & scan results\n"
            "• Phishing, OTP, UPI and KYC scams\n"
            "• Password & account security\n\n"
            "You can also ask me how to use any SENTINEL feature."
        )

    # -----------------------------------------------------
    # WEBSITE SCANNER
    # -----------------------------------------------------

    if intent == "scanner":
        return (
            "🔎 Website Scanner\n\n"
            "Use it to check a suspicious URL for common warning signs.\n\n"
            "SENTINEL checks things like HTTPS, IP-based domains, "
            "suspicious keywords, unusual URL structure, "
            "punycode and possible brand impersonation.\n\n"
            "Paste the URL into the Website Scanner and review the risk level."
        )

    # -----------------------------------------------------
    # MESSAGE SCANNER
    # -----------------------------------------------------

    if intent == "message_scanner":
        return (
            "💬 Message Scanner\n\n"
            "Paste the suspicious SMS, WhatsApp message, email text "
            "or other message into the Message Scanner.\n\n"
            "SENTINEL looks for urgency, OTP requests, KYC language, "
            "payment requests, prize scams, threats and suspicious links."
        )

    # -----------------------------------------------------
    # SOCIAL MEDIA
    # -----------------------------------------------------

    if intent == "social":
        if "instagram" in lower:
            return (
                "📸 Instagram Analyzer\n\n"
                "Open **Social → Instagram**, select Instagram, "
                "upload the relevant screenshot and run the analyzer.\n\n"
                "Look for suspicious profiles, investment promises, "
                "off-platform contact requests and other scam indicators."
            )

        if "facebook" in lower:
            return (
                "📘 Facebook Analyzer\n\n"
                "Open **Social → Facebook**, select Facebook, "
                "upload the screenshot and analyze it for suspicious indicators."
            )

        if "twitter" in lower or " x " in f" {lower} ":
            return (
                "𝕏 X Analyzer\n\n"
                "Open **Social → X**, select X, "
                "upload the screenshot and run the analyzer."
            )

        return (
            "📱 Social Media Analyzer\n\n"
            "SENTINEL supports separate analysis flows for:\n"
            "• Instagram\n"
            "• Facebook\n"
            "• X\n\n"
            "Select the platform, upload the screenshot, and analyze it."
        )

    # -----------------------------------------------------
    # CYBER GAME
    # -----------------------------------------------------

    if intent == "game":
        return (
            "🎮 Cyber Game\n\n"
            "Go to **Cyber Game** from the navigation menu.\n\n"
            "Answer the cybersecurity questions, build your score, "
            "and review your mistakes to improve your awareness."
        )

    # -----------------------------------------------------
    # AWARENESS
    # -----------------------------------------------------

    if intent == "awareness":
        return (
            "📚 Cyber Awareness\n\n"
            "Use the Awareness section to learn practical cybersecurity "
            "concepts such as phishing, passwords, scams, privacy and "
            "safe online behavior.\n\n"
            "If you give me a specific topic, I'll explain only what you need."
        )

    # -----------------------------------------------------
    # DASHBOARD
    # -----------------------------------------------------

    if intent == "dashboard":
        return (
            "📊 Dashboard\n\n"
            "The Dashboard is your SENTINEL activity overview.\n\n"
            "You can use it to understand your scan activity, "
            "cyber-game performance and mistakes."
        )

    # -----------------------------------------------------
    # AI ITSELF
    # -----------------------------------------------------

    if intent == "ai":
        return (
            "🤖 I'm SENTINEL Cyber AI.\n\n"
            "My job is to guide you through the SENTINEL platform "
            "and give focused cybersecurity help.\n\n"
            "Try asking:\n"
            "• Is this website safe?\n"
            "• How do I scan a message?\n"
            "• Where is Instagram Analyzer?\n"
            "• What should I do after an OTP scam?"
        )

    # -----------------------------------------------------
    # PHISHING
    # -----------------------------------------------------

    if intent == "phishing":
        return (
            "🎣 Phishing is a social-engineering attack where someone "
            "pretends to be a trusted person or organization.\n\n"
            "Common targets: passwords, OTPs, bank details and payments.\n\n"
            "Best defense: verify the sender and domain independently. "
            "Never trust urgency alone."
        )

    # -----------------------------------------------------
    # OTP
    # -----------------------------------------------------

    if intent == "otp":
        return (
            "🔐 Never share an OTP with another person.\n\n"
            "An OTP can authorize sensitive actions such as login, "
            "payments or account changes.\n\n"
            "If someone asks you to tell them your OTP, treat it as a major warning sign."
        )

    # -----------------------------------------------------
    # UPI
    # -----------------------------------------------------

    if intent == "upi":
        return (
            "💳 UPI Safety\n\n"
            "• Never share UPI PIN or OTP.\n"
            "• You do NOT need to enter your UPI PIN to receive money.\n"
            "• Reject unexpected collect/payment requests.\n"
            "• Verify the recipient before approving a payment.\n\n"
            "If money is lost to fraud in India, report it immediately through 1930."
        )

    # -----------------------------------------------------
    # KYC
    # -----------------------------------------------------

    if intent == "kyc":
        return (
            "⚠️ KYC scams often create urgency by claiming your bank/SIM/account "
            "will be blocked.\n\n"
            "Don't use the link they send. Open the official bank/service app "
            "or website yourself and verify the request."
        )

    # -----------------------------------------------------
    # PASSWORD
    # -----------------------------------------------------

    if intent == "password":
        return (
            "🔑 Password rule:\n\n"
            "Use a unique strong password for every important account "
            "and enable MFA wherever available.\n\n"
            "Never send your password to another person—even if they claim "
            "to be support staff."
        )

    # -----------------------------------------------------
    # FAKE WEBSITE
    # -----------------------------------------------------

    if intent == "fake_website":
        return (
            "🕵️ Don't judge a website only by its design or padlock.\n\n"
            "Check the exact domain, spelling, HTTPS, URL structure "
            "and whether the domain actually belongs to the claimed organization.\n\n"
            "For a suspicious URL, use SENTINEL's Website Scanner."
        )

    # -----------------------------------------------------
    # MALWARE
    # -----------------------------------------------------

    if intent == "malware":
        return (
            "🦠 Malware is malicious software designed to damage systems, "
            "steal information, spy on users or encrypt files.\n\n"
            "Avoid unknown downloads, cracked software and suspicious attachments. "
            "Keep your OS and security software updated."
        )

    # -----------------------------------------------------
    # ACCOUNT HACKED
    # -----------------------------------------------------

    if intent == "account_hacked":
        return (
            "🚨 If you think an account was hacked:\n\n"
            "1. Change the password using the official service.\n"
            "2. Enable MFA.\n"
            "3. Sign out unknown sessions/devices.\n"
            "4. Check recovery email/phone settings.\n"
            "5. Remove suspicious connected apps."
        )

    # -----------------------------------------------------
    # SCAM / FRAUD
    # -----------------------------------------------------

    if intent == "scam":
        return (
            "⚠️ Possible scam?\n\n"
            "Stop the interaction first.\n"
            "Don't click links, send money, share OTPs or provide passwords.\n\n"
            "If you have the message or URL, use SENTINEL's scanners to investigate it."
        )

    # -----------------------------------------------------
    # GENERAL CYBERSECURITY
    # -----------------------------------------------------

    cyber_words = [
        "cyber", "security", "safe", "hack",
        "online", "internet", "privacy",
        "data", "email", "bank"
    ]

    if any(word in lower for word in cyber_words):
        return (
            "🛡️ I can help with that from a cybersecurity perspective.\n\n"
            "Tell me the exact situation—website, message, account, payment, "
            "social media or security question—and I'll give you the shortest useful answer."
        )

    # -----------------------------------------------------
    # UNRELATED / UNKNOWN
    # -----------------------------------------------------

    return (
        "I'm focused on SENTINEL and cybersecurity.\n\n"
        "Ask me about the Website Scanner, Message Scanner, "
        "Social Analyzer, Cyber Game, Awareness, Dashboard, "
        "phishing, scams, OTP, UPI, passwords or account security."
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

        if any(
            x in text.lower()
            for x in ["crypto", "investment", "double money"]
        ):
            score += 30
            reasons.append(
                "Potential investment scam language detected."
            )

        if any(
            x in text.lower()
            for x in ["whatsapp", "telegram", "dm me"]
        ):
            score += 10
            reasons.append(
                "The profile attempts to move communication off-platform."
            )

    return jsonify(make_result(score, reasons))


@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    file = request.files.get("screenshot")

    if not file:
        return jsonify({
            "error": "No screenshot uploaded."
        }), 400

    return jsonify(scan_screenshot(file.filename))


# =========================================================
# AI CHAT
# =========================================================

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}

    message = str(
        data.get("message", "")
    ).strip()

    if not message:
        return jsonify({
            "response": "Tell me what you want help with."
        })

    response = local_ai(message)

    return jsonify({
        "response": response
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
