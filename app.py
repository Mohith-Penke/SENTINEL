import os
import re
import ipaddress
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)

PORT = int(os.environ.get("PORT", 5000))


# =========================================================
# RISK HELPERS
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
        "LOW": (
            "This looks relatively safe, but always verify "
            "before sharing sensitive information."
        ),
        "MEDIUM": (
            "Some suspicious indicators were detected. "
            "Verify the source before continuing."
        ),
        "HIGH": (
            "Multiple warning signs were detected. Avoid entering "
            "passwords, OTPs or payment details."
        ),
        "CRITICAL": (
            "This appears highly suspicious. Do not interact with "
            "the link or provide any personal information."
        )
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
# STRICT URL VALIDATION
# =========================================================

def is_valid_url_input(value):
    value = str(value or "").strip()

    if not value:
        return False, None, "Please enter a website URL."

    # Random text / spaces are not valid URLs.
    if any(character.isspace() for character in value):
        return False, None, (
            "Invalid URL. Please enter a valid website address."
        )

    candidate = value

    # Allow users to enter example.com without https://
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False, None, "Invalid URL. Please check the website address."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, None, (
            "Invalid URL. Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.netloc or not parsed.hostname:
        return False, None, (
            "Invalid URL. Please enter a complete website address."
        )

    host = parsed.hostname.lower().rstrip(".")

    # Localhost is not a public website.
    if host in {
        "localhost",
        "localhost.localdomain"
    }:
        return False, None, (
            "Invalid URL. Please enter a public website domain."
        )

    # Allow valid IPv4 addresses so the scanner can mark them risky.
    try:
        ipaddress.ip_address(host)

        if ":" in host:
            return False, None, (
                "Invalid URL. IPv6 website addresses are not supported."
            )

        return True, candidate, None

    except ValueError:
        pass

    # Normal public domains require a dot.
    if "." not in host:
        return False, None, (
            "Invalid URL. Enter a complete domain such as example.com."
        )

    if len(host) > 253:
        return False, None, "Invalid URL. The domain name is too long."

    labels = host.split(".")

    if any(not label or len(label) > 63 for label in labels):
        return False, None, "Invalid URL. The domain format is not valid."

    for label in labels:
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False, None, (
                "Invalid URL. The domain contains invalid characters."
            )

        if label.startswith("-") or label.endswith("-"):
            return False, None, (
                "Invalid URL. The domain format is not valid."
            )

    tld = labels[-1]

    if not re.fullmatch(r"[a-z]{2,63}", tld, re.IGNORECASE):
        return False, None, (
            "Invalid URL. Please enter a valid website domain."
        )

    return True, candidate, None


# =========================================================
# WEBSITE SCANNER
# =========================================================

def scan_url(url):
    valid, normalized_url, error = is_valid_url_input(url)

    if not valid:
        return {
            "invalid": True,
            "error": error,
            "message": error
        }

    url = normalized_url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    score = 0
    reasons = []

    # HTTPS
    if parsed.scheme.lower() != "https":
        score += 20
        reasons.append(
            "The website does not use HTTPS."
        )

    # IP address
    try:
        ipaddress.ip_address(host)

        score += 30
        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    except ValueError:
        pass

    # Very long URL
    if len(url) > 100:
        score += 15
        reasons.append(
            "The URL is unusually long."
        )

    # @ deception
    if "@" in url:
        score += 20
        reasons.append(
            "The URL contains an @ symbol, which can be used for deception."
        )

    # Punycode
    if "xn--" in host:
        score += 25
        reasons.append(
            "The domain contains punycode characters."
        )

    # Many subdomains
    if host.count(".") >= 3:
        score += 10
        reasons.append(
            "The domain contains many subdomains."
        )

    # Suspicious URL keywords
    suspicious_words = [
        "verify",
        "login",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "wallet",
        "bonus",
        "free",
        "claim",
        "urgent",
        "gift",
        "prize",
        "bank"
    ]

    found_words = []

    for word in suspicious_words:
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            url.lower()
        ):
            found_words.append(word)

    if found_words:
        score += min(25, len(found_words) * 5)

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words[:5])
        )

    # Brand impersonation
    brand_domains = {
        "paypal": {"paypal.com"},
        "google": {"google.com"},
        "microsoft": {"microsoft.com"},
        "apple": {"apple.com"},
        "amazon": {"amazon.com"},
        "instagram": {"instagram.com"},
        "facebook": {"facebook.com"},
        "sbi": {"sbi.co.in"},
        "hdfc": {"hdfcbank.com"},
        "icici": {"icicibank.com"}
    }

    for brand, official_domains in brand_domains.items():

        if brand not in host:
            continue

        official = any(
            host == domain
            or host.endswith("." + domain)
            for domain in official_domains
        )

        if not official:
            score += 20
            reasons.append(
                "The domain may be attempting brand impersonation."
            )
            break

    # Hyphenated domains
    if "-" in host:
        score += 5
        reasons.append(
            "The domain contains hyphens."
        )

    # Non-standard port
    if parsed.port:
        score += 15
        reasons.append(
            "The URL uses a non-standard port."
        )

    if not reasons:
        reasons.append(
            "No major suspicious URL indicators were detected."
        )

    return make_result(score, reasons)


# =========================================================
# MESSAGE SCANNER
# =========================================================

def scan_message(message):
    message = str(message or "")
    text = message.lower()

    score = 0
    reasons = []

    checks = [
        (
            [
                "urgent",
                "immediately",
                "act now",
                "within 24 hours"
            ],
            15,
            "The message uses urgency or pressure tactics."
        ),
        (
            [
                "otp",
                "one time password",
                "verification code"
            ],
            25,
            "The message asks for or references an OTP/verification code."
        ),
        (
            [
                "kyc",
                "verify your account",
                "account verification"
            ],
            20,
            "The message contains account/KYC verification language."
        ),
        (
            [
                "password",
                "username",
                "credentials"
            ],
            20,
            "The message involves sensitive login information."
        ),
        (
            [
                "payment",
                "upi",
                "bank",
                "card",
                "refund"
            ],
            20,
            "The message involves financial information or payment."
        ),
        (
            [
                "winner",
                "prize",
                "lottery",
                "free gift",
                "cash prize"
            ],
            25,
            "The message contains prize/reward scam indicators."
        ),
        (
            [
                "job offer",
                "work from home",
                "registration fee"
            ],
            15,
            "The message may contain job-scam indicators."
        ),
        (
            [
                "click here",
                "bit.ly",
                "tinyurl",
                "shorturl"
            ],
            20,
            "The message contains a suspicious or shortened link."
        ),
        (
            [
                "police",
                "arrest",
                "legal action",
                "blocked"
            ],
            20,
            "The message uses threats or intimidation."
        )
    ]

    for words, points, reason in checks:

        if any(
            re.search(
                rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
                text
            )
            for word in words
        ):
            score += points
            reasons.append(reason)

    links = re.findall(
        r"https?://\S+|www\.\S+",
        message
    )

    if links:
        score += 10
        reasons.append(
            "A web link was detected in the message."
        )

    if not reasons:
        reasons.append(
            "No major scam indicators were detected."
        )

    return make_result(score, reasons)


# =========================================================
# SCREENSHOT ANALYZER
# =========================================================

def scan_screenshot(filename):
    name = str(filename or "").lower()

    score = 15

    reasons = [
        "Screenshot metadata analysis completed."
    ]

    suspicious_names = [
        "fake",
        "scam",
        "phishing",
        "urgent",
        "verify",
        "payment",
        "otp"
    ]

    found = [
        word
        for word in suspicious_names
        if word in name
    ]

    if found:
        score += 35
        reasons.append(
            "The filename contains suspicious keywords: "
            + ", ".join(found)
        )

    return make_result(score, reasons)


# =========================================================
# AI COPILOT
# =========================================================

AI_INTENTS = {

    "urgent_incident": [
        "money stolen",
        "money lost",
        "money deducted",
        "sent money",
        "money sent",
        "already paid",
        "payment done",
        "shared otp",
        "gave otp",
        "shared password",
        "clicked the link",
        "already clicked"
    ],

    "account_hacked": [
        "account hacked",
        "hacked account",
        "account stolen",
        "instagram hacked",
        "facebook hacked",
        "email hacked"
    ],

    "fake_website": [
        "fake website",
        "fake site",
        "fake link",
        "website fake",
        "is this website safe",
        "is this link safe",
        "is this website fake"
    ],

    "phishing": [
        "phishing",
        "phishing attack",
        "phishing link",
        "fake email"
    ],

    "otp": [
        "otp",
        "one time password",
        "verification code"
    ],

    "upi": [
        "upi",
        "upi scam",
        "upi fraud",
        "phonepe",
        "gpay",
        "google pay",
        "paytm",
        "qr scam"
    ],

    "kyc": [
        "kyc",
        "kyc scam",
        "kyc update",
        "account verification"
    ],

    "password": [
        "password",
        "passcode",
        "strong password",
        "password safety"
    ],

    "malware": [
        "malware",
        "virus",
        "trojan",
        "spyware",
        "ransomware"
    ],

    "scanner": [
        "website scanner",
        "url scanner",
        "scan website",
        "scan url",
        "check website",
        "check url",
        "scan a link"
    ],

    "message_scanner": [
        "message scanner",
        "scan message",
        "check message",
        "sms scam",
        "message scam"
    ],

    "social": [
        "social analyzer",
        "social media analyzer",
        "instagram analyzer",
        "facebook analyzer",
        "x analyzer",
        "twitter analyzer",
        "instagram",
        "facebook",
        "twitter"
    ],

    "game": [
        "cyber game",
        "cyber quiz",
        "play game",
        "quiz",
        "game"
    ],

    "awareness": [
        "cyber awareness",
        "awareness",
        "security tips",
        "learn cybersecurity",
        "learn cyber security"
    ],

    "dashboard": [
        "dashboard",
        "statistics",
        "stats",
        "history",
        "my results"
    ],

    "ai": [
        "sentinel ai",
        "cyber ai",
        "copilot",
        "ai assistant"
    ],

    "scam": [
        "scam",
        "fraud",
        "fraudulent",
        "scammer",
        "cyber fraud"
    ],

    "help": [
        "help",
        "what can you do",
        "what do you do",
        "features",
        "capabilities"
    ],

    "greeting": [
        "hi",
        "hello",
        "hey",
        "hai",
        "hii",
        "hiii",
        "good morning",
        "good afternoon",
        "good evening"
    ]
}


def phrase_match(text, phrase):
    text = str(text or "").lower()
    phrase = str(phrase or "").lower()

    if not text or not phrase:
        return False

    pattern = (
        r"(?<![a-z0-9])"
        + re.escape(phrase)
        + r"(?![a-z0-9])"
    )

    return re.search(pattern, text) is not None


def detect_intent(message):
    text = str(message or "").lower().strip()

    if not text:
        return "help"

    scores = {}

    for intent, phrases in AI_INTENTS.items():

        score = 0

        for phrase in phrases:

            if phrase_match(text, phrase):
                # Longer phrases carry more meaning.
                score += max(1, len(phrase.split()))

        if score:
            scores[intent] = score

    if not scores:
        return "general"

    priority = [
        "urgent_incident",
        "account_hacked",
        "fake_website",
        "phishing",
        "upi",
        "otp",
        "kyc",
        "malware",
        "password",
        "message_scanner",
        "scanner",
        "social",
        "game",
        "awareness",
        "dashboard",
        "ai",
        "scam",
        "help",
        "greeting"
    ]

    highest_score = max(scores.values())

    for intent in priority:

        if (
            intent in scores
            and scores[intent] >= highest_score
        ):
            return intent

    return max(
        scores,
        key=scores.get
    )


def is_navigation_question(text):
    navigation_phrases = [
        "where is",
        "where can i find",
        "how to open",
        "how do i use",
        "how can i use",
        "open scanner",
        "open dashboard",
        "open game",
        "open awareness",
        "open ai",
        "go to scanner",
        "go to dashboard",
        "go to game",
        "ekkada",
        "ela use",
        "ela open",
        "open cheyali"
    ]

    return any(
        phrase_match(text, phrase)
        for phrase in navigation_phrases
    )


def local_ai(message):
    text = str(message or "").strip()
    lower = text.lower()

    if not text:
        return (
            "I'm SENTINEL AI 🛡️\n\n"
            "Ask me about website safety, phishing, "
            "scams, OTP, UPI, KYC, passwords, "
            "or how to use SENTINEL."
        )

    intent = detect_intent(text)

    # -----------------------------------------------------
    # EMERGENCY
    # -----------------------------------------------------

    if intent == "urgent_incident":

        if (
            "otp" in lower
            or "password" in lower
        ):
            return (
                "🚨 SECURITY ALERT\n\n"
                "Your credentials may be compromised.\n\n"
                "1. Secure the affected account immediately.\n"
                "2. Change the password using the official app/site.\n"
                "3. Sign out unknown sessions/devices.\n"
                "4. Enable two-factor authentication.\n"
                "5. Check for unauthorized activity.\n\n"
                "Never share another OTP or password."
            )

        if (
            "money" in lower
            or "paid" in lower
            or "payment" in lower
        ):
            return (
                "🚨 ACT NOW\n\n"
                "If money was sent to a scammer:\n\n"
                "1. Contact your bank/payment provider immediately.\n"
                "2. Report the fraudulent transaction.\n"
                "3. Preserve screenshots and transaction details.\n"
                "4. In India, financial cyber fraud can be reported "
                "through 1930.\n\n"
                "Do not send additional money to anyone claiming "
                "they can recover your money."
            )

        if "click" in lower:
            return (
                "⚠️ If you clicked a suspicious link:\n\n"
                "Do not enter any more information.\n"
                "Close the page.\n"
                "If you entered credentials, change them immediately "
                "from the official website/app.\n"
                "Also monitor the affected account for suspicious activity."
            )

        return (
            "🚨 Treat this as a possible cybersecurity incident.\n\n"
            "Stop interacting with the suspicious source, "
            "secure your accounts, preserve evidence, and "
            "report financial loss immediately."
        )

    # -----------------------------------------------------
    # GREETING
    # -----------------------------------------------------

    if intent == "greeting":
        return (
            "Hey! 👋 I'm SENTINEL Cyber AI.\n\n"
            "I can help you with:\n"
            "• Website safety\n"
            "• Phishing\n"
            "• Scam messages\n"
            "• OTP / UPI / KYC scams\n"
            "• Password security\n"
            "• Hacked accounts\n"
            "• SENTINEL features\n\n"
            "What do you want to check?"
        )

    # -----------------------------------------------------
    # HELP
    # -----------------------------------------------------

    if intent == "help":
        return (
            "🛡️ SENTINEL AI can help with:\n\n"
            "• Website & URL Scanner\n"
            "• Message Scanner\n"
            "• Social Analyzer\n"
            "• Cyber Game\n"
            "• Cyber Awareness\n"
            "• Dashboard\n"
            "• Phishing / scam guidance\n"
            "• OTP / UPI / KYC safety\n"
            "• Password & account security\n\n"
            "Ask me directly what you want to do."
        )

    # -----------------------------------------------------
    # WEBSITE SCANNER
    # -----------------------------------------------------

    if intent == "scanner":
        return (
            "🔎 Website Scanner\n\n"
            "Paste a complete website URL into the scanner.\n\n"
            "SENTINEL checks indicators including:\n"
            "• HTTPS usage\n"
            "• IP-based addresses\n"
            "• Suspicious keywords\n"
            "• Long URLs\n"
            "• Punycode\n"
            "• Multiple subdomains\n"
            "• Brand impersonation\n"
            "• Unusual ports\n\n"
            "Random text such as 'hi' or 'hello' is rejected "
            "as an invalid website URL."
        )

    # -----------------------------------------------------
    # MESSAGE SCANNER
    # -----------------------------------------------------

    if intent == "message_scanner":
        return (
            "💬 Message Scanner\n\n"
            "Paste the suspicious SMS, WhatsApp message, "
            "email or other text into the Message Scanner.\n\n"
            "SENTINEL checks for:\n"
            "• Urgency\n"
            "• OTP requests\n"
            "• KYC language\n"
            "• Payment requests\n"
            "• Prize scams\n"
            "• Job scams\n"
            "• Threats\n"
            "• Suspicious links"
        )

    # -----------------------------------------------------
    # SOCIAL
    # -----------------------------------------------------

    if intent == "social":

        if "instagram" in lower:
            return (
                "📸 Instagram Analyzer\n\n"
                "Open the Social Analyzer and select Instagram.\n"
                "Upload the relevant screenshot and run the analysis.\n\n"
                "Be careful with impersonation profiles, "
                "investment promises, money requests, "
                "and suspicious links."
            )

        if "facebook" in lower:
            return (
                "📘 Facebook Analyzer\n\n"
                "Open Social Analyzer → Facebook.\n"
                "Upload the screenshot and run the analysis."
            )

        if (
            "twitter" in lower
            or phrase_match(lower, "x")
        ):
            return (
                "𝕏 X Analyzer\n\n"
                "Open Social Analyzer → X.\n"
                "Upload the relevant screenshot and run the analysis."
            )

        return (
            "📱 Social Analyzer\n\n"
            "SENTINEL supports social-profile analysis for "
            "Instagram, Facebook and X.\n\n"
            "Select the platform, upload the screenshot, "
            "and run the analyzer."
        )

    # -----------------------------------------------------
    # GAME
    # -----------------------------------------------------

    if intent == "game":
        return (
            "🎮 Cyber Game\n\n"
            "Open the Cyber Game from the navigation menu.\n\n"
            "It helps you practice identifying phishing, "
            "scams, suspicious links and other cyber threats."
        )

    # -----------------------------------------------------
    # AWARENESS
    # -----------------------------------------------------

    if intent == "awareness":
        return (
            "📚 Cyber Awareness\n\n"
            "The Awareness section covers practical cybersecurity "
            "topics such as phishing, scams, passwords, privacy "
            "and safe online behavior.\n\n"
            "You can also ask me about any specific security topic."
        )

    # -----------------------------------------------------
    # DASHBOARD
    # -----------------------------------------------------

    if intent == "dashboard":
        return (
            "📊 Dashboard\n\n"
            "The SENTINEL Dashboard provides an overview of "
            "your security activity and results.\n\n"
            "Use it after interacting with SENTINEL's security tools."
        )

    # -----------------------------------------------------
    # AI
    # -----------------------------------------------------

    if intent == "ai":
        return (
            "🤖 I'm SENTINEL Cyber AI.\n\n"
            "I provide focused cybersecurity guidance and help "
            "you understand how to use the SENTINEL platform.\n\n"
            "Try asking:\n"
            "• Is this website suspicious?\n"
            "• What is phishing?\n"
            "• How do I scan a message?\n"
            "• What should I do after an OTP scam?"
        )

    # -----------------------------------------------------
    # PHISHING
    # -----------------------------------------------------

    if intent == "phishing":
        return (
            "🎣 Phishing is a social-engineering attack where "
            "someone pretends to be a trusted person or organization "
            "to steal information or money.\n\n"
            "Common signs:\n"
            "• Urgent requests\n"
            "• Fake login pages\n"
            "• Suspicious domains\n"
            "• Unexpected attachments\n"
            "• OTP/password requests\n\n"
            "Never trust a link simply because the message looks official."
        )

    # -----------------------------------------------------
    # OTP
    # -----------------------------------------------------

    if intent == "otp":
        return (
            "🔐 OTP Safety\n\n"
            "Never share an OTP with another person.\n\n"
            "An OTP can authorize sensitive actions such as "
            "login, payments or account changes.\n\n"
            "If someone asks you to tell them your OTP, "
            "treat it as a major warning sign."
        )

    # -----------------------------------------------------
    # UPI
    # -----------------------------------------------------

    if intent == "upi":
        return (
            "💳 UPI Safety\n\n"
            "• Never share your UPI PIN or OTP.\n"
            "• You do NOT need to enter your UPI PIN to receive money.\n"
            "• Reject unexpected collect/payment requests.\n"
            "• Verify the recipient before approving a payment.\n"
            "• Never scan a QR code just because someone says "
            "it will receive money.\n\n"
            "If you lose money to financial fraud in India, "
            "report it immediately through 1930."
        )

    # -----------------------------------------------------
    # KYC
    # -----------------------------------------------------

    if intent == "kyc":
        return (
            "🏦 KYC Scam Warning\n\n"
            "Scammers often claim that your KYC will expire "
            "or your bank/SIM/account will be blocked.\n\n"
            "Don't use links from unexpected messages.\n"
            "Open the official bank or service app yourself "
            "and verify the request there.\n\n"
            "Never share OTPs, PINs or passwords."
        )

    # -----------------------------------------------------
    # PASSWORD
    # -----------------------------------------------------

    if intent == "password":
        return (
            "🔑 Password Security\n\n"
            "Use a long, unique password for every important account.\n\n"
            "Best practices:\n"
            "• Don't reuse passwords.\n"
            "• Don't use your birthday or obvious information.\n"
            "• Use a password manager when possible.\n"
            "• Enable two-factor authentication.\n"
            "• Never share your password."
        )

    # -----------------------------------------------------
    # FAKE WEBSITE
    # -----------------------------------------------------

    if intent == "fake_website":
        return (
            "🌐 Fake Website Detection\n\n"
            "A website can look professional and still be fake.\n\n"
            "Check:\n"
            "• Exact domain spelling\n"
            "• HTTPS\n"
            "• Suspicious subdomains\n"
            "• Punycode\n"
            "• Brand impersonation\n"
            "• Unusual URL structure\n"
            "• Unexpected login/payment requests\n\n"
            "For an actual URL analysis, use SENTINEL's "
            "Website Scanner."
        )

    # -----------------------------------------------------
    # MALWARE
    # -----------------------------------------------------

    if intent == "malware":
        return (
            "🦠 Malware is malicious software that can steal "
            "information, spy on users, damage systems or encrypt files.\n\n"
            "Avoid unknown APKs, cracked software, suspicious "
            "attachments and fake updates.\n\n"
            "Keep your operating system and security software updated."
        )

    # -----------------------------------------------------
    # ACCOUNT HACKED
    # -----------------------------------------------------

    if intent == "account_hacked":
        return (
            "🚨 If you think your account was hacked:\n\n"
            "1. Change the password using the official service.\n"
            "2. Enable two-factor authentication.\n"
            "3. Sign out unknown sessions/devices.\n"
            "4. Check recovery email and phone settings.\n"
            "5. Remove suspicious connected apps.\n"
            "6. Review recent account activity."
        )

    # -----------------------------------------------------
    # SCAM
    # -----------------------------------------------------

    if intent == "scam":
        return (
            "⚠️ Possible Scam\n\n"
            "Stop interacting with the suspicious source.\n\n"
            "Don't:\n"
            "• Click unknown links\n"
            "• Send money\n"
            "• Share OTPs\n"
            "• Share passwords\n"
            "• Install unknown apps\n\n"
            "If you have the suspicious message or URL, "
            "use the appropriate SENTINEL scanner."
        )

    # -----------------------------------------------------
    # URL FOUND INSIDE AI MESSAGE
    # -----------------------------------------------------

    url_match = re.search(
        r"https?://[^\s]+|"
        r"(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"
        r"(?:/[^\s]*)?",
        text
    )

    if url_match:

        detected_url = url_match.group(0)

        valid, normalized, error = is_valid_url_input(
            detected_url
        )

        if not valid:
            return (
                "That doesn't look like a valid public website URL.\n\n"
                "Please check the spelling and enter a complete "
                "domain such as example.com."
            )

        return (
            "🌐 I detected a website URL in your message.\n\n"
            "For a proper safety assessment, paste it into "
            "SENTINEL's Website Scanner.\n\n"
            "The scanner evaluates the URL using multiple "
            "security indicators instead of simply guessing."
        )

    # -----------------------------------------------------
    # NAVIGATION
    # -----------------------------------------------------

    if is_navigation_question(text):
        return (
            "You can use the SENTINEL navigation to access:\n\n"
            "• Website Scanner\n"
            "• Message Scanner\n"
            "• Social Analyzer\n"
            "• Cyber Game\n"
            "• Cyber Awareness\n"
            "• Dashboard\n"
            "• AI Copilot"
        )

    # -----------------------------------------------------
    # GENERAL CYBERSECURITY
    # -----------------------------------------------------

    cyber_terms = [
        "cybersecurity",
        "cyber security",
        "online safety",
        "internet safety",
        "privacy",
        "security",
        "hacker",
        "hacking",
        "online fraud"
    ]

    if any(
        phrase_match(lower, term)
        for term in cyber_terms
    ):
        return (
            "🛡️ Cybersecurity Basics\n\n"
            "Stay safer online by:\n"
            "• Verifying links before opening them\n"
            "• Using unique passwords\n"
            "• Enabling two-factor authentication\n"
            "• Never sharing OTPs or PINs\n"
            "• Avoiding unknown downloads\n"
            "• Keeping devices updated\n"
            "• Verifying unexpected payment requests"
        )

    # -----------------------------------------------------
    # UNKNOWN / OFF TOPIC
    # -----------------------------------------------------

    return (
        "I'm focused on SENTINEL and cybersecurity. 🛡️\n\n"
        "You can ask me about:\n"
        "• Fake websites\n"
        "• Website scanning\n"
        "• Phishing\n"
        "• Scam messages\n"
        "• OTP / UPI / KYC scams\n"
        "• Password security\n"
        "• Malware\n"
        "• Hacked accounts\n"
        "• Social Analyzer\n"
        "• Cyber Game\n"
        "• Dashboard\n"
        "• Cyber Awareness"
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

    result = scan_url(url)

    # Invalid URL gets a proper HTTP error response.
    if result.get("invalid"):
        return jsonify(result), 400

    return jsonify(result)


@app.route("/scan-message", methods=["POST"])
def scan_message_route():
    data = request.get_json(silent=True) or {}

    message = data.get("message", "")

    return jsonify(
        scan_message(message)
    )


@app.route("/scan-profile", methods=["POST"])
def scan_profile():
    data = request.get_json(silent=True) or {}

    text = str(
        data.get("profile", "")
    )

    score = 10
    reasons = []

    if not text:

        score = 20

        reasons.append(
            "No profile information was provided."
        )

    else:

        if len(text) < 20:

            score += 15

            reasons.append(
                "Very little profile information was provided."
            )

        if any(
            word in text.lower()
            for word in [
                "crypto",
                "investment",
                "double money"
            ]
        ):

            score += 30

            reasons.append(
                "Potential investment scam language detected."
            )

        if any(
            word in text.lower()
            for word in [
                "whatsapp",
                "telegram",
                "dm me"
            ]
        ):

            score += 10

            reasons.append(
                "The profile attempts to move communication off-platform."
            )

    return jsonify(
        make_result(score, reasons)
    )


@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    file = request.files.get("screenshot")

    if not file:
        return jsonify({
            "error": "No screenshot uploaded."
        }), 400

    return jsonify(
        scan_screenshot(file.filename)
    )


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
            "response": (
                "Tell me what you want help with."
            )
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
