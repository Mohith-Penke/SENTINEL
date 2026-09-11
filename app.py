import os
import re
import ipaddress
import base64
import json
import hashlib
import subprocess
import tempfile
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)

PORT = int(os.environ.get("PORT", 5000))


# =========================================================
# RISK HELPERS
# =========================================================

def risk_level(score):
    # Internal/raw severity thresholds. The displayed score is mapped
    # separately so the UI stays inside the requested 30-100 range.
    score = max(0, min(100, float(score or 0)))
    if score >= 61:
        return "HIGH"
    if score >= 36:
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


def display_risk_score(raw_score):
    """Map raw evidence severity to the requested UI score bands.

    LOW: 30-40
    MEDIUM: 41-70
    HIGH: 71-100

    The mapping is based on the actual evidence score; it does not use
    fixed values for all websites.
    """
    raw = max(0.0, min(100.0, float(raw_score or 0)))

    if raw <= 35.0:
        return int(round(30.0 + (raw / 35.0) * 10.0))
    if raw <= 60.0:
        return int(round(41.0 + ((raw - 36.0) / 24.0) * 29.0))
    return int(round(71.0 + ((raw - 61.0) / 39.0) * 29.0))


def make_result(score, reasons):
    raw_score = max(0.0, min(100.0, float(score or 0)))
    score = display_risk_score(raw_score)
    level = risk_level(raw_score)

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
# ROUND 2: SSL / CERTIFICATE VALIDITY
# =========================================================

def check_ssl_certificate(url):
    """Perform a real TLS certificate validation and collect certificate details.

    The result contains both the security verdict and useful certificate
    metadata for the Website Scanner UI. A valid certificate only confirms
    the TLS connection is properly authenticated; it does not prove that the
    website itself is legitimate.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port or 443
    except ValueError:
        return {
            "checked": True,
            "https": parsed.scheme.lower() == "https",
            "valid": False,
            "hostname_match": False,
            "trusted": False,
            "expired": None,
            "expires_at": None,
            "valid_from": None,
            "days_remaining": None,
            "issuer": None,
            "subject": None,
            "tls_version": None,
            "cipher": None,
            "certificate_version": None,
            "error": "Invalid HTTPS port.",
            "security_message": "The HTTPS port is invalid."
        }
    now = datetime.now(timezone.utc)

    result = {
        "checked": True,
        "https": parsed.scheme.lower() == "https",
        "valid": False,
        "hostname_match": False,
        "trusted": False,
        "expired": None,
        "expires_at": None,
        "valid_from": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "tls_version": None,
        "cipher": None,
        "certificate_version": None,
        "error": None,
        "security_message": None,
    }

    if parsed.scheme.lower() != "https":
        result["error"] = "The website is not using HTTPS/TLS."
        result["security_message"] = (
            "This website does not establish an HTTPS/TLS connection."
        )
        return result

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=4) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()

                result["trusted"] = True
                result["hostname_match"] = True
                result["tls_version"] = tls_socket.version()

                cipher_info = tls_socket.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]

                if cert.get("version") is not None:
                    result["certificate_version"] = "v" + str(cert["version"] + 1)

                not_before = cert.get("notBefore")
                if not_before:
                    issued = datetime.strptime(
                        not_before, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    result["valid_from"] = issued.isoformat()

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    result["expires_at"] = expiry.isoformat()
                    result["expired"] = expiry <= now
                    result["days_remaining"] = max(0, (expiry - now).days)

                issuer_parts = []
                for group in cert.get("issuer", ()):
                    for key, value in group:
                        if key in ("organizationName", "commonName"):
                            issuer_parts.append(str(value))
                if issuer_parts:
                    result["issuer"] = " / ".join(dict.fromkeys(issuer_parts))

                subject_parts = []
                for group in cert.get("subject", ()):
                    for key, value in group:
                        if key in ("commonName", "organizationName"):
                            subject_parts.append(str(value))
                if subject_parts:
                    result["subject"] = " / ".join(dict.fromkeys(subject_parts))

                result["valid"] = (
                    result["trusted"]
                    and result["hostname_match"]
                    and result["expired"] is False
                )

                if result["valid"]:
                    result["security_message"] = (
                        "The certificate is trusted, matches the requested hostname, "
                        "and is currently within its validity period."
                    )
                elif result["expired"]:
                    result["error"] = "The TLS certificate has expired."
                    result["security_message"] = "The certificate exists but has expired."
                else:
                    result["security_message"] = (
                        "The HTTPS certificate could not be fully validated."
                    )

    except ssl.CertificateError:
        result["hostname_match"] = False
        result["error"] = "Certificate hostname verification failed."
        result["security_message"] = "The certificate does not match the requested hostname."
    except ssl.SSLCertVerificationError as exc:
        result["error"] = "The TLS certificate could not be trusted or is invalid."
        result["security_message"] = "The certificate validation failed during the TLS handshake."
        if getattr(exc, "verify_message", None):
            result["verification_error"] = str(exc.verify_message)
    except (socket.timeout, TimeoutError):
        result["error"] = "TLS certificate check timed out."
        result["security_message"] = "The server did not respond to the certificate check in time."
    except (socket.gaierror, ConnectionError, OSError):
        result["error"] = "The TLS certificate could not be checked because the host is unreachable."
        result["security_message"] = "The server could not complete the TLS certificate check."
    except Exception as exc:
        result["error"] = f"TLS certificate check failed: {exc.__class__.__name__}."
        result["security_message"] = "The certificate could not be fully evaluated."

    return result


# =========================================================
# ROUND 2: VISUAL SIMILARITY / CLONING CHECK
# =========================================================

KNOWN_LEGITIMATE_SITES = {
    "paypal": "https://www.paypal.com/",
    "google": "https://www.google.com/",
    "microsoft": "https://www.microsoft.com/",
    "apple": "https://www.apple.com/",
    "amazon": "https://www.amazon.com/",
    "instagram": "https://www.instagram.com/",
    "facebook": "https://www.facebook.com/",
    "sbi": "https://www.sbi.co.in/",
    "hdfc": "https://www.hdfcbank.com/",
    "icici": "https://www.icicibank.com/",
}


def _detect_brand_for_visual_check(host):
    for brand, official_url in KNOWN_LEGITIMATE_SITES.items():
        official_host = (urlparse(official_url).hostname or "").lower()
        if brand in host and not (
            host == official_host or host.endswith("." + official_host)
        ):
            return brand, official_url
    return None, None


def _visual_similarity_playwright(target_url, reference_url):
    """Render both pages and compare screenshots when Playwright is available.

    Returns a structured result instead of a guessed score. If the browser
    runtime is unavailable, the caller receives an explicit unavailable state.
    """
    try:
        from PIL import Image, ImageChops, ImageStat
        from playwright.sync_api import sync_playwright
    except Exception:
        return {
            "available": False,
            "method": "browser-rendered screenshot",
            "similarity_percent": None,
            "reference": reference_url,
            "reason": "Playwright/Pillow is not installed on the server."
        }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    viewport={"width": 1365, "height": 900},
                    ignore_https_errors=True,
                )

                images = []
                for page_url in (reference_url, target_url):
                    page = context.new_page()
                    page.goto(
                        page_url,
                        wait_until="domcontentloaded",
                        timeout=10000,
                    )
                    page.wait_for_timeout(700)
                    raw = page.screenshot(
                        type="png",
                        full_page=False,
                    )
                    images.append(Image.open(__import__("io").BytesIO(raw)).convert("RGB"))
                    page.close()

                reference_image, target_image = images
                target_image = target_image.resize(reference_image.size)
                diff = ImageChops.difference(reference_image, target_image)
                mean_diff = sum(ImageStat.Stat(diff).mean) / 3.0
                similarity = max(0.0, min(100.0, 100.0 - (mean_diff / 255.0 * 100.0)))

                return {
                    "available": True,
                    "method": "browser-rendered screenshot",
                    "similarity_percent": round(similarity, 2),
                    "reference": reference_url,
                    "reason": "Compared rendered page pixels at a fixed viewport."
                }
            finally:
                browser.close()
    except Exception as exc:
        return {
            "available": False,
            "method": "browser-rendered screenshot",
            "similarity_percent": None,
            "reference": reference_url,
            "reason": f"Visual rendering failed: {exc.__class__.__name__}."
        }


def check_visual_similarity(url):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    brand, reference_url = _detect_brand_for_visual_check(host)

    result = {
        "checked": False,
        "available": False,
        "brand": brand,
        "reference": reference_url,
        "similarity_percent": None,
        "cloning_indicator": False,
        "method": "browser-rendered screenshot",
        "reason": None,
    }

    if not brand or not reference_url:
        result["reason"] = "No known legitimate brand reference matched this domain."
        return result

    result["checked"] = True
    visual = _visual_similarity_playwright(url, reference_url)
    result.update(visual)

    similarity = result.get("similarity_percent")
    if isinstance(similarity, (int, float)):
        result["cloning_indicator"] = similarity >= 75.0
        if result["cloning_indicator"]:
            result["reason"] = (
                f"The rendered page is highly similar to the known legitimate "
                f"{brand.title()} site."
            )
        else:
            result["reason"] = (
                f"The rendered page was compared with the known legitimate "
                f"{brand.title()} site."
            )

    return result


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

    try:
        parsed_port = parsed.port
    except ValueError:
        return {
            "invalid": True,
            "error": "Invalid URL. The port number is not valid.",
            "message": "Invalid URL. The port number is not valid."
        }

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
    if parsed_port:
        score += 15
        reasons.append(
            "The URL uses a non-standard port."
        )

    # ---------------------------------------------------------
    # ROUND 2: SSL certificate validity
    # ---------------------------------------------------------
    try:
        ssl_result = check_ssl_certificate(url)
    except Exception as exc:
        ssl_result = {
            "checked": True,
            "https": parsed.scheme.lower() == "https",
            "valid": False,
            "hostname_match": False,
            "trusted": False,
            "expired": None,
            "expires_at": None,
            "issuer": None,
            "error": f"TLS certificate check failed: {exc.__class__.__name__}."
        }

    if parsed.scheme.lower() == "https":
        if ssl_result.get("valid"):
            reasons.append("TLS certificate validation passed: the certificate is trusted, matches the hostname, and is not expired.")
        else:
            score += 30
            if ssl_result.get("error"):
                reasons.append("SSL/TLS certificate check failed: " + ssl_result["error"])

    # ---------------------------------------------------------
    # ROUND 2: rendered visual similarity / cloning check
    # ---------------------------------------------------------
    try:
        visual_result = check_visual_similarity(url)
    except Exception as exc:
        # Visual analysis is an optional Round-2 signal. Never let a
        # missing browser/runtime break the normal URL scanner.
        visual_result = {
            "checked": False,
            "available": False,
            "brand": None,
            "reference": None,
            "similarity_percent": None,
            "cloning_indicator": False,
            "method": "browser-rendered screenshot",
            "reason": f"Visual analysis unavailable: {exc.__class__.__name__}."
        }

    if visual_result.get("cloning_indicator"):
        score += 30
        reasons.append(
            "Visual cloning indicator: the rendered page is highly similar to a known legitimate "
            + str(visual_result.get("brand") or "brand")
            + " website."
        )
    elif visual_result.get("checked") and visual_result.get("available"):
        reasons.append(
            "Visual similarity check completed against the known legitimate "
            + str(visual_result.get("brand") or "brand")
            + " website."
        )

    if not reasons:
        reasons.append(
            "No major suspicious URL indicators were detected."
        )

    result = make_result(score, reasons)
    result["ssl_check"] = ssl_result
    result["visual_similarity"] = visual_result
    return result


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
# SOCIAL SCREENSHOT ANALYZER — API-FREE ENGINE
# =========================================================
# This module intentionally uses ONLY the uploaded screenshot + local OCR.
# No OpenAI/API/network call is required for Social Analyzer.

SOCIAL_ROOT_GROUPS = {
    "giveaway": {
        "words": ["giveaway", "give away", "winner", "you won", "prize", "lucky draw", "free gift", "free iphone", "free phone", "iphone giveaway", "reward", "coupon", "voucher", "claim prize", "claim now", "congratulations", "selected winner", "selected for prize", "gift hamper"],
        "score": 24, "type": "Giveaway / prize signal", "tip": "Do not pay a processing, shipping, registration or claiming fee for a prize. Verify the giveaway through the brand's official channel."
    },
    "romance": {
        "words": ["love", "lover", "relationship", "soulmate", "boyfriend", "girlfriend", "fiance", "fiancé", "husband", "wife", "dating", "romance", "marry me", "marriage", "sweetheart", "baby", "darling", "miss you", "trust me", "lonely", "long distance", "true love", "future together"],
        "score": 8, "type": "Romance / relationship signal", "tip": "Do not send money, gifts, crypto or financial information to an online romantic contact without independent real-world verification."
    },
    "romance_money": {
        "words": ["send money", "need money", "borrow money", "help me financially", "gift card", "emergency", "hospital", "accident", "stranded", "pay my bill", "medical emergency", "urgent help", "family problem", "funeral", "travel emergency"],
        "score": 34, "type": "Romance / emotional-money risk", "tip": "Do not send money or gift cards because of an online relationship or emergency story. Verify the person independently first."
    },
    "investment": {
        "words": ["investment", "invest now", "guaranteed return", "guaranteed profit", "guaranteed returns", "profit", "returns", "double money", "triple money", "passive income", "forex", "trading", "trading signals", "crypto", "bitcoin", "ethereum", "usdt", "mining", "money flip", "flip money", "100% profit", "risk free investment", "risk-free investment", "daily profit", "fixed return", "instant profit"],
        "score": 38, "type": "Investment / financial scam signal", "tip": "Do not transfer money or crypto based on guaranteed-profit claims. Verify the company, platform and offer independently using trusted sources."
    },
    "job": {
        "words": ["job offer", "work from home", "work-from-home", "part time job", "part-time", "hiring", "vacancy", "recruitment", "recruiter", "earn money", "easy income", "daily income", "task job", "online task", "like and earn", "review and earn", "apply now", "limited slots", "training fee", "registration fee", "job registration", "joining fee", "security deposit for job", "salary"],
        "score": 26, "type": "Job / task scam signal", "tip": "Never pay a registration, training, joining or deposit fee to receive a job. Verify the employer through its official website and recruitment channel."
    },
    "payment": {
        "words": ["send money", "pay now", "payment", "processing fee", "shipping fee", "registration fee", "advance fee", "deposit", "recharge", "withdraw", "unlock payment", "upi", "upi id", "bank account", "bank details", "card number", "credit card", "debit card", "cvv", "gift card", "payment link", "qr code", "scan qr", "paytm", "phonepe", "google pay", "gpay", "transfer money", "wire transfer", "advance payment", "pay first", "pay to claim"],
        "score": 42, "type": "Payment / financial-risk signal", "tip": "Do not send money or share UPI PIN, banking, card or payment credentials. Independently verify the recipient and request."
    },
    "credentials": {
        "words": ["otp", "one time password", "verification code", "password", "passcode", "pin", "upi pin", "login", "sign in", "username", "credentials", "kyc", "verify account", "account verification", "verify your account", "reset password", "recover account", "security code", "authentication code", "login details", "secret code", "verification link", "enter otp", "share otp"],
        "score": 50, "type": "Credential / phishing signal", "tip": "Do not share OTPs, passwords, PINs or login codes. Open the official app/site yourself instead of using a suspicious link."
    },
    "phishing": {
        "words": ["bit.ly", "tinyurl", "goo.gl", "t.co/", "shorturl", "click here", "click the link", "login here", "verify here", "registration link", "claim link", "download now", "open this link", "link in bio", "tap here", "swipe up", "visit this link", "sign in here"],
        "score": 30, "type": "Suspicious link / phishing signal", "tip": "Do not open an unfamiliar link. Check the exact destination domain independently before entering any information."
    },
    "urgency": {
        "words": ["urgent", "immediately", "act now", "hurry", "limited time", "last chance", "expires today", "within 24 hours", "don't wait", "do it now", "final warning", "account will be blocked", "account suspended", "respond now", "only today", "offer ends", "deadline", "right now", "immediate action"],
        "score": 22, "type": "Urgency / social-engineering signal", "tip": "Do not let urgency force a decision. Pause and verify the request through an independent official channel."
    },
    "impersonation": {
        "words": ["official", "customer support", "customer care", "support team", "admin", "administrator", "ceo", "founder", "police", "government", "bank support", "instagram support", "facebook support", "x support", "recovery team", "account recovery", "security team", "help desk", "official account", "official support"],
        "score": 24, "type": "Possible impersonation / fake-support signal", "tip": "Verify the identity through the organization's official website or app. Do not trust a support claim just because the profile looks official."
    },
    "shopping": {
        "words": ["huge discount", "massive discount", "clearance sale", "limited stock", "only today", "cheap price", "lowest price", "50% off", "70% off", "80% off", "90% off", "brand new", "pre order", "pre-order", "advance payment", "cash on delivery", "flash sale", "mega sale", "exclusive offer", "limited offer"],
        "score": 22, "type": "Shopping / fake-store signal", "tip": "Check the seller, exact website, reviews and payment method independently. Avoid advance payment to an unknown seller."
    },
    "donation": {
        "words": ["donate", "donation", "fundraiser", "medical emergency", "medical help", "relief fund", "charity", "help this family", "help the child", "crowdfunding", "donate now", "support this cause"],
        "score": 20, "type": "Donation / charity signal", "tip": "Verify the charity or beneficiary independently before donating. Do not rely only on a social-media post or DM."
    },
    "tickets": {
        "words": ["concert ticket", "concert tickets", "event ticket", "event tickets", "vip pass", "tickets available", "booking", "reservation", "flight ticket", "movie ticket", "free ticket", "early bird ticket", "event registration"],
        "score": 18, "type": "Ticket / event signal", "tip": "Buy tickets only through official or trusted platforms. Avoid advance transfers to unknown accounts."
    },
    "loan_grant": {
        "words": ["instant loan", "easy loan", "loan approved", "loan offer", "grant", "subsidy", "financial aid", "scholarship", "government scheme", "loan processing fee", "loan fee", "approval fee", "loan deposit", "scholarship fee"],
        "score": 26, "type": "Loan / grant / financial-aid signal", "tip": "Verify the lender or program through its official website. Never pay an unexpected fee to unlock a loan, grant or scholarship."
    },
    "gambling": {
        "words": ["jackpot", "lottery", "betting", "bet now", "casino", "sports betting", "guaranteed win", "winning number", "spin and win", "jackpot winner", "lottery winner"],
        "score": 26, "type": "Lottery / gambling signal", "tip": "Do not send money or personal information to claim winnings or guaranteed profits. Verify the service independently."
    },
    "tech_support": {
        "words": ["virus detected", "your account is hacked", "device infected", "technical support", "remote access", "anydesk", "teamviewer", "support number", "call immediately", "security alert", "computer infected", "malware detected"],
        "score": 38, "type": "Tech-support scam signal", "tip": "Do not install remote-access software or call an unexpected support number. Use the official support page instead."
    },
    "delivery": {
        "words": ["parcel", "package", "courier", "delivery failed", "customs fee", "delivery fee", "shipment", "reschedule delivery", "delivery charge", "address confirmation", "missed package"],
        "score": 26, "type": "Delivery / parcel signal", "tip": "Verify delivery messages through the courier's official website or app. Do not pay unexpected fees through social-media links."
    },
    "government": {
        "words": ["income tax", "tax notice", "police notice", "court notice", "legal action", "arrest warrant", "aadhaar", "aadhar", "pan card", "government notice", "fine", "penalty", "court case", "police case", "legal notice", "tax penalty"],
        "score": 30, "type": "Authority impersonation signal", "tip": "Do not pay or share credentials because of an unexpected authority claim. Contact the organization using an official channel."
    },
    "personal_data": {
        "words": ["aadhaar number", "aadhar number", "pan number", "date of birth", "address", "phone number", "email address", "bank details", "card details", "identity proof", "id proof", "passport", "driving licence", "driver license", "selfie with id", "personal details"],
        "score": 20, "type": "Personal-data collection signal", "tip": "Avoid sharing identity, banking or other sensitive personal information with an unverified account."
    },
    "off_platform": {
        "words": ["whatsapp", "telegram", "dm me", "message me privately", "contact me privately", "move to whatsapp", "move to telegram", "send me a dm", "chat privately", "private message", "call me", "contact me"],
        "score": 14, "type": "Off-platform contact signal", "tip": "Be cautious when an unknown account quickly moves you to WhatsApp, Telegram or private contact. Verify the identity independently."
    },
    "secrecy_threat": {
        "words": ["keep this secret", "don't tell anyone", "do not tell anyone", "confidential", "you will be arrested", "police will arrest", "account will be deleted", "you will lose access", "nobody should know", "secret", "legal action", "arrested", "blocked permanently"],
        "score": 30, "type": "Threat / secrecy social-engineering signal", "tip": "Do not act under threats or secrecy pressure. Stop and verify the claim independently."
    },
    "fake_news": {
        "words": ["breaking news", "shocking news", "100% confirmed", "viral news", "share immediately", "forward this", "government confirmed", "secret news", "must share", "confirmed news", "exclusive breaking"],
        "score": 12, "type": "Potential misinformation / engagement-bait signal", "tip": "Verify sensational claims with reputable sources before sharing or acting on them."
    },
    "business_opportunity": {
        "words": ["franchise", "dealership", "reseller", "business opportunity", "passive income", "earn from home", "investment opportunity", "guaranteed business", "be your own boss", "business offer", "reselling opportunity"],
        "score": 22, "type": "Business-opportunity signal", "tip": "Verify the company, terms and financial claims independently. Avoid upfront payments for unverified opportunities."
    },
    "money_flip_task": {
        "words": ["deposit", "unlock", "withdraw", "recharge", "commission", "task completion", "complete tasks", "level up", "withdrawal fee", "unlock withdrawal", "recharge account", "commission earned", "task commission"],
        "score": 34, "type": "Money-flipping / task scam signal", "tip": "Do not deposit or recharge money to unlock tasks, commissions or withdrawals. Stop if the platform demands more money to release your balance."
    },
    "friend_family": {
        "words": ["new number", "new phone number", "my new number", "this is my new number", "send money", "emergency", "don't call", "lost my phone", "phone broken", "stranded"],
        "score": 30, "type": "Friend/family impersonation signal", "tip": "Do not send money to a claimed friend or family member based only on a message. Call their known number or verify through another trusted channel."
    },
    "matrimonial": {
        "words": ["marriage proposal", "matrimony", "wedding", "marry", "marriage proposal", "wedding expenses", "dowry"],
        "score": 12, "type": "Matrimonial signal", "tip": "Verify identity and family/background independently before sharing money or sensitive documents."
    },
    "travel": {
        "words": ["visa", "passport", "cheap flight", "flight offer", "hotel booking", "hotel deal", "travel package", "tour package", "visa fee", "immigration"],
        "score": 18, "type": "Travel / booking signal", "tip": "Verify travel, visa and booking offers through the official provider. Avoid advance payment to unknown accounts."
    },
    "property_rental": {
        "words": ["house rent", "rent", "rental", "property deal", "flat for rent", "apartment for rent", "security deposit", "advance rent", "property booking"],
        "score": 18, "type": "Rental / property signal", "tip": "Verify the property, owner and agreement independently. Do not transfer an advance or deposit before verification."
    },
    "too_good": {
        "words": ["free", "guaranteed", "instant", "unbelievable", "100% profit", "double your money", "get rich quick", "no risk", "zero risk", "easy money", "fast money"],
        "score": 14, "type": "Too-good-to-be-true signal", "tip": "Treat unusually easy or guaranteed benefits as a warning sign and verify the claim independently."
    }
}


def _read_uploaded_image(file):
    if file is None:
        return b""
    try:
        file.stream.seek(0)
    except Exception:
        pass
    try:
        data = file.read()
    except Exception:
        return b""
    try:
        file.stream.seek(0)
    except Exception:
        pass
    if not data or len(data) > 12 * 1024 * 1024:
        return b""
    return data


def _prepare_ocr_upload(image_bytes):
    """Prepare the screenshot for OCR.space free-tier limits.

    OCR.space free endpoint accepts image uploads, but the free plan has a
    small image-size limit. Resize/compress locally before sending so normal
    phone screenshots can still be analysed.
    """
    try:
        from PIL import Image
        import io

        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        max_side = 1800
        if max(image.size) > max_side:
            scale = max_side / float(max(image.size))
            image = image.resize(
                (max(1, int(image.width * scale)),
                 max(1, int(image.height * scale)))
            )

        quality = 88
        while True:
            out = io.BytesIO()
            image.save(out, format="JPEG", quality=quality, optimize=True)
            data = out.getvalue()
            # Keep comfortably below OCR.space's 1 MB free-tier image limit.
            if len(data) <= 900 * 1024 or quality <= 55:
                return data, "image/jpeg"
            quality -= 7
    except Exception:
        return image_bytes, "application/octet-stream"


def _ocr_space_request(image_bytes):
    """Extract text through OCR.space. The API key is read only from env."""
    try:
        import requests

        api_key = os.environ.get("OCR_SPACE_API_KEY", "").strip()
        if not api_key:
            return "", "OCR_SPACE_API_KEY is not configured on the server."

        upload, mime = _prepare_ocr_upload(image_bytes)
        response = requests.post(
            "https://api.ocr.space/parse/image",
            files={"file": ("screenshot.jpg", upload, mime)},
            data={
                "apikey": api_key,
                "language": "eng",
                "isOverlayRequired": "false",
                "OCREngine": "2",
                "scale": "true",
                "detectOrientation": "true",
            },
            timeout=45,
        )

        if response.status_code != 200:
            return "", f"OCR service returned HTTP {response.status_code}."

        try:
            payload = response.json()
        except ValueError:
            return "", "OCR service returned an invalid JSON response."

        if not isinstance(payload, dict):
            return "", "OCR service returned an unexpected response."

        if payload.get("IsErroredOnProcessing"):
            errors = payload.get("ErrorMessage") or payload.get("ErrorDetails") or "OCR processing failed."
            if isinstance(errors, list):
                errors = "; ".join(str(x) for x in errors)
            return "", str(errors)

        parsed_results = payload.get("ParsedResults") or []
        texts = []
        for item in parsed_results:
            if isinstance(item, dict):
                text = item.get("ParsedText") or ""
                if text:
                    texts.append(str(text))

        text = "\n".join(texts).strip()
        if not text:
            return "", "OCR service returned no readable text."

        return text, ""
    except requests.exceptions.Timeout:
        return "", "OCR service timed out."
    except requests.exceptions.RequestException as exc:
        return "", f"OCR service request failed: {exc.__class__.__name__}."
    except Exception as exc:
        return "", f"OCR processing failed: {exc.__class__.__name__}."


def _extract_local_ocr(image_bytes):
    """Extract screenshot text with OCR.space, while keeping analysis local.

    Only OCR is sent to the third-party service. The SENTINEL risk engine,
    root-word detection, scoring and situation-based advice remain in this
    application and are not delegated to the API.
    """
    if not image_bytes:
        return ""

    text, error = _ocr_space_request(image_bytes)
    # Keep the last OCR error available to scan_screenshot without exposing
    # implementation details in the normal successful result.
    global _SOCIAL_OCR_LAST_ERROR
    _SOCIAL_OCR_LAST_ERROR = error

    if not text:
        return ""

    seen = set()
    lines = []
    for raw in text.splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if len(line) < 2:
            continue
        key = line.lower()
        if key not in seen:
            seen.add(key)
            lines.append(line)
    return "\n".join(lines)


_SOCIAL_OCR_LAST_ERROR = ""

def _normalise_social_text(text):
    text = str(text or "").lower()
    replacements = {
        "0tp": "otp", "ot p": "otp", "u pi": "upi", "ky c": "kyc",
        "whats app": "whatsapp", "tele gram": "telegram", "bit . ly": "bit.ly",
        "t co /": "t.co/", "pay tm": "paytm", "phone pe": "phonepe",
        "google pay": "google pay", "pass word": "password", "log in": "login",
    }
    for a, b in replacements.items():
        text = text.replace(a, b)
    return re.sub(r"\s+", " ", text).strip()


def _keyword_hits(text, words):
    text = _normalise_social_text(text)
    hits = []
    for word in words:
        w = _normalise_social_text(word)
        if not w:
            continue
        # OCR-friendly matching: tolerate spaces/punctuation between phrase tokens.
        tokens = [re.escape(x) for x in re.split(r"\s+", w) if x]
        pattern = r"(?<![a-z0-9])" + r"\W*".join(tokens) + r"(?![a-z0-9])"
        if re.search(pattern, text, re.I):
            hits.append(word)
    return hits


def _extract_profile_numbers(text):
    text = str(text or "")
    result = {"followers": None, "following": None, "posts": None}
    patterns = {
        "followers": [r"([\d,.]+\s*[kKmMbB]?)\s*(?:followers|follower)\b"],
        "following": [r"([\d,.]+\s*[kKmMbB]?)\s*(?:following)\b"],
        "posts": [r"([\d,.]+\s*[kKmMbB]?)\s*(?:posts|post)\b"],
    }
    for field, pats in patterns.items():
        for pattern in pats:
            m = re.search(pattern, text, re.I)
            if not m:
                continue
            raw = m.group(1).replace(",", "").strip().lower()
            multiplier = 1
            if raw.endswith("k"):
                multiplier, raw = 1000, raw[:-1]
            elif raw.endswith("m"):
                multiplier, raw = 1000000, raw[:-1]
            elif raw.endswith("b"):
                multiplier, raw = 1000000000, raw[:-1]
            try:
                result[field] = int(float(raw) * multiplier)
            except ValueError:
                pass
            break
    return result


def _detect_platform(text):
    low = _normalise_social_text(text)
    if "instagram" in low or "followers" in low and "following" in low and "posts" in low:
        return "Instagram"
    if "facebook" in low or "friends" in low and "followers" in low:
        return "Facebook"
    if "twitter" in low or re.search(r"(^|\W)x(\W|$)", low) or "reposts" in low:
        return "X"
    return "Unknown"


def _detect_urls(text):
    raw = str(text or "")
    urls = re.findall(r"(?:https?://|www\.)[^\s<>()]+|\b[a-z0-9][a-z0-9.-]+\.(?:com|in|org|net|co|io|app|top|click|xyz|shop|win|vip|live|site|online)(?:/[^\s<>()]*)?", raw, re.I)
    return list(dict.fromkeys(urls))


def _social_signal(signals, category, signal, severity, evidence):
    signals.append({"category": category, "signal": signal, "severity": severity, "evidence": evidence})


def _apply_root_intelligence(analysis):
    text = _normalise_social_text(analysis.get("visible_text", ""))
    p = analysis.get("profile", {}) if isinstance(analysis.get("profile"), dict) else {}
    signals = [x for x in analysis.get("signals", []) if isinstance(x, dict)]
    scam_types = list(analysis.get("scam_types", []))
    advice = list(analysis.get("advice", []))
    detected = {}

    for category, info in SOCIAL_ROOT_GROUPS.items():
        hits = _keyword_hits(text, info["words"])
        if hits:
            detected[category] = hits
            sev = "high" if info["score"] >= 34 else ("medium" if info["score"] >= 18 else "low")
            _social_signal(signals, category, info["type"], sev, "Visible screenshot text: " + ", ".join(hits[:10]))
            if info["type"] not in scam_types:
                scam_types.append(info["type"])
            advice.append(info["tip"])

    # High-confidence combinations. These are deliberately stronger than single words.
    combos = [
        ({"romance", "romance_money"}, 32, "Romance + emergency/money request", "Relationship language is combined with an emotional emergency or financial request."),
        ({"romance", "off_platform"}, 14, "Romance + off-platform contact", "Relationship language is combined with private/off-platform contact."),
        ({"romance", "investment"}, 28, "Romance + investment pitch", "Relationship language is combined with an investment or profit opportunity."),
        ({"giveaway", "payment"}, 30, "Giveaway + payment request", "A prize/giveaway is combined with a fee or payment request."),
        ({"giveaway", "credentials"}, 38, "Giveaway + credential request", "A prize/giveaway is combined with OTP/password/account-verification language."),
        ({"giveaway", "phishing"}, 28, "Giveaway + suspicious link", "A prize/giveaway is combined with a claim/click/link request."),
        ({"job", "payment"}, 34, "Job + fee/payment request", "Employment/task language is combined with a fee, deposit or payment request."),
        ({"job", "off_platform"}, 12, "Job + off-platform contact", "Employment language is combined with private/off-platform contact."),
        ({"investment", "payment"}, 34, "Investment + payment request", "Investment language is combined with a request to transfer or deposit money."),
        ({"investment", "urgency"}, 20, "Investment + urgency", "Investment language is combined with pressure to act quickly."),
        ({"investment", "off_platform"}, 16, "Investment + private contact", "Investment language is combined with off-platform communication."),
        ({"impersonation", "credentials"}, 34, "Impersonation + credentials", "A support/authority identity is combined with credential or verification requests."),
        ({"impersonation", "payment"}, 36, "Impersonation + payment", "A support/authority identity is combined with a financial request."),
        ({"impersonation", "phishing"}, 28, "Impersonation + suspicious link", "A support/authority identity is combined with a suspicious link/login request."),
        ({"shopping", "payment"}, 26, "Shopping + advance payment", "A shopping offer is combined with an advance/payment request."),
        ({"delivery", "payment"}, 28, "Delivery + fee/payment", "A parcel/delivery claim is combined with a fee or payment request."),
        ({"government", "payment"}, 36, "Authority + payment", "An authority/legal claim is combined with a financial request."),
        ({"government", "credentials"}, 36, "Authority + credentials", "An authority claim is combined with identity/login information requests."),
        ({"secrecy_threat", "payment"}, 28, "Threat + payment", "Threat/secrecy pressure is combined with a financial request."),
        ({"tech_support", "credentials"}, 34, "Tech support + credentials", "Support/virus language is combined with security credential requests."),
        ({"loan_grant", "payment"}, 30, "Loan/grant + fee", "A loan/grant offer is combined with a fee or payment request."),
        ({"money_flip_task", "payment"}, 32, "Task/money-flip + payment", "A task or commission scheme is combined with deposits/recharges/payments."),
        ({"friend_family", "payment"}, 34, "Friend/family impersonation + payment", "A claimed friend/family emergency is combined with a money request."),
        ({"travel", "payment"}, 24, "Travel + payment", "A travel/visa/booking offer is combined with an advance payment request."),
        ({"property_rental", "payment"}, 24, "Rental/property + payment", "A property/rental offer is combined with an advance/deposit request."),
    ]
    for needed, points, label, evidence in combos:
        if needed.issubset(detected):
            _social_signal(signals, "combined_risk", label, "high", evidence)
            scam_types.append(label)
            advice.append("Do not proceed with this activity until the identity, offer, link and payment request are independently verified.")

    # URL intelligence from OCR-visible text.
    urls = _detect_urls(text)
    suspicious_tlds = (".top", ".click", ".xyz", ".shop", ".win", ".vip", ".live", ".site", ".online")
    for url in urls:
        ul = url.lower()
        if any(tld in ul for tld in suspicious_tlds):
            _social_signal(signals, "links", "Potentially suspicious domain pattern", "medium", "Visible URL: " + url)
            advice.append("Verify the exact domain independently before opening it or entering information.")
        if re.search(r"bit\.ly|tinyurl|goo\.gl|t\.co/|shorturl", ul):
            _social_signal(signals, "links", "Shortened URL", "high", "Visible URL: " + url)
            advice.append("Do not open a shortened link from an unknown account; verify its destination independently.")
        if re.search(r"login|signin|verify|account|payment|claim|register|registration", ul):
            _social_signal(signals, "links", "Action-oriented link destination", "medium", "Visible URL contains a login/verification/payment/claim-style path: " + url)

    # Extract weak account-authenticity clues, never as proof by themselves.
    nums = _extract_profile_numbers(text)
    for key in ("followers", "following", "posts"):
        if p.get(key) is None and nums.get(key) is not None:
            p[key] = nums[key]
    if p.get("posts") == 0:
        _social_signal(signals, "activity", "Zero posts visible", "low", "The target profile visibly shows 0 posts.")
    if isinstance(p.get("followers"), int) and isinstance(p.get("following"), int) and p["followers"] < 20 and p["following"] > 100:
        _social_signal(signals, "account_authenticity", "Unusual follower/following relationship", "low", "Visible follower count is much lower than following count.")
    if p.get("new_badge"):
        _social_signal(signals, "account_authenticity", "New-account indicator", "low", "A New indicator is associated with the target profile.")
    if p.get("default_profile_image"):
        _social_signal(signals, "account_authenticity", "Default/generic profile image", "low", "The target profile uses a default/generic image.")
    if p.get("fan_or_parody_label"):
        analysis.setdefault("risk_adjustments", {}).setdefault("negative", []).append("Fan/parody/unofficial labeling reduces impersonation concern.")
    if p.get("verified_badge"):
        analysis.setdefault("risk_adjustments", {}).setdefault("positive", []).append("A visible verified/blue badge is a positive verification signal.")

    analysis["profile"] = p
    analysis["signals"] = signals
    analysis["scam_types"] = list(dict.fromkeys(scam_types))
    analysis["advice"] = list(dict.fromkeys(advice))
    return analysis


def _social_score(analysis):
    analysis = _apply_root_intelligence(analysis)
    p = analysis.get("profile", {})
    signals = analysis.get("signals", [])
    score = 0
    reasons = []
    categories = set()
    for item in signals:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("category", "general")).lower()
        sev = str(item.get("severity", "low")).lower()
        categories.add(cat)
        pts = {"low": 3, "medium": 12, "high": 24}.get(sev, 3)
        score += pts
        signal = str(item.get("signal", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        if signal:
            reasons.append(signal + (": " + evidence if evidence else ""))

    # Avoid letting repeated OCR passes explode the score: cap each category contribution.
    by_cat = {}
    for item in signals:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("category", "general"))
        sev = str(item.get("severity", "low")).lower()
        pts = {"low": 3, "medium": 12, "high": 24}.get(sev, 3)
        by_cat[cat] = min(36, by_cat.get(cat, 0) + pts)
    score = sum(by_cat.values())

    # Strong cross-domain combinations.
    if {"credentials", "phishing"}.issubset(categories): score += 20
    if {"payment", "urgency"}.issubset(categories): score += 18
    if {"impersonation", "payment"}.issubset(categories): score += 20
    if {"romance", "romance_money"}.issubset(categories): score += 20
    if {"giveaway", "credentials"}.issubset(categories): score += 24

    hard = {"credentials", "payment", "investment", "romance_money", "tech_support", "government", "money_flip_task"}
    if categories.intersection(hard):
        score = max(score, 55)
    if {"credentials", "payment"}.issubset(categories) or {"giveaway", "credentials"}.issubset(categories):
        score = max(score, 78)

    # Weak account clues never create a strong accusation.
    if categories and categories.issubset({"activity", "account_authenticity"}):
        score = min(score, 25)

    if p.get("verified_badge"):
        score = max(0, score - 10)
        reasons.append("A visible verified badge is a positive credibility signal; it does not make suspicious requests safe.")
    if p.get("fan_or_parody_label"):
        score = max(0, score - 6)
        reasons.append("A visible fan/parody/unofficial label reduces impersonation concern.")
    return min(100, int(score)), list(dict.fromkeys(reasons)), analysis


def _social_advice(score, analysis):
    advice = list(analysis.get("advice", []))
    p = analysis.get("profile", {})
    categories = {str(x.get("category", "")).lower() for x in analysis.get("signals", []) if isinstance(x, dict)}

    if score >= 80:
        advice.insert(0, "🚫 Do not use or proceed with the suspicious activity shown. Do not click suspicious links, send money, or share OTP/password/PIN/KYC/bank/card/UPI details.")
    elif score >= 60:
        advice.insert(0, "⚠️ Do not proceed with the suspicious activity shown until the account, link and request are independently verified through an official/trusted source.")
    elif score >= 35:
        advice.insert(0, "🛡️ Be cautious with the activity shown. Verify the account and request independently before clicking links, sharing information or sending money.")
    elif p.get("verified_badge"):
        advice.insert(0, "🔵 Verified Profile Detected — the visible badge is a strong positive verification signal, but it is not an absolute guarantee. Verify unusual money, link or credential requests separately.")
    else:
        advice.insert(0, "🛡️ No strong combined-risk pattern was detected from the readable screenshot evidence. This does not prove the account is genuine; verify unexpected requests before acting.")

    if "credentials" in categories:
        advice.append("Never share an OTP, password, PIN or verification code with a person who contacts you through social media.")
    if "payment" in categories:
        advice.append("Do not send money or make an advance payment until the recipient and reason for payment are independently verified.")
    if "phishing" in categories or "links" in categories:
        advice.append("Do not click the visible suspicious link. Open the official website/app yourself instead.")
    if "off_platform" in categories:
        advice.append("Do not move to WhatsApp/Telegram/private chat solely because an unknown account asks you to.")
    if "impersonation" in categories:
        advice.append("Verify the claimed person, company or support team using a known official website or app, not the contact details shown in the screenshot.")
    if "romance_money" in categories:
        advice.append("Do not send gifts, gift cards, crypto or emergency money based only on an online relationship story.")
    return list(dict.fromkeys(str(x) for x in advice if str(x).strip()))


def scan_screenshot(file_or_filename):
    if not hasattr(file_or_filename, "read"):
        return {"score": 0, "level": "LOW", "summary": "The screenshot content was not available. Filename-only analysis is not sufficient.", "reasons": ["Actual screenshot content was not provided."], "actions": ["Upload the actual social-media screenshot for content analysis."], "invalid": False, "social_analysis": {"platform": "Unknown", "evidence_quality": "Insufficient"}}

    image_bytes = _read_uploaded_image(file_or_filename)
    if not image_bytes:
        return {"score": 0, "level": "LOW", "summary": "The uploaded screenshot could not be read. No authenticity verdict was made.", "reasons": ["The screenshot file is empty, unreadable, or too large."], "actions": ["Upload a clear PNG, JPG or WEBP screenshot."], "invalid": False, "social_analysis": {"platform": "Unknown", "evidence_quality": "Insufficient"}}

    ocr_text = _extract_local_ocr(image_bytes)
    if not ocr_text:
        error = globals().get("_SOCIAL_OCR_LAST_ERROR", "")
        reason = "OCR service could not extract readable text from the screenshot."
        action_list = ["Upload a clear screenshot with readable text and try again."]
        if error:
            reason = error
            if "API_KEY" in error:
                action_list.insert(0, "Set the OCR_SPACE_API_KEY environment variable in Render and redeploy.")
            elif "HTTP 403" in error or "HTTP 401" in error:
                action_list.insert(0, "Check that OCR_SPACE_API_KEY in Render is valid and active.")
            elif "1 MB" in error.lower() or "size" in error.lower():
                action_list.insert(0, "Try a smaller screenshot; SENTINEL also compresses uploads automatically.")
        return {"score": 0, "level": "LOW", "summary": "Insufficient evidence. No authenticity verdict was made because the screenshot text could not be reliably extracted.", "reasons": [reason], "actions": list(dict.fromkeys(action_list)), "invalid": False, "confidence": "Insufficient", "evidence_quality": "Insufficient", "social_analysis": {"platform": "Unknown", "evidence_quality": "Insufficient", "visible_text": ""}, "analysis_engine": "OCR.space text extraction + SENTINEL deterministic multi-factor rules"}

    profile_numbers = _extract_profile_numbers(ocr_text)
    analysis = {
        "platform": _detect_platform(ocr_text),
        "evidence_quality": "High" if len(ocr_text) >= 120 else "Medium",
        "visible_text": ocr_text,
        "profile": profile_numbers,
        "signals": [],
        "scam_types": [],
        "risk_adjustments": {"positive": [], "negative": []},
        "summary": "Local OCR extracted screenshot-visible text and the rule engine evaluated multiple security factors.",
        "advice": []
    }

    # Text-level hints for common platform/profile labels.
    low = _normalise_social_text(ocr_text)
    analysis["profile"]["verified_badge"] = bool(re.search(r"verified|officially verified", low))
    analysis["profile"]["new_badge"] = bool(re.search(r"\bnew\b", low))
    analysis["profile"]["fan_or_parody_label"] = bool(re.search(r"fan page|fan account|parody|unofficial|commentary", low))
    analysis["profile"]["official_claim"] = bool(re.search(r"\bofficial\b", low))
    analysis["profile"]["default_profile_image"] = bool(re.search(r"default profile|no profile picture", low))

    score, reasons, analysis = _social_score(analysis)
    quality = analysis.get("evidence_quality", "Insufficient")
    level = risk_level(score)

    if analysis["profile"].get("verified_badge") and score < 35:
        summary = "🔵 Verified Profile Detected — the screenshot contains a visible verification/official signal. This is a positive signal, not an absolute guarantee."
    elif score >= 80:
        summary = "🚨 Critical-risk activity detected from multiple screenshot-visible signals. Do not proceed with the suspicious activity shown."
    elif score >= 60:
        summary = "⚠️ High-risk activity detected from several combined screenshot-visible signals. Independent verification is required before any action."
    elif score >= 35:
        summary = "⚠️ Suspicious indicators were detected from the screenshot. The screenshot alone does not prove the account is fake, but caution is strongly recommended."
    else:
        summary = "🛡️ No strong combined-risk pattern was detected from the readable screenshot evidence. This does not prove that the account is genuine."

    result = make_result(score, reasons)
    result["summary"] = summary
    result["actions"] = _social_advice(score, analysis)
    result["confidence"] = quality
    result["evidence_quality"] = quality
    result["social_analysis"] = analysis
    result["platform"] = analysis.get("platform", "Unknown")
    result["scam_types"] = analysis.get("scam_types", [])
    result["analysis_engine"] = "Local OCR + deterministic multi-factor rules (API-free)"
    return result



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
@app.route("/analyze-social-screenshot", methods=["POST"])
def analyze_screenshot():
    file = request.files.get("screenshot")

    if not file:
        return jsonify({
            "error": "No screenshot uploaded."
        }), 400

    return jsonify(
        scan_screenshot(file)
    )


# =========================================================
# AI CHAT
# =========================================================

@app.route("/chat", methods=["POST"])
@app.route("/api/ai-chat", methods=["POST"])
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
