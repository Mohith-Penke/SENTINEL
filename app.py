import os
import re
import ipaddress
import base64
import json
import hashlib
import subprocess
import tempfile
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

SOCIAL_VISION_PROMPT = r"""
You are SENTINEL Social Analyzer, a cybersecurity screenshot analyst.
Analyze the ACTUAL uploaded image, not the filename and not assumptions.
Only use information visibly present in the image. Do not identify a real person.

Your job is to inspect the whole screenshot and extract evidence from the TARGET
social-media profile/page/post shown. Ignore unrelated suggested accounts,
neighboring profiles, ads, and UI elements unless they clearly belong to the target.

Return ONLY valid JSON with exactly this general structure:
{
  "platform":"Instagram|Facebook|X|Unknown",
  "evidence_quality":"High|Medium|Low|Insufficient",
  "visible_text":"all clearly readable target text",
  "profile":{
    "username":"","display_name":"","bio":"",
    "followers":null,"following":null,"posts":null,
    "verified_badge":false,"new_badge":false,
    "fan_or_parody_label":false,"official_claim":false,
    "default_profile_image":false,"profile_image_present":false,
    "links":[]
  },
  "signals":[
    {"category":"","signal":"","severity":"low|medium|high","evidence":""}
  ],
  "scam_types":[],
  "risk_adjustments":{"positive":[],"negative":[]},
  "summary":"",
  "advice":[]
}

IMPORTANT RULES:
- Read the actual screenshot carefully. Different screenshots must produce different
  visible_text, profile evidence, signals and conclusions when their contents differ.
- A blue verified badge is positive verification evidence, NOT a guarantee that every
  post, message or request is safe.
- New badge, low followers, few posts, celebrity photo, generic photo or a new-looking
  account alone is NOT proof of fraud.
- Fan Page, Fan, Parody, Commentary or Unofficial labels reduce impersonation concern.
- A genuine/verified account can still be compromised or post a malicious offer.
- Never identify the real person in a photograph.
- Check profile identity, username, display name, bio, follower/following/post counts,
  verification indicators, labels, links and visible activity.
- Check visible content for giveaway/prize, romance, emergency, money, investment,
  crypto, jobs/tasks, shopping, donation, tickets, loans/grants, gambling, tech support,
  delivery, government/authority, credentials, OTP, KYC, payment, QR/UPI, urgency,
  threats, secrecy, off-platform contact, fake support and impersonation.
- Check visible URLs for shortened links, look-alike domains, typosquatting,
  unrelated domains and suspicious login/payment/registration destinations.
- A celebrity name/photo plus a money request, suspicious link or urgent claim can be
  an impersonation/compromise signal. The photo alone cannot establish fraud.
- Giveaway/job/investment/shopping/romance language alone does not prove a scam.
  Strong combinations should increase risk substantially.
- If information is cropped, blurred or unreadable, mark it unavailable instead of guessing.
"""

SOCIAL_ROOT_GROUPS = {
    "giveaway":{"words":["giveaway","give away","you won","winner","prize","lucky draw","free gift","reward","claim prize","claim now","congratulations","selected winner","iphone giveaway","free iphone","free phone","coupon","voucher","free ps5","free laptop"],"score":24,"type":"Giveaway / prize risk","tip":"Do not use or proceed with a prize claim that asks for money or sensitive information. Verify the giveaway through the brand's official source."},
    "romance":{"words":["love","lover","relationship","soulmate","boyfriend","girlfriend","fiancé","fiance","husband","wife","dating","romance","marry me","marriage","sweetheart","baby","darling","miss you","trust me","lonely","long distance"],"score":8,"type":"Romance / relationship risk","tip":"Do not send money, gifts, crypto or financial details to an online romantic contact without independent verification."},
    "romance_money":{"words":["send money","need money","borrow money","gift card","emergency","hospital","accident","stranded","help me financially","pay my bill","medical emergency","family emergency"],"score":34,"type":"Romance / emotional-money risk","tip":"Do not send money or gift cards because of an online relationship or emergency story. Verify independently first."},
    "investment":{"words":["investment","invest now","guaranteed return","guaranteed profit","guaranteed returns","profit","returns","double money","triple money","passive income","forex","trading signals","crypto","bitcoin","ethereum","usdt","mining","money flip","flip money","100% profit","risk free investment","no risk"],"score":34,"type":"Investment / financial risk","tip":"Do not transfer money or crypto based on guaranteed-profit claims. Verify the company and offer independently."},
    "job":{"words":["job offer","work from home","work-from-home","part time job","part-time","hiring","vacancy","recruitment","earn money","easy income","daily income","task job","online task","like and earn","review and earn","apply now","limited slots","training fee","registration fee","job registration","data entry"],"score":25,"type":"Job / task risk","tip":"Do not pay a registration, training or deposit fee to receive a job. Verify the employer independently."},
    "payment":{"words":["send money","pay now","payment","pay","processing fee","shipping fee","registration fee","advance fee","deposit","recharge","withdraw","unlock payment","upi","upi id","bank account","bank details","card number","credit card","debit card","cvv","gift card","payment link","qr code","scan qr","transfer money"],"score":38,"type":"Payment / financial risk","tip":"Do not send money or share UPI PIN, banking, card or payment credentials. Verify the recipient and request independently."},
    "credentials":{"words":["otp","one time password","verification code","password","passcode","pin","upi pin","login","sign in","username","credentials","kyc","verify account","account verification","verify your account","reset password","recover account","security code","authentication code","login details"],"score":48,"type":"Credential / phishing risk","tip":"Do not share OTPs, passwords, PINs or login codes. Open the official app/site yourself instead of using a suspicious link."},
    "phishing":{"words":["bit.ly","tinyurl","goo.gl","t.co/","shorturl","click here","click the link","login here","verify here","registration link","claim link","download now","open this link","tap here","link in bio"],"score":28,"type":"Suspicious link / phishing risk","tip":"Do not open an unfamiliar link. Check the exact destination domain independently before entering information."},
    "urgency":{"words":["urgent","immediately","act now","hurry","limited time","last chance","expires today","within 24 hours","don't wait","do it now","final warning","account will be blocked","account suspended","only today","claim fast"],"score":20,"type":"Social-engineering pressure","tip":"Do not let urgency force a decision. Pause and verify through an independent official channel."},
    "impersonation":{"words":["official","customer support","customer care","support team","admin","administrator","ceo","founder","police","government","bank support","instagram support","facebook support","x support","recovery team","account recovery","help center"],"score":22,"type":"Possible impersonation / fake-support risk","tip":"Verify the identity through the organization's official website or app. Do not trust a support claim just because the profile looks official."},
    "shopping":{"words":["huge discount","massive discount","clearance sale","limited stock","only today","cheap price","lowest price","50% off","70% off","90% off","brand new","pre order","advance payment","cash on delivery","mega sale","flash sale"],"score":22,"type":"Shopping / fake-store risk","tip":"Verify the seller, domain, reviews and payment method independently. Avoid advance payment to an unknown seller."},
    "donation":{"words":["donate","donation","fundraiser","medical emergency","medical help","relief fund","charity","help this family","help the child","crowdfunding"],"score":18,"type":"Donation / charity risk","tip":"Verify the charity or beneficiary independently before donating. Do not rely only on a social-media post or DM."},
    "tickets":{"words":["concert ticket","concert tickets","event ticket","vip pass","tickets available","booking","reservation","flight ticket","movie ticket","free ticket","sold out tickets"],"score":18,"type":"Ticket / event risk","tip":"Buy tickets only through official or trusted platforms. Avoid advance transfers to unknown accounts."},
    "loan_grant":{"words":["instant loan","easy loan","loan approved","loan offer","grant","subsidy","financial aid","scholarship","government scheme","loan processing fee","loan fee"],"score":24,"type":"Loan / grant / financial-aid risk","tip":"Verify the lender or program through its official website. Never pay an unexpected fee to unlock a loan or grant."},
    "gambling":{"words":["jackpot","lottery","betting","bet now","casino","sports betting","guaranteed win","winning number","spin and win"],"score":24,"type":"Gambling / prize risk","tip":"Do not send money or personal information to claim winnings or guaranteed profits. Verify the service independently."},
    "tech_support":{"words":["virus detected","your account is hacked","device infected","technical support","remote access","anydesk","teamviewer","support number","call immediately","security alert"],"score":35,"type":"Tech-support scam risk","tip":"Do not install remote-access software or call an unexpected support number. Use the official support page instead."},
    "delivery":{"words":["parcel","package","courier","delivery failed","customs fee","delivery fee","shipment","reschedule delivery","delivery charge"],"score":24,"type":"Delivery / parcel risk","tip":"Verify delivery messages through the courier's official website or app. Do not pay unexpected fees through social-media links."},
    "government":{"words":["income tax","tax notice","police notice","court notice","legal action","arrest warrant","aadhaar","pan card","government notice","fine","penalty"],"score":28,"type":"Authority impersonation risk","tip":"Do not pay or share credentials because of an unexpected authority claim. Contact the organization through an official channel."},
    "personal_data":{"words":["aadhaar number","pan number","date of birth","address","phone number","email address","bank details","card details","identity proof","id proof","passport","driving licence"],"score":18,"type":"Personal-data collection risk","tip":"Avoid sharing identity, banking or other sensitive personal information with an unverified account."},
    "off_platform":{"words":["whatsapp","telegram","dm me","message me privately","contact me privately","move to whatsapp","move to telegram","send me a dm","contact privately"],"score":12,"type":"Off-platform social-engineering signal","tip":"Be cautious when an unknown account quickly moves you to WhatsApp or Telegram. Verify the identity independently."},
    "secrecy_threat":{"words":["keep this secret","don't tell anyone","do not tell anyone","confidential","you will be arrested","police will arrest","account will be deleted","you will lose access","don't tell my family"],"score":28,"type":"Threat / secrecy social engineering","tip":"Do not act under threats or secrecy pressure. Stop and verify the claim independently."},
    "fake_news":{"words":["breaking news","shocking news","100% confirmed","viral news","share immediately","forward this","government confirmed","secret news","breaking"],"score":12,"type":"Potential misinformation / engagement bait","tip":"Verify sensational claims with reputable sources before sharing or acting on them."},
    "business_opportunity":{"words":["franchise","dealership","reseller","business opportunity","passive income","earn from home","investment opportunity","guaranteed business","be your own boss","distributor"],"score":20,"type":"Business-opportunity risk","tip":"Verify the company, terms and financial claims independently. Avoid upfront payments for unverified opportunities."},
    "romance_offplatform":{"words":["whatsapp number","telegram id","private chat","secret relationship","don't tell my family"],"score":18,"type":"Romance social-engineering signal","tip":"Be cautious if an online relationship quickly becomes secretive or moves off-platform. Do not send money or sensitive information."}
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
    if len(data) > 12 * 1024 * 1024:
        return b""
    return data


def _image_mime(file):
    mime = str(getattr(file, "mimetype", "") or "").lower().strip()
    if mime in {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"}:
        return "image/jpeg" if mime == "image/jpg" else mime
    name = str(getattr(file, "filename", "") or "").lower()
    if name.endswith(".png"):
        return "image/png"
    if name.endswith(".webp"):
        return "image/webp"
    if name.endswith(".gif"):
        return "image/gif"
    return "image/jpeg"


def _extract_local_ocr(image_bytes):
    if not image_bytes:
        return ""
    try:
        from PIL import Image
        import pytesseract
        with Image.open(__import__("io").BytesIO(image_bytes)) as image:
            image = image.convert("RGB")
            return str(pytesseract.image_to_string(image) or "").strip()
    except Exception:
        return ""


def _vision_api_analysis(image_bytes, mime_type="image/jpeg"):
    """Analyze the actual uploaded screenshot with a vision-capable OpenAI model.

    This intentionally uses two API attempts: JSON mode first, then a plain-text
    JSON response fallback. That makes the analyzer resilient to model/endpoint
    differences while keeping the screenshot itself as the source of truth.
    """
    api_key = os.environ.get("SENTINEL_VISION_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key or not image_bytes:
        return None, "Vision API key or image data is unavailable."

    endpoint = os.environ.get("SENTINEL_VISION_API_URL", "https://api.openai.com/v1/chat/completions")
    configured_model = os.environ.get("SENTINEL_VISION_MODEL", "gpt-4o-mini").strip()
    models = [configured_model]
    # Safe fallback if a custom Render model name is invalid/unavailable.
    for fallback in ("gpt-4o-mini", "gpt-4.1-mini"):
        if fallback not in models:
            models.append(fallback)

    encoded = base64.b64encode(image_bytes).decode("ascii")
    data_url = "data:" + mime_type + ";base64," + encoded
    user_text = (
        "Analyze THIS uploaded screenshot itself. Do not use the filename and do not invent "
        "details that are not visible. Identify the platform/profile/page, visible text, "
        "verification/new/fan/parody labels, links, money/payment requests, credentials, "
        "urgency, impersonation, scam patterns, and evidence quality. Return ONLY valid JSON."
    )

    last_error = None
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    for model in models:
        for json_mode in (True, False):
            payload = {
                "model": model,
                "temperature": 0,
                "max_tokens": 4500,
                "messages": [
                    {"role": "system", "content": SOCIAL_VISION_PROMPT},
                    {"role": "user", "content": [
                        {"type": "text", "text": user_text},
                        {"type": "image_url", "image_url": {"url": data_url, "detail": "high"}}
                    ]}
                ]
            }
            if json_mode:
                payload["response_format"] = {"type": "json_object"}

            try:
                req = Request(
                    endpoint,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + api_key
                    },
                    method="POST"
                )
                with urlopen(req, timeout=75) as response:
                    raw = response.read().decode("utf-8")
                data = json.loads(raw)
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                if isinstance(content, list):
                    content = "".join(
                        part.get("text", "") for part in content if isinstance(part, dict)
                    )
                content = str(content or "").strip()
                content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content, flags=re.I).strip()
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    parsed["vision_model"] = model
                    parsed["vision_api"] = "OpenAI"
                    return parsed, None
                last_error = "Vision API returned a non-object JSON response."
            except HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8", errors="ignore")
                    err = json.loads(body).get("error", {}).get("message", body)
                except Exception:
                    err = str(exc)
                last_error = f"HTTP {exc.code}: {str(err)[:220]}"
                # Try the next compatible mode/model rather than failing immediately.
            except URLError as exc:
                last_error = "Network error reaching Vision API: " + str(exc.reason)[:180]
            except Exception as exc:
                last_error = "Vision API parse/request error: " + str(exc).strip().replace("\n", " ")[:200]

    return None, (last_error or "Vision API analysis failed.")


def _normalise_social_analysis(data):
    if not isinstance(data, dict):
        data = {}
    data.setdefault("platform", "Unknown")
    data.setdefault("evidence_quality", "Insufficient")
    data.setdefault("visible_text", "")
    data.setdefault("profile", {})
    data.setdefault("signals", [])
    data.setdefault("scam_types", [])
    data.setdefault("risk_adjustments", {})
    data.setdefault("summary", "")
    data.setdefault("advice", [])

    if not isinstance(data["profile"], dict):
        data["profile"] = {}
    p = data["profile"]
    for key in ["username", "display_name", "bio", "links"]:
        p.setdefault(key, "" if key != "links" else [])
    for key in ["followers", "following", "posts"]:
        p.setdefault(key, None)
    for key in ["verified_badge", "new_badge", "fan_or_parody_label", "official_claim", "default_profile_image", "profile_image_present"]:
        p.setdefault(key, False)

    if not isinstance(data["signals"], list):
        data["signals"] = []
    if not isinstance(data["scam_types"], list):
        data["scam_types"] = []
    if not isinstance(data["risk_adjustments"], dict):
        data["risk_adjustments"] = {}
    data["risk_adjustments"].setdefault("positive", [])
    data["risk_adjustments"].setdefault("negative", [])
    if not isinstance(data["advice"], list):
        data["advice"] = []
    return data


def _social_visible_text(analysis):
    p = analysis.get("profile", {})
    parts = [
        analysis.get("visible_text", ""),
        p.get("username", ""),
        p.get("display_name", ""),
        p.get("bio", "")
    ]
    links = p.get("links", [])
    if isinstance(links, list):
        parts.extend(str(x) for x in links)
    else:
        parts.append(str(links))
    for item in analysis.get("signals", []):
        if isinstance(item, dict):
            parts.extend([item.get("signal", ""), item.get("evidence", "")])
    return " ".join(str(x) for x in parts if x).lower()


def _add_social_signal(signals, category, signal, severity, evidence):
    signals.append({
        "category": category,
        "signal": signal,
        "severity": severity,
        "evidence": evidence
    })


def _keyword_hits(text, words):
    hits = []
    for word in words:
        w = str(word).lower().strip()
        if not w:
            continue
        pattern = r"(?<![a-z0-9])" + r"\s+".join(re.escape(x) for x in re.split(r"\s+", w)) + r"(?![a-z0-9])"
        if re.search(pattern, text, re.I):
            hits.append(word)
    return hits


def _extract_profile_numbers(text):
    text = str(text or "")
    result = {"followers": None, "following": None, "posts": None}
    patterns = {
        "followers": [r"([\d,.]+)\s*(?:followers|follower)\b"],
        "following": [r"([\d,.]+)\s*(?:following)\b"],
        "posts": [r"([\d,.]+)\s*(?:posts|post)\b"]
    }
    for field, pats in patterns.items():
        for pattern in pats:
            m = re.search(pattern, text, re.I)
            if m:
                try:
                    result[field] = int(float(m.group(1).replace(",", "")))
                    break
                except ValueError:
                    pass
    return result


def _apply_root_intelligence(analysis):
    analysis = _normalise_social_analysis(analysis)
    text = _social_visible_text(analysis)
    signals = [x for x in analysis.get("signals", []) if isinstance(x, dict)]
    scam_types = list(analysis.get("scam_types", []))
    advice = list(analysis.get("advice", []))
    positive = list(analysis.get("risk_adjustments", {}).get("positive", []))
    negative = list(analysis.get("risk_adjustments", {}).get("negative", []))
    detected = {}

    for category, info in SOCIAL_ROOT_GROUPS.items():
        hits = _keyword_hits(text, info["words"])
        if hits:
            detected[category] = hits
            severity = "high" if info["score"] >= 32 else ("medium" if info["score"] >= 18 else "low")
            _add_social_signal(signals, category, info["type"], severity, "Visible screenshot signals: " + ", ".join(hits[:8]))
            if info["type"] not in scam_types:
                scam_types.append(info["type"])
            advice.append(info["tip"])

    combo_rules = [
        ({"romance", "romance_money"}, 30, "Romance + money/emergency request", "Relationship/emotional language is combined with a financial or emergency request."),
        ({"romance", "off_platform"}, 14, "Romance + off-platform contact", "Relationship language is combined with a private/off-platform contact request."),
        ({"giveaway", "payment"}, 30, "Giveaway + payment request", "A prize/giveaway is combined with a payment or fee request."),
        ({"giveaway", "credentials"}, 38, "Giveaway + credential request", "A prize/giveaway is combined with OTP/password/account-verification language."),
        ({"giveaway", "phishing"}, 28, "Giveaway + suspicious link", "A prize/giveaway is combined with a link or claim instruction."),
        ({"job", "payment"}, 32, "Job + fee/payment request", "Employment/task language is combined with a fee or payment request."),
        ({"investment", "payment"}, 30, "Investment + payment request", "Investment language is combined with a request to transfer money or pay."),
        ({"investment", "off_platform"}, 15, "Investment + private contact", "Investment language is combined with off-platform communication."),
        ({"impersonation", "credentials"}, 32, "Impersonation + credentials", "A support/authority identity is combined with credential or verification requests."),
        ({"impersonation", "payment"}, 34, "Impersonation + payment", "A support/authority identity is combined with a financial request."),
        ({"impersonation", "phishing"}, 28, "Impersonation + suspicious link", "A support/authority identity is combined with a suspicious login/link request."),
        ({"shopping", "payment"}, 24, "Shopping + payment", "A shopping offer is combined with an advance/payment request."),
        ({"delivery", "payment"}, 28, "Delivery + payment", "A parcel/delivery claim is combined with a fee/payment request."),
        ({"government", "payment"}, 34, "Authority + payment", "An authority/legal claim is combined with a financial request."),
        ({"government", "credentials"}, 34, "Authority + credentials", "An authority claim is combined with identity/login information requests."),
        ({"secrecy_threat", "payment"}, 28, "Threat + payment", "Threat/secrecy language is combined with a financial request."),
        ({"tech_support", "credentials"}, 32, "Tech support + credentials", "Support language is combined with security/login information requests."),
        ({"loan_grant", "payment"}, 28, "Loan/grant + fee", "A loan/grant offer is combined with a fee/payment request.")
    ]
    for needed, points, label, evidence in combo_rules:
        if needed.issubset(detected):
            _add_social_signal(signals, "combined_risk", label, "high", evidence)
            if label not in scam_types:
                scam_types.append(label)
            advice.append("Do not use or proceed with this activity until the identity, offer and request are independently verified.")

    links = analysis.get("profile", {}).get("links", [])
    if not isinstance(links, list):
        links = [links]
    link_text = " ".join(str(x) for x in links).lower()
    if link_text:
        if re.search(r"bit\.ly|tinyurl|t\.co/|goo\.gl|shorturl", link_text):
            _add_social_signal(signals, "links", "Shortened URL", "high", "A shortened URL is visible in the target profile evidence.")
            advice.append("Do not open a shortened link from an unknown account; verify the destination independently.")
        if any(x in link_text for x in (".top", ".click", ".xyz", ".win", ".vip", ".live")):
            _add_social_signal(signals, "links", "Potentially suspicious domain pattern", "medium", "A visible link uses a domain pattern that deserves independent verification.")
            advice.append("Verify the exact domain independently before opening it or entering information.")

    p = analysis.get("profile", {})
    numbers = _extract_profile_numbers(text)
    for key in ("followers", "following", "posts"):
        if p.get(key) is None and numbers.get(key) is not None:
            p[key] = numbers[key]
    if p.get("posts") == 0:
        _add_social_signal(signals, "activity", "Zero posts visible", "low", "The target profile visibly shows 0 posts.")
    if isinstance(p.get("followers"), int) and isinstance(p.get("following"), int) and p["followers"] < 20 and p["following"] > 100:
        _add_social_signal(signals, "account_authenticity", "Unusual follower/following relationship", "low", "The visible follower count is much lower than the following count.")
    if p.get("new_badge"):
        _add_social_signal(signals, "account_authenticity", "New-account indicator", "low", "A New indicator is visibly associated with the target profile.")
    if p.get("default_profile_image"):
        _add_social_signal(signals, "account_authenticity", "Default/generic profile image", "low", "The target profile visibly uses a default or generic profile image.")
    if p.get("fan_or_parody_label"):
        negative.append("Fan/parody/unofficial labeling reduces impersonation concern.")
    if p.get("verified_badge"):
        positive.append("A verified/blue badge is visibly present on the target profile.")

    analysis["signals"] = signals
    analysis["scam_types"] = list(dict.fromkeys(scam_types))
    analysis["advice"] = list(dict.fromkeys(advice))
    analysis["risk_adjustments"]["positive"] = list(dict.fromkeys(positive))
    analysis["risk_adjustments"]["negative"] = list(dict.fromkeys(negative))
    return analysis


def _social_score(analysis):
    analysis = _apply_root_intelligence(analysis)
    p = analysis.get("profile", {})
    signals = analysis.get("signals", [])
    categories = {}
    reasons = []
    for item in signals:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("category", "general")).lower()
        sev = str(item.get("severity", "low")).lower()
        pts = {"low": 4, "medium": 13, "high": 25}.get(sev, 4)
        categories[cat] = max(categories.get(cat, 0), pts)
        signal = str(item.get("signal", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        if signal:
            reasons.append(signal + (": " + evidence if evidence else ""))

    score = sum(categories.values())
    if p.get("posts") == 0:
        score += 3
    if p.get("new_badge"):
        score += 2
    if p.get("default_profile_image"):
        score += 3
    followers, following = p.get("followers"), p.get("following")
    if isinstance(followers, int) and isinstance(following, int) and followers < 20 and following > 100:
        score += 3
    if p.get("verified_badge"):
        score = max(0, score - 8)
        reasons.append("A visible verified badge is a positive verification signal; it does not make suspicious requests safe.")
    if p.get("fan_or_parody_label"):
        score = max(0, score - 5)
        reasons.append("A visible fan/parody/unofficial label reduces impersonation concern.")

    strong = set(categories)
    if {"credentials", "phishing"}.issubset(strong): score += 18
    if {"payment", "urgency"}.issubset(strong): score += 15
    if {"impersonation", "payment"}.issubset(strong): score += 15
    if {"romance", "romance_money"}.issubset(strong): score += 18
    hard_categories = {"credentials", "payment", "investment", "romance_money", "tech_support", "government"}
    if strong.intersection(hard_categories): score = max(score, 55)
    if {"credentials", "payment"}.issubset(strong) or {"giveaway", "credentials"}.issubset(strong): score = max(score, 75)
    if strong and strong.issubset({"activity", "account_authenticity"}): score = min(score, 28)
    return min(100, int(score)), list(dict.fromkeys(reasons)), analysis


def _social_advice(score, analysis):
    advice = list(analysis.get("advice", []))
    p = analysis.get("profile", {})
    if score >= 80:
        advice.insert(0, "🚫 Do not use, click, pay, reply to, or provide sensitive information to the suspicious activity shown in this screenshot. Verify through an official/trusted source first.")
    elif score >= 60:
        advice.insert(0, "⚠️ Do not proceed with the suspicious activity shown until the account, link and request are independently verified.")
    elif score >= 35:
        advice.insert(0, "🛡️ Be cautious with the activity shown. Verify the account and request independently before sharing information, clicking links or sending money.")
    elif p.get("verified_badge"):
        advice.insert(0, "🔵 The profile appears verified based on the visible badge. Still verify any unusual money, link or credential request separately.")
    else:
        advice.insert(0, "🛡️ No major combined-risk pattern was detected from the visible screenshot evidence. Still verify unexpected requests before sharing sensitive information.")
    return list(dict.fromkeys(str(x) for x in advice if str(x).strip()))


def scan_screenshot(file_or_filename):
    if not hasattr(file_or_filename, "read"):
        return {"score":0,"level":"LOW","summary":"The screenshot content was not available. Filename-only analysis is not sufficient.","reasons":["Actual screenshot content was not provided."],"actions":["Upload the actual social-media screenshot for content analysis."],"invalid":False,"social_analysis":{"platform":"Unknown","evidence_quality":"Insufficient"}}

    image_bytes = _read_uploaded_image(file_or_filename)
    if not image_bytes:
        return {"score":0,"level":"LOW","summary":"The uploaded screenshot could not be read. No authenticity verdict was made.","reasons":["The screenshot file is empty, unreadable, or too large."],"actions":["Upload a clear PNG, JPG or WEBP screenshot."],"social_analysis":{"platform":"Unknown","evidence_quality":"Insufficient"}}

    analysis, api_error = _vision_api_analysis(image_bytes, _image_mime(file_or_filename))
    ocr_text = ""
    if analysis is None:
        ocr_text = _extract_local_ocr(image_bytes)
        analysis = {
            "platform":"Unknown",
            "evidence_quality":"Low" if ocr_text else "Insufficient",
            "visible_text":ocr_text,
            "profile":_extract_profile_numbers(ocr_text),
            "signals":[],"scam_types":[],
            "risk_adjustments":{"positive":[],"negative":[]},
            "summary":"OCR-visible screenshot text was analyzed." if ocr_text else "The Vision API could not analyze this screenshot.",
            "advice":[]
        }
        if api_error:
            analysis["api_status"] = api_error
        low = ocr_text.lower()
        if "instagram" in low: analysis["platform"] = "Instagram"
        elif "facebook" in low: analysis["platform"] = "Facebook"
        elif "twitter" in low: analysis["platform"] = "X"

    analysis = _normalise_social_analysis(analysis)
    score, reasons, analysis = _social_score(analysis)
    quality = str(analysis.get("evidence_quality", "Insufficient"))

    if quality == "Insufficient":
        score = 0
        summary = "Insufficient evidence. The screenshot could not be reliably analyzed, so SENTINEL will not guess whether the profile is genuine or fake."
        if analysis.get("api_status"):
            reasons = [analysis["api_status"]]
    else:
        if analysis.get("profile", {}).get("verified_badge") and score < 35:
            summary = "🔵 Verified Profile Detected — the profile appears verified based on the visible verification badge."
        elif score >= 80:
            summary = "🚨 High-risk activity detected from multiple screenshot-visible signals. Do not proceed with the suspicious activity shown."
        elif score >= 60:
            summary = "⚠️ Several strong warning signals were detected from the screenshot. Independent verification is recommended before any action."
        elif score >= 35:
            summary = "⚠️ Some suspicious indicators were detected. The screenshot alone does not prove that the account is fake, but caution is recommended."
        else:
            summary = "No major combined-risk pattern was detected from the visible evidence. This does not prove that the account is genuine."

    final_actions = _social_advice(score, analysis)
    result = make_result(score, reasons)
    result["summary"] = summary
    result["actions"] = final_actions
    result["confidence"] = quality
    result["evidence_quality"] = quality
    result["social_analysis"] = analysis
    result["platform"] = analysis.get("platform", "Unknown")
    result["scam_types"] = analysis.get("scam_types", [])
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
