def is_valid_url_input(value):
    value = str(value or "").strip()

    if not value:
        return False, None, "Please enter a website URL."

    if any(ch.isspace() for ch in value):
        return False, None, "Invalid URL. Please enter a valid website address."

    candidate = value

    if not re.match(r"^https?://", candidate, re.I):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ("http", "https"):
        return False, None, "Invalid URL. Only HTTP or HTTPS website URLs are supported."

    if not parsed.netloc or not parsed.hostname:
        return False, None, "Invalid URL. Please enter a valid website address."

    host = parsed.hostname.lower().rstrip(".")

    if host in {"localhost", "localhost.localdomain"}:
        return False, None, "Invalid URL. Please enter a public website domain."

    if "." not in host:
        return False, None, (
            "Invalid URL. Please enter a complete website domain, "
            "such as example.com."
        )

    if len(host) > 253:
        return False, None, "Invalid URL. The domain name is too long."

    labels = host.split(".")

    if any(not label or len(label) > 63 for label in labels):
        return False, None, "Invalid URL. The domain format is not valid."

    for label in labels:
        if (
            not re.fullmatch(r"[a-z0-9-]+", label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            return False, None, "Invalid URL. The domain format is not valid."

    tld = labels[-1]

    if len(tld) < 2 or not re.fullmatch(r"[a-z]{2,63}", tld, re.I):
        return False, None, "Invalid URL. Please enter a valid website domain."

    return True, candidate, None


def scan_url(url):
    valid, url, error = is_valid_url_input(url)

    if not valid:
        return {
            "invalid": True,
            "error": error,
            "message": error
        }

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    score = 0
    reasons = []

    if parsed.scheme.lower() != "https":
        score += 20
        reasons.append("The website does not use HTTPS.")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 30
        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    if len(url) > 100:
        score += 15
        reasons.append("The URL is unusually long.")

    if "@" in url:
        score += 20
        reasons.append(
            "The URL contains an @ symbol, which can be used for deception."
        )

    if "xn--" in host:
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
        word
        for word in suspicious_words
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            url.lower()
        )
    ]

    if found_words:
        score += min(25, len(found_words) * 5)

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words[:5])
        )

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

        if brand in host:

            is_official = any(
                host == domain
                or host.endswith("." + domain)
                for domain in official_domains
            )

            if not is_official:
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
        reasons.append(
            "No major suspicious URL indicators were detected."
        )

    return make_result(score, reasons)
