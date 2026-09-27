from urllib.parse import urlparse, unquote
import ipaddress
import re


# =========================================================
# PHISHING URL ANALYZER - V2.7
# =========================================================


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "credential",
    "bank",
    "banking",
    "payment",
    "wallet",
    "confirm",
    "recover",
    "recovery",
    "unlock",
    "support",
    "webmail",
    "admin",
    "invoice",
    "refund",
    "bonus",
    "free",
    "prize",
    "urgent",
]


SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".zip",
    ".mov",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
]


URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
]


BRAND_NAMES = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "whatsapp",
    "dropbox",
    "outlook",
    "office365",
    "bank",
]


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def is_ip_address(hostname):
    """Check whether hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def get_registered_domain(hostname):
    """
    Basic registered-domain extraction.

    This intentionally avoids external dependencies.
    """

    if not hostname:
        return "Unknown"

    if is_ip_address(hostname):
        return "Unknown"

    parts = hostname.split(".")

    if len(parts) < 2:
        return "Unknown"

    # Handle common two-level country domains.
    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
    }

    last_two = ".".join(parts[-2:])

    if last_two in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def get_subdomain(hostname):
    """Return subdomain portion of a hostname."""

    if not hostname or is_ip_address(hostname):
        return None

    registered_domain = get_registered_domain(hostname)

    if registered_domain == "Unknown":
        return None

    if hostname == registered_domain:
        return None

    suffix = "." + registered_domain

    if hostname.endswith(suffix):
        subdomain = hostname[:-len(suffix)]

        if subdomain:
            return subdomain

    return None


def count_subdomains(hostname):
    """Count subdomain labels."""

    subdomain = get_subdomain(hostname)

    if not subdomain:
        return 0

    return len(subdomain.split("."))


def find_suspicious_keywords(url):
    """Find suspicious words appearing in the URL."""

    text = unquote(url).lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in text:
            found.append(keyword)

    return found


def count_special_characters(url):
    """
    Count characters commonly seen in suspicious URLs.

    The count focuses on characters beyond normal URL structure.
    """

    suspicious_chars = "@!$%^&*_=+{}[]|<>;'\"`"

    return sum(1 for char in url if char in suspicious_chars)


def detect_brand_like_name(hostname):
    """
    Detect brand names appearing in a hostname.

    This is only an indicator, not proof of impersonation.
    """

    if not hostname:
        return None

    hostname_lower = hostname.lower()

    for brand in BRAND_NAMES:

        if brand in hostname_lower:
            return brand

    return None


def has_punycode(hostname):
    """Detect internationalized domain Punycode."""

    if not hostname:
        return False

    return "xn--" in hostname.lower()


def has_url_encoding(url):
    """Detect percent-encoded characters."""

    return bool(re.search(r"%[0-9a-fA-F]{2}", url))


def is_url_shortener(hostname):
    """Check whether hostname belongs to a common URL shortener."""

    if not hostname:
        return False

    return hostname.lower() in URL_SHORTENERS


# =========================================================
# MAIN ANALYZER
# =========================================================

def analyze_url(url):

    # -----------------------------------------------------
    # Initial validation
    # -----------------------------------------------------

    if not url:
        return {
            "url": "",
            "scheme": "",
            "hostname": "",
            "path": "",
            "url_length": 0,
            "https_used": False,
            "is_ip": False,
            "registered_domain": "Unknown",
            "subdomain": None,
            "subdomain_count": 0,
            "found_keywords": [],
            "special_character_count": 0,
            "brand_detected": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "reasons": ["No URL was provided."]
        }


    original_url = url.strip()

    # -----------------------------------------------------
    # Add temporary scheme for parsing
    # -----------------------------------------------------

    parse_url = original_url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url
    ):
        parse_url = "http://" + parse_url


    parsed = urlparse(parse_url)

    scheme = parsed.scheme.lower()

    hostname = parsed.hostname or ""

    hostname = hostname.lower()

    path = parsed.path or ""

    url_length = len(original_url)


    # -----------------------------------------------------
    # Basic properties
    # -----------------------------------------------------

    https_used = scheme == "https"

    is_ip = is_ip_address(hostname)

    registered_domain = get_registered_domain(hostname)

    subdomain = get_subdomain(hostname)

    subdomain_count = count_subdomains(hostname)

    found_keywords = find_suspicious_keywords(original_url)

    special_character_count = count_special_characters(
        original_url
    )

    brand_detected = detect_brand_like_name(hostname)


    # -----------------------------------------------------
    # Risk scoring
    # -----------------------------------------------------

    risk_score = 0

    reasons = []


    # -----------------------------------------------------
    # 1. HTTPS
    # -----------------------------------------------------

    if not https_used:

        risk_score += 10

        reasons.append(
            "URL does not use HTTPS"
        )


    # -----------------------------------------------------
    # 2. IP address
    # -----------------------------------------------------

    if is_ip:

        risk_score += 25

        reasons.append(
            "Hostname is an IP address"
        )


    # -----------------------------------------------------
    # 3. Suspicious keywords
    # -----------------------------------------------------

    if len(found_keywords) >= 3:

        risk_score += 15

        reasons.append(
            "Multiple suspicious keywords detected"
        )

    elif len(found_keywords) > 0:

        risk_score += 5

        reasons.append(
            "Suspicious keyword detected"
        )


    # -----------------------------------------------------
    # 4. Long URL
    # -----------------------------------------------------

    if url_length > 200:

        risk_score += 10

        reasons.append(
            "URL is unusually long"
        )

    elif url_length > 100:

        risk_score += 5

        reasons.append(
            "URL is relatively long"
        )


    # -----------------------------------------------------
    # 5. @ symbol
    # -----------------------------------------------------

    if "@" in original_url:

        risk_score += 15

        reasons.append(
            "URL contains '@' symbol"
        )


    # -----------------------------------------------------
    # 6. Excessive subdomains
    # -----------------------------------------------------

    if subdomain_count >= 4:

        risk_score += 10

        reasons.append(
            "Hostname contains many subdomains"
        )

    elif subdomain_count >= 2:

        risk_score += 5

        reasons.append(
            "Hostname contains multiple subdomains"
        )


    # -----------------------------------------------------
    # 7. Hyphens
    # -----------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:

        risk_score += 8

        reasons.append(
            "Hostname contains several hyphens"
        )

    elif hyphen_count == 2:

        risk_score += 4

        reasons.append(
            "Hostname contains multiple hyphens"
        )


    # -----------------------------------------------------
    # 8. Punycode
    # -----------------------------------------------------

    if has_punycode(hostname):

        risk_score += 15

        reasons.append(
            "Hostname uses Punycode"
        )


    # -----------------------------------------------------
    # 9. Suspicious TLD
    # -----------------------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            risk_score += 10

            reasons.append(
                f"Potentially suspicious TLD detected: {tld}"
            )

            break


    # -----------------------------------------------------
    # 10. URL shortener
    # -----------------------------------------------------

    if is_url_shortener(hostname):

        risk_score += 10

        reasons.append(
            "URL uses a shortening service"
        )


    # -----------------------------------------------------
    # 11. Special characters
    # -----------------------------------------------------

    if special_character_count >= 4:

        risk_score += 10

        reasons.append(
            "URL contains several suspicious special characters"
        )

    elif special_character_count >= 2:

        risk_score += 5

        reasons.append(
            "URL contains suspicious special characters"
        )


    # -----------------------------------------------------
    # 12. URL encoding
    # -----------------------------------------------------

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            original_url
        )
    )

    if encoded_count >= 6:

        risk_score += 8

        reasons.append(
            "URL contains many encoded characters"
        )

    elif encoded_count >= 3:

        risk_score += 4

        reasons.append(
            "URL contains encoded characters"
        )


    # -----------------------------------------------------
    # 13. Digit-heavy hostname
    # -----------------------------------------------------

    if hostname and not is_ip:

        digit_count = sum(
            char.isdigit()
            for char in hostname
        )

        if digit_count >= 4:

            risk_score += 5

            reasons.append(
                "Hostname contains many numeric characters"
            )


    # -----------------------------------------------------
    # 14. Excessive dots
    # -----------------------------------------------------

    if hostname.count(".") >= 4:

        risk_score += 5

        reasons.append(
            "Hostname contains an unusually large number of dots"
        )


    # -----------------------------------------------------
    # 15. Brand-like hostname
    # -----------------------------------------------------

    if brand_detected:

        # Brand detection alone is not treated as proof.
        # It is only a supporting indicator.

        risk_score += 5

        reasons.append(
            f"Brand-like name detected: {brand_detected}"
        )


    # -----------------------------------------------------
    # Limit score to 100
    # -----------------------------------------------------

    risk_score = min(risk_score, 100)


    # -----------------------------------------------------
    # Risk classification
    # -----------------------------------------------------

    if risk_score >= 80:

        risk_level = "CRITICAL"

    elif risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 20:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # -----------------------------------------------------
    # No suspicious indicators
    # -----------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected"
        )


    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {

        "url": original_url,

        "scheme": scheme,

        "hostname": hostname,

        "path": path,

        "url_length": url_length,

        "https_used": https_used,

        "is_ip": is_ip,

        "registered_domain": registered_domain,

        "subdomain": subdomain,

        "subdomain_count": subdomain_count,

        "found_keywords": found_keywords,

        "special_character_count": special_character_count,

        "brand_detected": brand_detected,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "reasons": reasons
    }


# =========================================================
# COMMAND-LINE TEST
# =========================================================

def print_analysis(result):

    print()
    print("=" * 55)
    print("              PHISHING URL ANALYZER")
    print("=" * 55)

    print()

    print("--- URL INFORMATION ---")

    print(f"URL              : {result['url']}")
    print(f"Scheme           : {result['scheme']}")
    print(f"Hostname         : {result['hostname']}")
    print(f"Path             : {result['path']}")
    print(f"URL Length       : {result['url_length']}")

    print()

    print("--- SECURITY FEATURES ---")

    print(
        f"HTTPS            : "
        f"{'YES' if result['https_used'] else 'NO'}"
    )

    print(
        f"IP Address       : "
        f"{'YES' if result['is_ip'] else 'NO'}"
    )

    print()

    print("--- DOMAIN ANALYSIS ---")

    print(
        f"Registered Domain : "
        f"{result['registered_domain']}"
    )

    print(
        f"Subdomain         : "
        f"{result['subdomain'] or 'None'}"
    )

    print(
        f"Subdomain Count   : "
        f"{result['subdomain_count']}"
    )

    print(
        f"Suspicious Keywords: "
        f"{', '.join(result['found_keywords']) if result['found_keywords'] else 'None'}"
    )

    print(
        f"Special Characters: "
        f"{result['special_character_count']}"
    )

    print(
        f"Brand-like Name   : "
        f"{result['brand_detected'] or 'None'}"
    )

    print()

    print("=" * 55)
    print("                  RISK ANALYSIS")
    print("=" * 55)

    print()

    print(
        f"Risk Score : "
        f"{result['risk_score']}/100"
    )

    print(
        f"Risk Level : "
        f"{result['risk_level']}"
    )

    print()

    print("--- DETECTION REASONS ---")

    for reason in result["reasons"]:

        print(f"[!] {reason}")

    print()

    print("=" * 55)

    print(
        f"Result: {result['risk_level']} RISK"
    )

    print("=" * 55)

    print()

    print("NOTE:")
    print(
        "This is a rule-based educational analyzer."
    )

    print(
        "A high risk score does not prove that a URL is malicious."
    )

    print()


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("=" * 55)
    print("              PHISHING URL ANALYZER")
    print("=" * 55)

    url = input("Enter a URL: ").strip()

    result = analyze_url(url)

    print_analysis(result)
