from urllib.parse import urlparse
import ipaddress
import re


def is_ip_address(hostname):
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url):

    original_url = url.strip()

    parse_url = original_url

    if "://" not in parse_url:
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    features = {

        "url_length": len(original_url),

        "hostname_length": len(hostname),

        "path_length": len(path),

        "dot_count": original_url.count("."),

        "hyphen_count": original_url.count("-"),

        "slash_count": original_url.count("/"),

        "question_count": original_url.count("?"),

        "equal_count": original_url.count("="),

        "at_symbol": int("@" in original_url),

        "https": int(parsed.scheme.lower() == "https"),

        "is_ip": is_ip_address(hostname),

        "subdomain_count": max(
            len(hostname.split(".")) - 2,
            0
        ),

        "digit_count": sum(
            char.isdigit()
            for char in original_url
        ),

        "special_character_count": len(
            re.findall(
                r"[^a-zA-Z0-9./:_-]",
                original_url
            )
        ),

        "has_punycode": int(
            "xn--" in hostname.lower()
        ),

        "has_percent_encoding": int(
            bool(
                re.search(
                    r"%[0-9a-fA-F]{2}",
                    original_url
                )
            )
        ),

        "query_parameter_count": (
            len(parsed.query.split("&"))
            if parsed.query
            else 0
        ),
    }

    return features


if __name__ == "__main__":

    test_url = "http://192.168.1.10/login/verify-account"

    features = extract_features(test_url)

    print("=" * 50)
    print("V3.0 ML FEATURE EXTRACTION")
    print("=" * 50)

    print(f"\nURL: {test_url}\n")

    for name, value in features.items():

        print(f"{name:25}: {value}")
