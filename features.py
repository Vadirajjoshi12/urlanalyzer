from urllib.parse import urlparse
import math
import re

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "has_https",
    "num_subdomains",
    "contains_login",
    "contains_verify",
    "contains_secure",
    "contains_bank",
    "contains_account",
    "contains_update",
    "suspicious_tld",
    "entropy",
    "has_ip",
    "special_char_ratio"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".click"
]


def shannon_entropy(data):

    if not data:
        return 0

    entropy = 0

    try:

        for x in set(data):

            p_x = float(data.count(x)) / len(data)

            entropy += -p_x * math.log2(p_x)

    except:
        return 0

    return entropy


def has_ip_address(domain):

    ipv4_pattern = r"\d+\.\d+\.\d+\.\d+"

    ipv6_pattern = r"\[[0-9a-fA-F:]+\]"

    if re.search(ipv4_pattern, domain):
        return 1

    if re.search(ipv6_pattern, domain):
        return 1

    return 0


def extract_features(url, links=0, forms=0, iframes=0):

    try:

        if not isinstance(url, str):
            return [0] * len(FEATURE_COLUMNS)

        url = url.strip()

        if not url:
            return [0] * len(FEATURE_COLUMNS)

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        path = parsed.path.lower()

    except:
        return [0] * len(FEATURE_COLUMNS)

    try:

        url_length = len(url)

        domain_length = len(domain)

        path_length = len(path)

        num_dots = url.count(".")

        num_hyphens = url.count("-")

        num_digits = sum(c.isdigit() for c in url)

        has_https = 1 if url.startswith("https") else 0

        num_subdomains = max(0, domain.count(".") - 1)

        contains_login = 1 if "login" in url.lower() else 0

        contains_verify = 1 if "verify" in url.lower() else 0

        contains_secure = 1 if "secure" in url.lower() else 0

        contains_bank = 1 if "bank" in url.lower() else 0

        contains_account = 1 if "account" in url.lower() else 0

        contains_update = 1 if "update" in url.lower() else 0

        suspicious_tld = (
            1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS)
            else 0
        )

        entropy = shannon_entropy(url)

        has_ip = has_ip_address(domain)

        special_chars = sum(
            not c.isalnum()
            for c in url
        )

        special_char_ratio = (
            special_chars / max(1, len(url))
        )

        return [
            url_length,
            domain_length,
            path_length,
            num_dots,
            num_hyphens,
            num_digits,
            has_https,
            num_subdomains,
            contains_login,
            contains_verify,
            contains_secure,
            contains_bank,
            contains_account,
            contains_update,
            suspicious_tld,
            entropy,
            has_ip,
            special_char_ratio
        ]

    except:
        return [0] * len(FEATURE_COLUMNS)