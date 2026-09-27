from urllib.parse import urlparse


# ============================================================
# PHISHGUARD - 48 CATEGORY URL CLASSIFIER
# ============================================================

CATEGORY_KEYWORDS = {

    # 1
    "Banking & Financial Services": [
        "bank", "banking", "finance", "financial", "credit",
        "debit", "loan", "mortgage", "bankofamerica",
        "chase", "wellsfargo", "hsbc", "barclays",
        "icicibank", "hdfcbank", "sbi", "axisbank"
    ],

    # 2
    "Payment & Digital Wallets": [
        "paypal", "paytm", "phonepe", "googlepay", "gpay",
        "stripe", "razorpay", "venmo", "cashapp",
        "wallet", "payment", "payments", "upi"
    ],

    # 3
    "Cryptocurrency & Web3": [
        "crypto", "bitcoin", "ethereum", "blockchain",
        "web3", "binance", "coinbase", "kraken",
        "metamask", "nft", "defi", "token"
    ],

    # 4
    "Shopping & E-commerce": [
        "shop", "shopping", "store", "amazon", "flipkart",
        "ebay", "walmart", "myntra", "etsy", "product",
        "seller", "buy", "cart", "checkout"
    ],

    # 5
    "Social Media": [
        "facebook", "instagram", "twitter", "x.com",
        "linkedin", "pinterest", "snapchat", "tiktok",
        "social"
    ],

    # 6
    "Email & Communication": [
        "mail", "email", "gmail", "outlook", "proton",
        "communication", "message", "chat",
        "messenger", "telegram", "whatsapp"
    ],

    # 7
    "Login / Authentication": [
        "login", "signin", "sign-in", "signup", "sign-up",
        "authenticate", "authentication", "account",
        "password", "verify", "verification", "oauth"
    ],

    # 8
    "Education & Learning": [
        "edu", "education", "school", "college", "university",
        "course", "courses", "learning", "academy", "tutorial",
        "study", "exam", "student", "training",
        "coursera", "udemy", "edx", "khan",
        "learning"
    ],

    # 9
    "Government & Public Services": [
        ".gov", "government", "gov", "ministry",
        "municipality", "india.gov", "publicservice",
        "passport", "tax", "visa"
    ],

    # 10
    "Healthcare & Medical": [
        "health", "hospital", "clinic", "medical",
        "doctor", "medicine", "pharmacy", "healthcare",
        "dental", "patient", "wellness"
    ],

    # 11
    "Entertainment": [
        "movie", "movies", "film", "music", "spotify",
        "netflix", "cinema", "entertainment", "celebrity"
    ],

    # 12
    "News & Media": [
        "news", "times", "daily", "journal", "media",
        "newspaper", "bbc", "cnn", "reuters", "article"
    ],

    # 13
    "Technology & Software": [
        "tech", "technology", "software", "hardware",
        "microsoft", "apple", "android", "windows",
        "computer"
    ],

    # 14
    "Cloud & Online Storage": [
        "cloud", "drive", "dropbox", "onedrive",
        "storage", "icloud", "box"
    ],

    # 15
    "Business & Corporate": [
        "business", "company", "corporate", "enterprise",
        "consulting", "organization", "office", "firm"
    ],

    # 16
    "Jobs & Careers": [
        "job", "jobs", "career", "careers", "hiring",
        "recruitment", "resume", "employment", "work",
        "indeed", "glassdoor"
    ],

    # 17
    "Travel & Transportation": [
        "travel", "hotel", "booking", "airline", "flight",
        "airport", "uber", "ola", "taxi", "train",
        "railway", "transport", "trip"
    ],

    # 18
    "Food & Restaurants": [
        "food", "restaurant", "pizza", "burger",
        "delivery", "zomato", "swiggy", "menu",
        "cafe"
    ],

    # 19
    "Real Estate & Property": [
        "realestate", "real-estate", "property",
        "house", "home", "apartment", "rent",
        "estate"
    ],

    # 20
    "Sports & Fitness": [
        "sports", "sport", "football", "soccer",
        "cricket", "basketball", "tennis", "fitness",
        "gym", "running", "olympics"
    ],

    # 21
    "Adult Content": [
        "porn", "pornography", "xxx", "adult", "nsfw",
        "sex", "sexual", "erotic", "hentai",
        "nude", "nudity", "camgirl", "camgirls",
        "pornhub", "xhamster", "xvideos", "redtube",
        "youporn", "xnxx", "brazzers", "onlyfans"
    ],

    # 22
    "Dating & Relationships": [
        "dating", "date", "relationship", "love",
        "tinder", "bumble", "match", "grindr",
        "hinge", "romance"
    ],

    # 23
    "Forums & Communities": [
        "forum", "forums", "community", "communities",
        "discussion", "thread", "board"
    ],

    # 24
    "Gaming": [
        "game", "gaming", "steam", "epicgames", "xbox",
        "playstation", "twitch", "roblox", "minecraft",
        "esports", "ign"
    ],

    # 25
    "Streaming & Video": [
        "stream", "streaming", "video", "videos",
        "youtube", "twitch", "vimeo", "dailymotion"
    ],

    # 26
    "Shopping Deals / Coupons": [
        "coupon", "coupons", "deal", "deals",
        "discount", "offer", "offers", "promo",
        "promocode", "sale", "cashback"
    ],

    # 27
    "Investment & Trading": [
        "investment", "invest", "trading", "trader",
        "stock", "stocks", "forex", "broker",
        "tradingview", "market", "shares"
    ],

    # 28
    "Insurance": [
        "insurance", "insurer", "policy",
        "premium", "claim", "lifeinsurance",
        "healthinsurance", "carinsurance"
    ],

    # 29
    "Legal Services": [
        "legal", "law", "lawyer", "attorney",
        "court", "justice", "solicitor", "lawfirm"
    ],

    # 30
    "Religious / Spiritual": [
        "religion", "religious", "church", "temple",
        "mosque", "prayer", "bible", "quran",
        "spiritual", "faith"
    ],

    # 31
    "Charity & Donations": [
        "charity", "donate", "donation", "donations",
        "fundraiser", "fundraising", "ngo",
        "nonprofit", "non-profit"
    ],

    # 32
    "Personal Websites / Blogs": [
        "blog", "blogs", "personal", "portfolio",
        "wordpress", "blogger", "medium"
    ],

    # 33
    "Search Engines & Portals": [
        "google", "bing", "yahoo", "duckduckgo",
        "search", "portal"
    ],

    # 34
    "URL Shorteners": [
        "bit.ly", "tinyurl", "t.co", "goo.gl",
        "ow.ly", "shorturl", "is.gd", "buff.ly"
    ],

    # 35
    "File Sharing / Downloads": [
        "download", "downloads", "file", "files",
        "torrent", "upload", "sharefile",
        "fileshare", "archive", "zip"
    ],

    # 36
    "Developer / Programming": [
        "github", "gitlab", "bitbucket", "developer",
        "programming", "coding", "code", "api",
        "stackoverflow", "npm", "pypi", "dev"
    ],

    # 37
    "AI & Machine Learning": [
        "ai", "artificialintelligence", "machinelearning",
        "ml", "openai", "chatgpt", "gemini",
        "tensorflow", "pytorch", "huggingface"
    ],

    # 38
    "Cybersecurity": [
        "cybersecurity", "security", "infosec",
        "pentest", "pentesting", "hacking",
        "ethicalhacking", "malware", "soc",
        "threat", "vulnerability"
    ],

    # 39
    "VPN / Privacy Services": [
        "vpn", "privacy", "proxy", "tor",
        "anonymous", "securevpn", "nordvpn",
        "expressvpn"
    ],

    # 40
    "Hosting / Domain Services": [
        "hosting", "host", "domain", "domains",
        "dns", "server", "webhosting",
        "godaddy", "namecheap", "cloudflare"
    ],

    # 41
    "Advertising / Marketing": [
        "advertising", "ads", "advertisement",
        "marketing", "seo", "affiliate",
        "campaign", "agency"
    ],

    # 42
    "Dating / Social Networking": [
        "dating", "socialnetwork", "social-network",
        "friends", "friendship", "meetup"
    ],

    # 43
    "Reference / Knowledge": [
        "wikipedia", "encyclopedia", "reference",
        "dictionary", "knowledge", "definition",
        "wiki"
    ],

    # 44
    "Research / Scientific": [
        "research", "science", "scientific",
        "journal", "paper", "arxiv", "academic",
        "laboratory", "lab", "nature"
    ],

    # 45
    "Adult / Explicit": [
        "explicit", "xxx", "porn", "pornographic",
        "adultcontent", "adult-content", "nsfw",
        "sexvideo", "sexvideos", "xxxvideo"
    ],

    # 46
    "Malicious / Phishing": [
        "phishing", "malicious", "credential",
        "steal", "verify-account",
        "account-verification", "secure-login",
        "urgent-login", "confirm-account",
        "verify-now", "login-verification"
    ],

    # 47
    "Suspicious / Unknown": [
        "suspicious", "unknown", "urgent",
        "click-now", "claim-prize"
    ]
}


# ============================================================
# EXACT DOMAIN / BRAND RULES
# These have higher priority than normal keywords.
# ============================================================

DOMAIN_CATEGORIES = {

    # Banking
    "icicibank.com": "Banking & Financial Services",
    "hdfcbank.com": "Banking & Financial Services",
    "sbi.co.in": "Banking & Financial Services",
    "axisbank.com": "Banking & Financial Services",

    # Payment
    "paytm.com": "Payment & Digital Wallets",
    "phonepe.com": "Payment & Digital Wallets",
    "paypal.com": "Payment & Digital Wallets",
    "stripe.com": "Payment & Digital Wallets",

    # Cryptocurrency
    "coinbase.com": "Cryptocurrency & Web3",
    "binance.com": "Cryptocurrency & Web3",
    "kraken.com": "Cryptocurrency & Web3",

    # Shopping
    "amazon.in": "Shopping & E-commerce",
    "amazon.com": "Shopping & E-commerce",
    "flipkart.com": "Shopping & E-commerce",
    "ebay.com": "Shopping & E-commerce",
    "walmart.com": "Shopping & E-commerce",
    "myntra.com": "Shopping & E-commerce",

    # Social Media
    "facebook.com": "Social Media",
    "instagram.com": "Social Media",
    "twitter.com": "Social Media",
    "linkedin.com": "Social Media",
    "pinterest.com": "Social Media",
    "snapchat.com": "Social Media",
    "tiktok.com": "Social Media",

    # Forums
    "reddit.com": "Forums & Communities",

    # Email
    "gmail.com": "Email & Communication",
    "outlook.com": "Email & Communication",
    "proton.me": "Email & Communication",

    # Education
    "coursera.org": "Education & Learning",
    "udemy.com": "Education & Learning",
    "edx.org": "Education & Learning",
    "khanacademy.org": "Education & Learning",

    # Government
    "india.gov.in": "Government & Public Services",

    # Healthcare
    "mayoclinic.org": "Healthcare & Medical",

    # Entertainment
    "netflix.com": "Entertainment",
    "spotify.com": "Entertainment",

    # Streaming
    "youtube.com": "Streaming & Video",
    "vimeo.com": "Streaming & Video",

    # Technology
    "microsoft.com": "Technology & Software",
    "apple.com": "Technology & Software",

    # Cloud
    "dropbox.com": "Cloud & Online Storage",
    "onedrive.live.com": "Cloud & Online Storage",
    "drive.google.com": "Cloud & Online Storage",

    # Business
    "ibm.com": "Business & Corporate",

    # Jobs
    "indeed.com": "Jobs & Careers",
    "glassdoor.com": "Jobs & Careers",

    # Travel
    "booking.com": "Travel & Transportation",
    "uber.com": "Travel & Transportation",

    # Food
    "zomato.com": "Food & Restaurants",
    "swiggy.com": "Food & Restaurants",

    # Real Estate
    "zillow.com": "Real Estate & Property",

    # Sports
    "espn.com": "Sports & Fitness",

    # Adult
    "xhamster46.desi": "Adult Content",
    "xhamster.com": "Adult Content",
    "pornhub.com": "Adult Content",
    "xvideos.com": "Adult Content",
    "xnxx.com": "Adult Content",

    # Dating
    "tinder.com": "Dating & Relationships",
    "bumble.com": "Dating & Relationships",

    # Gaming
    "steampowered.com": "Gaming",
    "store.steampowered.com": "Gaming",
    "epicgames.com": "Gaming",
    "roblox.com": "Gaming",

    # Deals
    "retailmenot.com": "Shopping Deals / Coupons",

    # Investment
    "tradingview.com": "Investment & Trading",

    # Insurance
    "allstate.com": "Insurance",

    # Legal
    "legalzoom.com": "Legal Services",

    # Religious
    "bible.com": "Religious / Spiritual",

    # Charity
    "redcross.org": "Charity & Donations",

    # Blogs
    "wordpress.com": "Personal Websites / Blogs",
    "blogger.com": "Personal Websites / Blogs",

    # Search
    "google.com": "Search Engines & Portals",
    "bing.com": "Search Engines & Portals",
    "duckduckgo.com": "Search Engines & Portals",

    # URL Shorteners
    "bit.ly": "URL Shorteners",
    "tinyurl.com": "URL Shorteners",
    "t.co": "URL Shorteners",

    # File Sharing
    "mediafire.com": "File Sharing / Downloads",

    # Developer
    "github.com": "Developer / Programming",
    "gitlab.com": "Developer / Programming",
    "stackoverflow.com": "Developer / Programming",

    # AI
    "huggingface.co": "AI & Machine Learning",
    "openai.com": "AI & Machine Learning",

    # Cybersecurity
    "tryhackme.com": "Cybersecurity",

    # VPN
    "nordvpn.com": "VPN / Privacy Services",

    # Hosting
    "namecheap.com": "Hosting / Domain Services",
    "godaddy.com": "Hosting / Domain Services",
    "cloudflare.com": "Hosting / Domain Services",

    # Reference
    "wikipedia.org": "Reference / Knowledge",

    # Research
    "arxiv.org": "Research / Scientific"
}


# ============================================================
# SECURITY INDICATORS
# ============================================================

SECURITY_INDICATORS = [
    "phishing",
    "malicious",
    "credential",
    "steal",
    "verify-account",
    "account-verification",
    "secure-login",
    "urgent-login",
    "confirm-account",
    "verify-now",
    "login-verification"
]


# ============================================================
# CLASSIFIER
# ============================================================

def classify_url(url):
    """
    PhishGuard URL classification.

    Priority:
    1. Security indicators
    2. Exact known domain
    3. Keyword classification
    4. Other / Uncategorized
    """

    if not url:
        return {
            "category": "Other / Uncategorized",
            "confidence": 0.0,
            "matched_keywords": []
        }

    original_url = url.strip()

    parsed = urlparse(
        original_url
        if "://" in original_url
        else "https://" + original_url
    )

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    # Remove www.
    clean_hostname = hostname

    if clean_hostname.startswith("www."):
        clean_hostname = clean_hostname[4:]

    # Everything that can contain classification indicators
    searchable_text = f"{hostname} {path} {query}"

    # ========================================================
    # 1. SECURITY / MALICIOUS INDICATORS
    # ========================================================

    security_matches = []

    for indicator in SECURITY_INDICATORS:

        indicator = indicator.lower()

        if indicator in searchable_text:
            security_matches.append(indicator)

    if security_matches:

        return {
            "category": "Malicious / Phishing",
            "confidence": 90.0,
            "matched_keywords": security_matches
        }

    # ========================================================
    # 2. EXACT DOMAIN / BRAND MATCH
    # ========================================================

    for domain, category in DOMAIN_CATEGORIES.items():

        domain = domain.lower()

        if (
            clean_hostname == domain
            or clean_hostname.endswith("." + domain)
        ):

            return {
                "category": category,
                "confidence": 95.0,
                "matched_keywords": [domain]
            }

    # ========================================================
    # 3. KEYWORD CLASSIFICATION
    # ========================================================

    scores = {}

    for category, keywords in CATEGORY_KEYWORDS.items():

        score = 0
        matches = []

        for keyword in keywords:

            keyword = keyword.lower()

            if keyword in searchable_text:

                score += 1
                matches.append(keyword)

        if score > 0:

            scores[category] = {
                "score": score,
                "matches": matches
            }

    # ========================================================
    # 4. NO MATCH
    # ========================================================

    if not scores:

        return {
            "category": "Other / Uncategorized",
            "confidence": 0.0,
            "matched_keywords": []
        }

    # ========================================================
    # 5. BEST KEYWORD CATEGORY
    # ========================================================

    best_category = max(
        scores,
        key=lambda category: scores[category]["score"]
    )

    best_score = scores[best_category]["score"]

    confidence = min(
        85.0,
        50.0 + (best_score * 10.0)
    )

    return {
        "category": best_category,
        "confidence": round(confidence, 2),
        "matched_keywords": scores[best_category]["matches"]
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # Banking
        "https://www.icicibank.com",

        # Payment
        "https://paytm.com",

        # Crypto
        "https://www.coinbase.com",

        # Shopping
        "https://www.amazon.in",

        # Social
        "https://www.instagram.com",

        # Email
        "https://mail.google.com",

        # Login
        "https://accounts.google.com",

        # Education
        "https://www.coursera.org",

        # Government
        "https://www.india.gov.in",

        # Healthcare
        "https://www.mayoclinic.org",

        # Entertainment
        "https://www.netflix.com",

        # News
        "https://www.bbc.com",

        # Technology
        "https://www.microsoft.com",

        # Cloud
        "https://www.dropbox.com",

        # Business
        "https://www.ibm.com",

        # Jobs
        "https://www.indeed.com",

        # Travel
        "https://www.booking.com",

        # Food
        "https://www.zomato.com",

        # Real Estate
        "https://www.zillow.com",

        # Sports
        "https://www.espn.com",

        # Adult
        "https://www.xhamster46.desi",

        # Dating
        "https://www.tinder.com",

        # Forums
        "https://www.reddit.com",

        # Gaming
        "https://store.steampowered.com",

        # Streaming
        "https://www.youtube.com",

        # Deals
        "https://www.retailmenot.com",

        # Investment
        "https://www.tradingview.com",

        # Insurance
        "https://www.allstate.com",

        # Legal
        "https://www.legalzoom.com",

        # Religion
        "https://www.bible.com",

        # Charity
        "https://www.redcross.org",

        # Blog
        "https://wordpress.com",

        # Search
        "https://www.google.com",

        # URL shortener
        "https://bit.ly",

        # File sharing
        "https://www.mediafire.com",

        # Developer
        "https://github.com",

        # AI
        "https://huggingface.co",

        # Cybersecurity
        "https://tryhackme.com",

        # VPN
        "https://www.nordvpn.com",

        # Hosting
        "https://www.namecheap.com",

        # Reference
        "https://www.wikipedia.org",

        # Research
        "https://arxiv.org",

        # Malicious / Phishing test
        "http://example.com/verify-account",

        # Suspicious test
        "http://example.com/urgent",

        # Other
        "https://example.com"
    ]

    print("\n")
    print("=" * 70)
    print("PHISHGUARD URL CATEGORY CLASSIFIER")
    print("=" * 70)

    for url in test_urls:

        result = classify_url(url)

        print("\nURL        :", url)
        print("Category   :", result["category"])
        print("Confidence :", str(result["confidence"]) + "%")
        print("Matched    :", result["matched_keywords"])

    print("\n")
    print("=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
