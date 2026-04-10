# -----------------------------
# Imports
# -----------------------------
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
from datetime import datetime
# -----------------------------
# Helper: Validate Domain
# -----------------------------
def is_valid_domain(domain):
    # Allow suspicious patterns for phishing detection
    return len(domain) > 3 and "." in domain

# -----------------------------
# App Initialization
# -----------------------------
app = Flask(__name__)
CORS(app)

# -----------------------------
# MongoDB Connection
# -----------------------------
client = MongoClient("mongodb+srv://admin:admin123@cluster0.pmrjoue.mongodb.net/?appName=Cluster0")
db = client["phishing_db"]
reports_collection = db["reports"]
scans_collection = db["scans"]

# -----------------------------
# Load ML Model
# -----------------------------
model = pickle.load(open("../ml_model/phishing_model.pkl", "rb"))

# -----------------------------
# Feature Order
# -----------------------------
FEATURE_ORDER = [
    'URLLength',
    'DomainLength',
    'NoOfSubDomain',
    'IsHTTPS',
    'NoOfDegitsInURL',
    'DegitRatioInURL',
    'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL'
]

# -----------------------------
# Trusted Sites
# -----------------------------
TRUSTED_SITES = [
    "google.com",
    "amazon.in",
    "amazon.com",
    "flipkart.com",
    "ebay.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "wikipedia.org",
    "meesho.com",
    "hp.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com",
    "twitter.com",
    "netflix.com"
]

# -----------------------------
# Feature Extraction
# -----------------------------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}

    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)
    features["IsHTTPS"] = 1 if url.startswith("https") else 0

    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)

    url_length = len(url) if len(url) > 0 else 1

    features["DegitRatioInURL"] = features["NoOfDegitsInURL"] / url_length

    # CORRECT POSITION
    features["NoOfOtherSpecialCharsInURL"] = len(re.findall(r"[^\w]", url))

    features["SpacialCharRatioInURL"] = features["NoOfOtherSpecialCharsInURL"] / url_length

    features["NoOfSubDomain"] = domain.count(".")

    return features

# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():
    return "Phishing Detection API Running"

# -----------------------------
# 🔍 Predict
# -----------------------------

@app.route("/predict", methods=["POST"])
def predict():
 try:
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL not provided"}), 400

    url = data["url"].strip().replace(" ", "")

    # -----------------------------
    # Normalize URL
    # -----------------------------
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")

    # -----------------------------
    # Invalid Domain Check
    # -----------------------------
    if not is_valid_domain(domain):
        return jsonify({
            "url": url,
            "result": "Invalid URL",
            "safety_score": 0,
            "https_secure": False,
            "secure_label": "Invalid URL",
            "reasons": ["Invalid domain format"]
        })

    # -----------------------------
    # HTTPS CHECK
    # -----------------------------
    is_https = url.startswith("https")

    # -----------------------------
    # Trusted Site Override
    # -----------------------------
    if any(domain == site or domain.endswith("." + site) for site in TRUSTED_SITES):

        result = "Safe"
        probability = 98.0
        reasons = ["Trusted domain"]
        secure_label = "Secure (Trusted)"

        scan_record = {
            "url": url,
            "domain": domain,
            "result": result,
            "score": probability,
            "https": is_https,
            "reasons": reasons,
            "timestamp": datetime.utcnow()
        }

        scans_collection.insert_one(scan_record)

        return jsonify({
            "url": url,
            "result": result,
            "safety_score": probability,
            "https_secure": is_https,
            "secure_label": secure_label,
            "confidence": 99.0,
            "reasons": reasons
        })

    # -----------------------------
    # Clean URL
    # -----------------------------
    clean_url = url.split("?")[0]

    # -----------------------------
    # Feature Extraction
    # -----------------------------
    features = extract_features(clean_url)

    features_df = pd.DataFrame(
        [[features[col] for col in FEATURE_ORDER]],
        columns=FEATURE_ORDER
    )

  # -----------------------------
    # ML Prediction (Separate)
    # -----------------------------
    ml_prob = model.predict_proba(features_df)[0][1]   # 0–1
    ml_score = ml_prob * 70   # ML contributes 70%

    # -----------------------------
    # Rule System (Separate)
    # -----------------------------
    reasons = []
    rule_penalty = 0
    rule_score = 30   # Rules contribute 30%

    # HTTPS
    if not is_https:
        rule_penalty += 10
        reasons.append("No HTTPS (Not Secure)")

    # Subdomains
    if features["NoOfSubDomain"] > 4:
        rule_penalty += 5
        reasons.append("Too many subdomains")

    # Digits
    if features["NoOfDegitsInURL"] > 8:
        rule_penalty += 5
        reasons.append("Too many digits in URL")

    # @ symbol
    if "@" in url:
        rule_penalty += 25
        reasons.append("Contains @ symbol")

    # Suspicious //
    if "//" in url[8:]:
        rule_penalty += 10
        reasons.append("Suspicious redirect (//)")

    # Hyphen
    if "-" in domain:
        rule_penalty += 5
        reasons.append("Hyphen in domain")

    # -----------------------------
    # Final Score Calculation
    # -----------------------------
    final_score = ml_score + (rule_score - rule_penalty)
    if len(domain) < 15 and "." in domain:
       final_score += 5

    
    probability = max(0, min(100, final_score))

  

    # -----------------------------
    # Final Decision
    # -----------------------------
    if probability >= 60:
        result = "Safe"
    elif 40 <= probability < 60:
        result = "Suspicious"
    else:
        result = "Phishing"

    # -----------------------------
    # Secure Label
    # -----------------------------
    secure_label = (
        "Secure (Trusted)" if is_https and result == "Safe"
        else "Encrypted but Risky" if is_https
        else "Not Secure"
    )

    # -----------------------------
    # sacn results
    # -----------------------------
    
    scan_record = {
        "url": url,
        "domain": domain,
        "result": result,
        "score": round(probability, 2),
        "https": is_https,
        "reasons": reasons,
        "timestamp": datetime.utcnow()
    }

    scans_collection.insert_one(scan_record)
    # -----------------------------
    # Final Response
    # -----------------------------
    return jsonify({
        "url": url,
        "result": result,
        "safety_score": round(probability, 2),
        "https_secure": is_https,
        "secure_label": secure_label,
        "confidence": round(ml_prob * 100, 2),
        "reasons": reasons if reasons else ["No major risks detected"]
    })
 except Exception as e:
    print("ERROR:", str(e))
    return jsonify({"error": str(e)}), 500
# -----------------------------
# Safe Search
# -----------------------------
@app.route("/safe-search", methods=["POST"])
def safe_search():

    data = request.get_json()

    if not data or "query" not in data:
        return jsonify({"error": "Search query required"}), 400

    query = data["query"]
    search_query = query.replace(" ", "+")

    trusted_sites = [
        {"site": "Amazon", "url": f"https://www.amazon.in/s?k={search_query}", "type": "E-commerce"},
        {"site": "Flipkart", "url": f"https://www.flipkart.com/search?q={search_query}", "type": "E-commerce"},
        {"site": "Meesho", "url": f"https://www.meesho.com/search?q={search_query}", "type": "E-commerce"},
        {"site": "Snapdeal", "url": f"https://www.snapdeal.com/search?keyword={search_query}", "type": "E-commerce"},
        {"site": "eBay", "url": f"https://www.ebay.com/sch/i.html?_nkw={search_query}", "type": "E-commerce"}
    ]

    return jsonify({
        "query": query,
        "safe_results": trusted_sites
    })

# -----------------------------
# Report Phishing
# -----------------------------
@app.route("/report", methods=["POST"])
def report_phishing():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    report = {
        "url": data["url"],
        "reason": data.get("reason", "Phishing"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    reports_collection.insert_one(report)

    return jsonify({"message": "Reported successfully"})

# -----------------------------
# Admin Panel
# -----------------------------
@app.route("/admin/reports", methods=["GET"])
def get_admin_reports():

    token = request.headers.get("Authorization")

    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 403

    reports = list(reports_collection.find({}, {"_id": 0}))
    return jsonify(reports)

# -----------------------------
# Stats
# -----------------------------
@app.route("/stats", methods=["GET"])
def get_stats():

    total = scans_collection.count_documents({})
    safe = scans_collection.count_documents({"result": "Safe"})
    phishing = scans_collection.count_documents({"result": "Phishing"})
    suspicious = scans_collection.count_documents({"result": "Suspicious"})

    return jsonify({
        "total": total,
        "safe": safe,
        "phishing": phishing,
        "suspicious": suspicious
    })
 # -----------------------------
 # timeline analytics
 # -----------------------------
@app.route("/stats/timeline", methods=["GET"])
def stats_timeline():

    pipeline = [
        {
            "$group": {
                "_id": {
                    "day": {"$dayOfMonth": "$timestamp"},
                    "month": {"$month": "$timestamp"}
                },
                "count": {"$sum": 1}
            }
        },
        {"$sort": {"_id.month": 1, "_id.day": 1}}
    ]

    data = list(scans_collection.aggregate(pipeline))

    formatted = [
        {
            "date": f"{d['_id']['day']}/{d['_id']['month']}",
            "count": d["count"]
        }
        for d in data
    ]

    return jsonify(formatted)
# -----------------------------
# Admin Login
# -----------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_TOKEN = "secure_admin_token_123"

@app.route("/admin/login", methods=["POST"])
def admin_login():

    data = request.get_json()

    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        return jsonify({
            "message": "Login successful",
            "token": ADMIN_TOKEN
        })

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/admin/scans", methods=["GET"])
def get_all_scans():

    token = request.headers.get("Authorization")

    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 403

    scans = list(scans_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))

    return jsonify(scans)

@app.route("/admin/delete", methods=["DELETE"])
def delete_report():

    token = request.headers.get("Authorization")

    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()

    url = data.get("url")

    reports_collection.delete_one({"url": url})

    return jsonify({"message": "Deleted successfully"})

@app.route("/admin/delete-scan", methods=["DELETE"])
def delete_scan():

    token = request.headers.get("Authorization")

    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    url = data.get("url")

    scans_collection.delete_one({"url": url})

    return jsonify({"message": "Scan deleted"})
# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
