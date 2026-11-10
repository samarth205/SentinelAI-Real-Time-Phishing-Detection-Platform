"""Small, explainable URL risk model. No URL is fetched or opened by this service."""
from urllib.parse import urlparse
import re
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

app = FastAPI(title="SentinelAI URL Risk Model", version="1.0.0")

def features(url: str):
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host, path = parsed.hostname or "", parsed.path or ""
    return [len(url), len(host), host.count("."), host.count("-"), int(parsed.scheme != "https"),
            int(bool(re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host))), int("@" in url),
            int(bool(re.search(r"login|verify|secure|account|update|wallet|signin|password", url.lower()))),
            int(bool(re.search(r"xn--|%[0-9a-f]{2}", url.lower()))), len(path), int("=" in parsed.query)]

# Synthetic examples provide a runnable baseline; replace with a validated, representative
# labeled dataset before using this classifier to make operational decisions.
TRAINING = [
    ("https://www.google.com/search", 0), ("https://github.com/openai", 0), ("https://www.wikipedia.org/", 0),
    ("https://docs.python.org/3/", 0), ("https://notion.so/product", 0), ("https://www.apple.com/store", 0),
    ("http://192.168.1.10/login", 1), ("http://paypal-account-verify-login.co/security", 1),
    ("https://secure-update-account.example.net/signin", 1), ("http://xn--paypa1-4ve.com/verify", 1),
    ("https://login-confirm-password.example.org/account", 1), ("http://account-security-check.xyz/update", 1),
    ("http://verify-wallet-access.example.com/login", 1), ("https://microsoft-login-security.info/", 1),
]
model = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=120, random_state=42, class_weight="balanced"))
model.fit([features(u) for u, _ in TRAINING], [label for _, label in TRAINING])
KNOWN = ("google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com", "github.com", "notion.so", "wikipedia.org")

class Request(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

@app.get("/health")
def health(): return {"status": "ok", "model": "random-forest-baseline"}

@app.post("/predict")
def predict(request: Request):
    url = request.url.strip()
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    if any(host == domain or host.endswith("." + domain) for domain in KNOWN):
        return {"risk": "Safe", "score": 3, "flags": ["Known established domain"]}
    probability = float(model.predict_proba([features(url)])[0][1])
    score = min(99, max(1, round(probability * 100)))
    flags = []
    if parsed.scheme != "https": flags.append("No HTTPS encryption")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host): flags.append("IP address used as domain")
    if re.search(r"login|verify|secure|account|update|wallet|signin|password", url.lower()): flags.append("Credential or account keywords")
    if "xn--" in host or "@" in url: flags.append("Obfuscated URL pattern")
    if host.count("-") >= 2: flags.append("Multiple hyphens in domain")
    if not flags: flags.append("No obvious risk signals")
    risk = "Critical" if score >= 75 else "High" if score >= 40 else "Safe"
    return {"risk": risk, "score": score, "flags": flags}
