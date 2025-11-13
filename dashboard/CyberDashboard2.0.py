from flask import Flask, render_template
import requests, feedparser, os
from datetime import datetime, timezone

app = Flask(__name__)

import os
import requests
import sys

sys.stdout.reconfigure(encoding='utf-8')


def get_recent_cves(limit=10, page=1):
    user = os.getenv("OPENCVE_USER")
    passwd = os.getenv("OPENCVE_PASS")
    if not user or not passwd:
        print("[!] OpenCVE credentials not set")
        return []

    url = f"https://app.opencve.io/api/cve?page={page}"
    try:
        r = requests.get(url, auth=(user, passwd), timeout=15)
        r.raise_for_status()
        data = r.json()
        cves = []
        for item in data.get("results", [])[:limit]:
            cves.append({
                "id": item.get("cve_id", "Unknown"),
                "desc": item.get("description", "No description")[:200] + "...",
                "published": item.get("created_at", "")[:10]
            })
        return cves
    except requests.exceptions.HTTPError as e:
        print(f"[!] OpenCVE fetch HTTP error: {e} - {r.text[:200]}")
        return []
    except Exception as e:
        print(f"[!] OpenCVE fetch error: {e}")
        return []

def get_ransomware_attacks(limit=10):
    url = "https://api.ransomware.live/v2/recentvictims"
    headers = {"User‑Agent": "CyberDashboard/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = []
        for v in data[:limit]:
            results.append({
                "group": v.get("group", "Unknown"),
                "victim": v.get("victim", "Unknown"),
                "date": v.get("attackdate", "")
            })
        return results
    except requests.exceptions.HTTPError as e:
        print(f"[!] Ransomware fetch HTTP error: {e} – {r.text[:200]}")
        return []
    except Exception as e:
        print(f"[!] Ransomware fetch error: {e}")
        return []

def get_cyber_news():
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
    ]
    news_items = []
    try:
        for feed in feeds:
            parsed = feedparser.parse(feed)
            for entry in parsed.entries[:5]:
                news_items.append({"title": entry.title, "link": entry.link})
        return news_items
    except Exception as e:
        print(f"[!] News fetch error: {e}")
        return []

def get_threat_intel(limit=10):
    key = os.getenv("OTX_API_KEY")
    if not key:
        print("[!] OTX_API_KEY not set — skipping threat intel.")
        return []
    headers = {"X-OTX-API-KEY": key, "User-Agent": "CyberDashboard/1.0"}
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        pulses = data.get("results", [])[:limit]
        intel = []
        for pulse in pulses:
            intel.append({
                "name": pulse.get("name"),
                "author": pulse.get("author_name", "Unknown"),
                "created": pulse.get("created", "")[:10],
                "tags": ", ".join(pulse.get("tags", [])) or "None"
            })
        return intel
    except requests.exceptions.RequestException as e:
        print(f"[!] Threat intel fetch error: {e}")
        return []

@app.route("/")
def index():
    cves = get_recent_cves()
    ransomware = get_ransomware_attacks()
    news = get_cyber_news()
    intel = get_threat_intel()
    return render_template(
        "dashboard.html",
        cves=cves,
        ransomware=ransomware,
        news=news,
        intel=intel,
        updated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

port = int(os.environ.get("PORT", 5000))
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)







