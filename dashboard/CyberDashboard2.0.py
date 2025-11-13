from flask import Flask, render_template
import requests, feedparser, os
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

def get_recent_cves(days_back=1, limit=10):
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={start_date.isoformat()}Z&pubEndDate={end_date.isoformat()}Z"
    )
    headers = {"User-Agent": "CyberDashboard/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            print(f"[!] CVE API error: {r.status_code} {r.text[:200]}")
            return []
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", [])[:limit]:
            cve_id = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]
            cves.append({"id": cve_id, "desc": desc[:200] + "..."})
        return cves
    except Exception as e:
        print(f"[!] CVE fetch error: {e}")
        return []


def get_ransomware_attacks(limit=10):
    urls = [
        "https://api.ransomware.live/v2/recentvictims",  # main API
        "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware.json"  # fallback
    ]
    headers = {"User-Agent": "CyberDashboard/1.0"}
    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code != 200:
                print(f"[!] Ransomware API error ({url}): {r.status_code}")
                continue
            data = r.json()

            # Detect which format we got:
            if isinstance(data, dict) and "victims" in data:
                victims = data["victims"]
            elif isinstance(data, list):
                victims = data
            else:
                print(f"[!] Unknown ransomware JSON structure from {url}")
                continue

            if not victims:
                continue

            # Try flexible parsing
            results = []
            for v in victims[:limit]:
                group = v.get("group") or v.get("group_name") or v.get("ransomware", "Unknown")
                victim = v.get("victim") or v.get("title") or v.get("target", "Unknown")
                date = v.get("attackdate") or v.get("published", "")
                results.append({"group": group, "victim": victim, "date": date})
            return results

        except Exception as e:
            print(f"[!] Ransomware fetch error ({url}): {e}")
            continue
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
        if r.status_code != 200:
            print(f"[!] OTX API error: {r.status_code} {r.text[:200]}")
            return []
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
    except Exception as e:
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
def dashboard():
    cves = []  
    ransomware = []
    threat_intel = []
    return render_template("dashboard.html", cves=cves, ransomware=ransomware, threat_intel=threat_intel)

port = int(os.environ.get("PORT", 5000)) 

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
