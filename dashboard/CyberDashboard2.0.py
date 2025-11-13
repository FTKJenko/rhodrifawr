from flask import Flask, render_template
import requests, feedparser, os
from datetime import datetime, timezone

app = Flask(__name__)

def get_recent_cves(limit=10):
    year = datetime.now().year
    url = f"https://raw.githubusercontent.com/CVEProject/cvelist/main/{year}.json"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        all_cves = r.json()
        cves = []
        for cve_id, details in list(all_cves.items())[:limit]:
            summary = details.get("summary", "No description available")
            published = details.get("published", "Unknown")
            cves.append({
                "id": cve_id,
                "desc": summary[:200] + "...",
                "published": published
            })
        return cves
    except requests.exceptions.RequestException as e:
        print(f"[!] GitHub CVE fetch error: {e}")
        return []

def get_ransomware_attacks(limit=10):
    urls = [
        "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware.json",
        "https://raw.githubusercontent.com/monkeysecurity/ransomware-feed/main/ransomware.json"
    ]
    headers = {"User-Agent": "CyberDashboard/1.0"}
    
    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            data = r.json()

            if isinstance(data, dict) and "victims" in data:
                victims = data["victims"]
            elif isinstance(data, list):
                victims = data
            else:
                print(f"[!] Unknown ransomware JSON structure from {url}")
                continue

            if not victims:
                continue

            results = []
            for v in victims[:limit]:
                group = v.get("group") or v.get("group_name") or v.get("ransomware", "Unknown")
                victim = v.get("victim") or v.get("title") or v.get("target", "Unknown")
                date = v.get("attackdate") or v.get("published", "")
                results.append({"group": group, "victim": victim, "date": date})
            return results

        except requests.exceptions.RequestException as e:
            print(f"[!] Ransomware fetch error ({url}): {e}")
            continue

    print("[!] No ransomware data available from any source.")
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
