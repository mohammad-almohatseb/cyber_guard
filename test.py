import requests
import json

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_score(cve_metrics):
    if "cvssMetricV31" in cve_metrics:
        cvss = cve_metrics["cvssMetricV31"][0]["cvssData"]
        return cvss.get("baseScore")
    elif "cvssMetricV30" in cve_metrics:
        cvss = cve_metrics["cvssMetricV30"][0]["cvssData"]
        return cvss.get("baseScore")
    elif "cvssMetricV2" in cve_metrics:
        cvss = cve_metrics["cvssMetricV2"][0]["cvssData"]
        return cvss.get("baseScore")
    return None

def extract_description(cve_data):
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value")
    return None

def extract_name(cve_data):
    for title in cve_data.get("titles", []):
        if title.get("lang") == "en":
            return title.get("value")
    return None

def fetch_first_2000_cves():
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0
    }

    print("Fetching first 2000 CVEs...")
    response = requests.get(API_URL, params=params)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    extracted_data = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        name = extract_name(cve)
        metrics = cve.get("metrics", {})
        score = extract_score(metrics)
        description = extract_description(cve)

        extracted_data.append({
            "cve_id": cve_id,
            "name": name,
            "score": score,
            "description": description
        })

    # Save to JSON file
    with open("first_2000_cves_with_name_score_description.json", "w", encoding="utf-8") as f:
        json.dump(extracted_data, f, indent=2, ensure_ascii=False)

    print(f"✅ Saved {len(extracted_data)} CVEs to first_2000_cves_with_name_score_description.json")

if __name__ == "__main__":
    fetch_first_2000_cves()
