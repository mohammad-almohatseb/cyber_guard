import json
import logging
import os
from collections import defaultdict
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, urlparse

import pandas as pd
import tldextract
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, PyMongoError, OperationFailure

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDataProcessor:
    """Processes threat data from MongoDB for security analysis."""

    def __init__(
        self,
        connection_string: Optional[str] = None,
        database_name: str = "cyberguard",
        collection_name: str = "WebVulnerabilityAssessmentModel"
    ) -> None:
        self.connection_string = connection_string or self._build_connection_string()
        self.database_name = database_name
        self.collection_name = collection_name
        self.client = None
        self.db = None

    @staticmethod
    def _build_connection_string() -> str:
        username = quote_plus(os.getenv('MONGO_USER', 'admin'))
        password = quote_plus(os.getenv('MONGO_PASS', 'password'))
        host = os.getenv('MONGO_HOST', 'localhost')
        port = os.getenv('MONGO_PORT', '27017')
        db_name = os.getenv('MONGO_DB', 'cyberguard')
        return (
            f"mongodb://{username}:{password}@{host}:{port}/{db_name}?"
            "authSource=admin&connectTimeoutMS=5000&socketTimeoutMS=5000"
        )

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self) -> None:
        try:
            self.client = MongoClient(self.connection_string)
            self.client.admin.command('ping')
            self.db = self.client[self.database_name]
            logger.info("Successfully connected to MongoDB: %s, collection: %s", self.database_name, self.collection_name)
        except (ConnectionFailure, OperationFailure, Exception) as e:
            logger.error("MongoDB connection error: %s", e)
            raise

    def disconnect(self) -> None:
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

    def fetch_threat_data(self) -> Dict[str, List[Dict[str, Any]]]:
        collection = self.db[self.collection_name]
        try:
            all_documents = list(collection.find({}))
            logger.info("Fetched %d documents", len(all_documents))

            https_headers_data, certificate_data, input_validation_data = [], [], []
            server_cve_data, service_cve_data, waf_cve_data = [], [], []

            for doc in all_documents:
                https_headers_data.extend(self._flatten(doc.get('https_headers_data', [])))
                certificate_data.extend(self._flatten(doc.get('certificate_data', [])))
                input_validation_data.extend(self._flatten(doc.get('input_validation_data', [])))
                server_cve_data.extend(doc.get('server_cve_data', []))
                service_cve_data.extend(doc.get('service_cve_data', []))
                waf_cve_data.extend(doc.get('waf_cve_data', []))

            return {
                "https_headers_data": https_headers_data,
                "certificate_data": certificate_data,
                "input_validation_data": input_validation_data,
                "server_cve_data": server_cve_data,
                "service_cve_data": service_cve_data,
                "waf_cve_data": waf_cve_data
            }

        except PyMongoError as e:
            logger.error("MongoDB fetch error: %s", e)
            raise

    @staticmethod
    def _flatten(data):
        """Recursively flatten nested lists."""
        if isinstance(data, list):
            for item in data:
                yield from ThreatDataProcessor._flatten(item)
        else:
            yield data

    @staticmethod
    def normalize_subdomain(entry: Dict[str, Any]) -> str:
        if not isinstance(entry, dict):
            logger.warning("Expected dict but got: %s", type(entry))
            return ""
        if "subdomain" in entry and entry["subdomain"]:
            return entry["subdomain"].split("?")[0].lower()
        if "domain" in entry and entry["domain"]:
            return entry["domain"].split("?")[0].lower()
        url = entry.get("url")
        if url:
            try:
                return urlparse(url).netloc.lower()
            except Exception:
                logger.warning("Malformed URL: %s", url)
        return ""

    def extract_model_data(self, data: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        result = defaultdict(lambda: {
            "certificate": None,
            "http_headers": [],
            "expected_vulnerabilities": set(),
            "cves": set(),
            "cvss_scores": [],
            "has_waf": None,
            "waf_description": None
        })

        # Certificates
        cert_seen = set()
        for cert in data.get("certificate_data", []):
            sub = self.normalize_subdomain(cert)
            if sub and sub not in cert_seen:
                result[sub]["certificate"] = {
                    "has_tls": cert.get("has_tls"),
                    "status": cert.get("status"),
                    "severity": cert.get("severity"),
                    "issuer": cert.get("issuer"),
                    "start_date": cert.get("start_date"),
                    "expire_date": cert.get("expire_date"),
                    "days_until_expire": cert.get("days_until_expire")
                }
                cert_seen.add(sub)

        # HTTPS headers
        for h in data.get("https_headers_data", []):
            sub = self.normalize_subdomain(h)
            if sub:
                result[sub]["http_headers"].append({
                    "header": h.get("header"),
                    "status": h.get("status"),
                    "description": h.get("description")
                })

        # Expected vulnerabilities
        for v in data.get("input_validation_data", []):
            sub = self.normalize_subdomain(v)
            if sub:
                ev = v.get("expected_vulnerability")
                if ev:
                    result[sub]["expected_vulnerabilities"].add(ev)
                cve = v.get("cve")
                if cve:
                    result[sub]["cves"].add(cve)

        # CVEs from server_cve_data
        for entry in data.get("server_cve_data", []):
            sub = self.normalize_subdomain(entry)
            if sub and "id" in entry:
                result[sub]["cves"].add(entry["id"])
                score = entry.get("cvss_score")
                if isinstance(score, (int, float)):
                    result[sub]["cvss_scores"].append(score)

        # CVEs from service_cve_data
        for entry in data.get("service_cve_data", []):
            sub = self.normalize_subdomain(entry)
            if sub and "id" in entry:
                result[sub]["cves"].add(entry["id"])
                score = entry.get("cvss_score")
                if isinstance(score, (int, float)):
                    result[sub]["cvss_scores"].append(score)

        # WAF info
        for entry in data.get("waf_cve_data", []):
            sub = self.normalize_subdomain(entry)
            if sub:
                result[sub]["has_waf"] = entry.get("has_waf")
                result[sub]["waf_description"] = entry.get("description")
                score = entry.get("cvss_score")
                if isinstance(score, (int, float)):
                    result[sub]["cvss_scores"].append(score)

        # Final output
        final = []
        for subdomain, info in result.items():
            avg_score = round(sum(info["cvss_scores"]) / len(info["cvss_scores"]), 2) if info["cvss_scores"] else None
            final.append({
                "subdomain": subdomain,
                "certificate": info["certificate"],
                "http_headers": info["http_headers"],
                "expected_vulnerabilities": list(info["expected_vulnerabilities"]),
                "cves": list(info["cves"]),
                "cvss_score": avg_score,
                "has_waf": info["has_waf"],
                "waf_description": info["waf_description"]
            })
        return final

    @staticmethod
    def save_to_dataframe(processed_data: List[Dict[str, Any]]) -> pd.DataFrame:
        return pd.DataFrame(processed_data)

    @staticmethod
    def save_to_json_per_domain(processed_data: List[Dict[str, Any]], output_dir: str = "per_domain_data") -> None:
        os.makedirs(output_dir, exist_ok=True)
        domain_group = defaultdict(list)

        for entry in processed_data:
            sub = entry.get("subdomain", "")
            if sub:
                extracted = tldextract.extract(sub)
                root_domain = f"{extracted.domain}.{extracted.suffix}"
                domain_group[root_domain].append(entry)

        for domain, entries in domain_group.items():
            file_path = os.path.join(output_dir, f"{domain}.json")
            with open(file_path, 'w') as f:
                json.dump(entries, f, indent=2)
            logger.info("Saved data for domain %s to %s", domain, file_path)

def main() -> None:
    try:
        with ThreatDataProcessor() as processor:
            raw_data = processor.fetch_threat_data()
            processed_data = processor.extract_model_data(raw_data)
            df = processor.save_to_dataframe(processed_data)
            print(f"DataFrame shape: {df.shape}")
            print(df.head())

            # Save JSON per domain (not per subdomain)
            processor.save_to_json_per_domain(processed_data)

            # Save CSV (optional)
            df.to_csv("processed_threat_data.csv", index=False)

    except Exception as e:
        logger.error("Application error: %s", e)
        raise

if __name__ == "__main__":
    main()

