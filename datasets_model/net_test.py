import logging
import os
import json
from collections import defaultdict
from typing import List, Dict, Any, Optional

import pandas as pd
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure, PyMongoError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkThreatDataProcessor:
    """Processes and aggregates network vulnerability data by target IP address."""

    def __init__(
        self,
        connection_string: Optional[str] = None,
        database_name: str = "cyberguard",
        collection_name: str = "NetworkVulnerabilityAssessmentModel"
    ):
        self.connection_string = connection_string or self._build_connection_string()
        self.database_name = database_name
        self.collection_name = collection_name
        self.client = None
        self.db = None

    @staticmethod
    def _build_connection_string() -> str:
        user = os.getenv("MONGO_USER", "admin")
        pwd = os.getenv("MONGO_PASS", "password")
        host = os.getenv("MONGO_HOST", "localhost")
        port = os.getenv("MONGO_PORT", "27017")
        return f"mongodb://{user}:{pwd}@{host}:{port}/?authSource=admin"

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self):
        try:
            self.client = MongoClient(self.connection_string)
            self.client.admin.command('ping')
            self.db = self.client[self.database_name]
            logger.info("Connected to MongoDB: %s/%s", self.database_name, self.collection_name)
        except (ConnectionFailure, OperationFailure, Exception) as e:
            logger.error("MongoDB connection error: %s", e)
            raise

    def disconnect(self):
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

    def fetch_data_from_db(self) -> List[Dict[str, Any]]:
        try:
            collection = self.db[self.collection_name]
            documents = list(collection.find({}))
            logger.info("Fetched %d documents from MongoDB", len(documents))
            return documents
        except PyMongoError as e:
            logger.error("MongoDB fetch error: %s", e)
            raise

    def process_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregate data per target IP."""
        result = defaultdict(lambda: {
            "services": set(),
            "cves": set(),
            "cvss_scores": [],
            "os_info": set(),
            "has_waf": None,
            "waf_description": None
        })

        for doc in data:
            # Process detected services
            for service in self._flatten(doc.get("detected_services_data", [])):
                target = service.get("target")
                if not target:
                    continue
                svc_name = service.get("service")
                if svc_name:
                    result[target]["services"].add(svc_name)
                cve_id = service.get("id")
                if cve_id:
                    result[target]["cves"].add(cve_id)
                score = service.get("cvss_score")
                if isinstance(score, (int, float)):
                    result[target]["cvss_scores"].append(score)

            # Process OS data
            for os_entry in self._flatten(doc.get("os_detection_data", [])):
                target = os_entry.get("target")
                if not target:
                    continue
                os_name = os_entry.get("os")
                if os_name:
                    result[target]["os_info"].add(os_name)
                cve_id = os_entry.get("id")
                if cve_id:
                    result[target]["cves"].add(cve_id)
                score = os_entry.get("cvss_score")
                if isinstance(score, (int, float)):
                    result[target]["cvss_scores"].append(score)

            # Process WAF data
            for waf_entry in self._flatten(doc.get("waf_cve_data", [])):
                target = waf_entry.get("target")
                if not target:
                    continue
                result[target]["has_waf"] = waf_entry.get("has_waf")
                result[target]["waf_description"] = waf_entry.get("description")

        # Finalize
        final = []
        for target, info in result.items():
            avg_score = self._compute_average(info["cvss_scores"])
            final.append({
                "target": target,
                "services": list(info["services"]),
                "cves": list(info["cves"]),
                "cvss_score": avg_score,
                "os_info": list(info["os_info"]),
                "has_waf": info["has_waf"],
                "waf_description": info["waf_description"]
            })

        logger.info("Processed %d unique targets", len(final))
        return final

    @staticmethod
    def _flatten(data):
        """Recursively flatten nested lists."""
        if isinstance(data, list):
            for item in data:
                yield from NetworkThreatDataProcessor._flatten(item)
        else:
            yield data

    @staticmethod
    def _compute_average(values: List[float]) -> Optional[float]:
        if not values:
            return None
        return round(sum(values) / len(values), 2)

    @staticmethod
    def to_dataframe(processed_data: List[Dict[str, Any]]) -> pd.DataFrame:
        return pd.DataFrame(processed_data)

    @staticmethod
    def save_to_csv(df: pd.DataFrame, filename: str = "network_threat_data.csv"):
        df.to_csv(filename, index=False)
        logger.info("Saved CSV: %s", filename)

    @staticmethod
    def save_to_json(data: List[Dict[str, Any]], filename: str = "network_threat_data.json"):
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved JSON: %s", filename)


def main():
    # Example: Process data in-memory (pass JSON list here)
    example_data = [ ... ]  # Your JSON list goes here
    processor = NetworkThreatDataProcessor()
    processed = processor.process_data(example_data)

    # Convert to DataFrame and save
    df = processor.to_dataframe(processed)
    print(df.head())
    processor.save_to_csv(df)
    processor.save_to_json(processed)

  

if __name__ == "__main__":
    main()
