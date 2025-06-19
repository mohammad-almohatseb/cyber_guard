import json
import logging
import os
from collections import defaultdict
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, urlparse

import pandas as pd
import tldextract
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from bson import ObjectId
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatDataProcessor:
    """Processes raw threat data from MongoDB and saves processed results."""

    def __init__(
        self,
        connection_string: Optional[str] = None,
        database_name: str = "cyberguard",
        collection_name: str = "NetworkVulnerabilityAssessmentModel"
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
            logger.info("Connected to MongoDB: %s, collection: %s", self.database_name, self.collection_name)
        except (ConnectionFailure, OperationFailure, Exception) as e:
            logger.error("MongoDB connection error: %s", e)
            raise

    def disconnect(self) -> None:
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

    def fetch_documents(self) -> List[Dict[str, Any]]:
        """Fetch all documents from the collection."""
        collection = self.db[self.collection_name]
        documents = list(collection.find({}))
        logger.info("Fetched %d documents", len(documents))
        return documents

    def _make_json_serializable(self, obj: Any) -> Any:
        """Recursively convert MongoDB types like ObjectId and datetime to JSON serializable types."""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(i) for i in obj]
        elif isinstance(obj, ObjectId):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return obj

    @staticmethod
    def _normalize_target(target: Optional[str]) -> str:
        """Normalize target strings for safe folder/file names."""
        if not target:
            return "unknown_target"
        # Extract domain part if URL
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            target = parsed.netloc
        # Clean characters not suitable for folder names
        return target.replace(":", "_").replace("/", "_").lower()

    def process_documents(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Preprocess and normalize each document for later saving or analysis."""
        processed = []
        for idx, doc in enumerate(documents):
            doc_clean = self._make_json_serializable(doc)

            detected_services = doc_clean.get("detected_services_data", [])
            os_data = doc_clean.get("os_detection_data", [])

            target = None
            if detected_services and isinstance(detected_services, list) and detected_services:
                target = detected_services[0].get("target")
            elif os_data and isinstance(os_data, list) and os_data:
                target = os_data[0].get("target")

            if not target:
                target = f"unknown_target_{idx}"

            doc_clean["_normalized_target"] = self._normalize_target(target)
            processed.append(doc_clean)
        return processed

    def group_by_root_domain(self, documents: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group documents by root domain extracted from normalized target."""
        grouped = defaultdict(list)
        for doc in documents:
            norm_target = doc.get("_normalized_target", "unknown_target")
            ext = tldextract.extract(norm_target)
            if ext.suffix:
                root_domain = f"{ext.domain}.{ext.suffix}"
            else:
                root_domain = norm_target  # fallback if no suffix found
            grouped[root_domain].append(doc)
        return grouped

    def save_documents_per_domain(self, grouped_docs: Dict[str, List[Dict[str, Any]]], base_dir: str = "output") -> None:
        """Save grouped documents as JSON files per root domain inside folders."""
        os.makedirs(base_dir, exist_ok=True)
        for domain, docs in grouped_docs.items():
            domain_dir = os.path.join(base_dir, domain)
            os.makedirs(domain_dir, exist_ok=True)
            file_path = os.path.join(domain_dir, f"{domain}.json")
            with open(file_path, "w") as f:
                json.dump(docs, f, indent=2)
            logger.info("Saved %d documents for domain %s at %s", len(docs), domain, file_path)

    def save_summary_dataframe(self, documents: List[Dict[str, Any]], csv_path: str = "summary.csv") -> None:
        """Create and save a pandas DataFrame summary from documents."""
        # Example: Extract key info for summary; you can adjust fields as needed
        summary_rows = []
        for doc in documents:
            target = doc.get("_normalized_target", "unknown")
            detected_services_count = len(doc.get("detected_services_data", []))
            os_detection_count = len(doc.get("os_detection_data", []))
            summary_rows.append({
                "target": target,
                "detected_services_count": detected_services_count,
                "os_detection_count": os_detection_count,
                "_id": str(doc.get("_id", ""))
            })
        df = pd.DataFrame(summary_rows)
        df.to_csv(csv_path, index=False)
        logger.info("Saved summary CSV to %s with %d records", csv_path, len(df))

def main():
    try:
        with ThreatDataProcessor() as processor:
            raw_docs = processor.fetch_documents()
            processed_docs = processor.process_documents(raw_docs)

            grouped = processor.group_by_root_domain(processed_docs)
            processor.save_documents_per_domain(grouped, base_dir="network_per_ip_output")

            processor.save_summary_dataframe(processed_docs, csv_path="processed_summary.csv")

            logger.info("Processing complete.")

    except Exception as e:
        logger.error("Error during processing: %s", e)
        raise

if __name__ == "__main__":
    main()
