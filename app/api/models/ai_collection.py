from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://admin:password@mongodb:27017/cyberguard?authSource=admin",
)

mongo = AsyncIOMotorClient(MONGO_URI).get_default_database()

# Expose any collections that need to be shared
AI_RISK_REPORT = mongo["ai_risk_reports"]