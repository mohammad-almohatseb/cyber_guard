from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://admin:password@mongodb:27017/"

client = AsyncIOMotorClient(MONGO_URI)

db = client["info_gathering"]

# Test Connection
try:
    client.admin.command("ping")
    print("MongoDB connected successfully!")
except Exception as e:
    print("MongoDB connection failed:", e)

