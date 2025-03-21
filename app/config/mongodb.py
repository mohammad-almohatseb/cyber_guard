from contextlib import asynccontextmanager
from beanie import init_beanie
from fastapi import FastAPI
from motor import motor_asyncio
import logging


logging.basicConfig(level=logging.INFO)

class MongoDB:
    async def init_db():
        try:
            client = motor_asyncio.AsyncIOMotorClient(
                "mongodb://admin:password@mongodb:27017/cyberguard?authSource=admin"
            )
            db = client.cyberguard
    
            # Initialize Beanie ODM
            await init_beanie(database=db, document_models=[])
        except Exception as e:
            logging.error(f"MongoDB connection failed: {e}")
            raise  
    
@asynccontextmanager
async def db_startup(app: FastAPI):
    try:
        await MongoDB.init_db() 
        logging.info("MongoDB connected successfully!")
    except Exception as e:
        logging.error(f"MongoDB connection failed: {e}")
        raise e  

    yield  
    
    logging.info("Application shutting down...")
