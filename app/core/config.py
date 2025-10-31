import os
from dotenv import load_dotenv

load_dotenv()

LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", 5))
LOGIN_RATE_PERIOD = int(os.getenv("LOGIN_RATE_PERIOD", 600))

UPLOAD_RATE_LIMIT = int(os.getenv("UPLOAD_RATE_LIMIT", 10))
UPLOAD_RATE_PERIOD = int(os.getenv("UPLOAD_RATE_PERIOD", 3600))

UPLOAD_DIRECTORY = os.getenv("UPLOAD_DIRECTORY", "./uploads")
INGEST_BASE_DIRECTORY = os.path.abspath(os.getenv("INGEST_BASE_DIRECTORY", "./uploads/ingest"))