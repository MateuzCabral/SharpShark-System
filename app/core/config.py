import os
from dotenv import load_dotenv

load_dotenv()

LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT") or 5)
LOGIN_RATE_PERIOD = int(os.getenv("LOGIN_RATE_PERIOD") or 600)

UPLOAD_RATE_LIMIT = int(os.getenv("UPLOAD_RATE_LIMIT") or 10)
UPLOAD_RATE_PERIOD = int(os.getenv("UPLOAD_RATE_PERIOD") or 3600)

UPLOAD_DIRECTORY = os.getenv("UPLOAD_DIRECTORY") or "./uploads"
INGEST_BASE_DIRECTORY = os.path.abspath(os.getenv("INGEST_BASE_DIRECTORY") or "./uploads/ingest")