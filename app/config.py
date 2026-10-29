import os
from dotenv import load_dotenv

load_dotenv()  # reads .env into environment variables

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VT_KEY = os.getenv("VT_KEY")
SHODAN_KEY = os.getenv("SHODAN_KEY")
