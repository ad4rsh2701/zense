import os
from dotenv import load_dotenv

# Load variables from .env into os.environ
load_dotenv()

# Retrieve keys
ar_api_key = os.getenv("AR_KEY")

# Validate presence
if not ar_api_key:
    raise RuntimeError("Missing AR_KEY in .env file")