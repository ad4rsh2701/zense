import os
from dotenv import load_dotenv

# Load variables from .env into os.environ
load_dotenv()

# Retrieve keys
vt_api_key = os.getenv("VT_KEY")

# Validate presence
if not vt_api_key:
    raise RuntimeError("Missing VT_KEY in .env file")