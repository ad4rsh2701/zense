import os
from dotenv import load_dotenv

# Load variables from .env into os.environ
load_dotenv()

# Retrieve keys
ha_api_key = os.getenv("HA_KEY")

# Validate presence
if not ha_api_key:
    raise RuntimeError("Missing HA_KEY in .env file")
