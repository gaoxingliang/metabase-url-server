# You'll need to install PyJWT via pip 'pip install PyJWT' or your project packages file

# require module PyJWT
import jwt
import time
import os

# Get secrets from environment variables
METABASE_SITE_URL = os.getenv('METABASE_SITE_URL')
METABASE_SECRET_KEY = os.getenv('METABASE_SECRET_KEY')

# Validate required environment variables
if not METABASE_SITE_URL:
    raise ValueError("METABASE_SITE_URL environment variable is required")
if not METABASE_SECRET_KEY:
    raise ValueError("METABASE_SECRET_KEY environment variable is required")

payload = {
    "resource": {"dashboard": 2},
    "params": {

    },
    "exp": round(time.time()) + (60 * 20)  # 10 minute expiration
}

# For jwt 1.4.0 library, use encode directly with the secret key
token = jwt.encode(payload, METABASE_SECRET_KEY, algorithm='HS256')

iframeUrl = METABASE_SITE_URL + "/embed/dashboard/" + token +"#bordered=true&titled=true"
print(iframeUrl)