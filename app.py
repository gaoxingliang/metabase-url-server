import os
import jwt
import time
import logging
from bottle import Bottle, request, response
import json

# Configure logging with rotation
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import os

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure logging with both size and time-based rotation
def setup_logging():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # File handler with size-based rotation (10MB per file, keep 5 files)
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Daily rotation handler (rotate daily, keep 30 days)
    daily_handler = TimedRotatingFileHandler(
        'logs/app_daily.log',
        when='midnight',
        interval=1,
        backupCount=30
    )
    daily_handler.setLevel(logging.INFO)
    daily_handler.setFormatter(file_formatter)
    
    # Add all handlers
    logger.addHandler(console_handler)
    logger.addHandler(daily_handler)
    
    return logger

logger = setup_logging()

app = Bottle()

# Get secrets from environment variables
METABASE_SITE_URL = os.getenv('METABASE_SITE_URL')
METABASE_SECRET_KEY = os.getenv('METABASE_SECRET_KEY')
# Get expiration time from environment variable (default: 30 minutes)
TOKEN_EXPIRATION_MINUTES = int(os.getenv('TOKEN_EXPIRATION_MINUTES', '30'))

# Validate required environment variables
if not METABASE_SITE_URL:
    logger.error("METABASE_SITE_URL environment variable is required")
    raise ValueError("METABASE_SITE_URL environment variable is required")
if not METABASE_SECRET_KEY:
    logger.error("METABASE_SECRET_KEY environment variable is required")
    raise ValueError("METABASE_SECRET_KEY environment variable is required")

logger.info(f"Server initialized with METABASE_SITE_URL: {METABASE_SITE_URL}")
logger.info(f"Token expiration set to {TOKEN_EXPIRATION_MINUTES} minutes")

@app.post('/api/metabase/urls')
def generate_url():
    # Log incoming request
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    user_agent = request.environ.get('HTTP_USER_AGENT', 'unknown')
    logger.info(f"POST /api/urls - Client IP: {client_ip}, User-Agent: {user_agent}")
    
    try:
        # Parse JSON body
        body = request.json
        logger.info(f"Request body: {json.dumps(body, indent=2)}")
        
        if not body:
            logger.warning("Request rejected: Missing request body")
            response.status = 400
            return {'error': 'Request body is required'}
        
        resource_type = body.get('resource')
        resource_id = body.get('id')
        
        logger.info(f"Processing request - Resource: {resource_type}, ID: {resource_id}")
        
        if not resource_type or not resource_id:
            logger.warning(f"Request rejected: Missing required fields - resource: {resource_type}, id: {resource_id}")
            response.status = 400
            return {'error': 'Both "resource" and "id" are required in request body'}
        
        # Create payload for JWT token
        payload = {
            "resource": {resource_type: int(resource_id)},
            "params": {},
            "exp": round(time.time()) + (60 * TOKEN_EXPIRATION_MINUTES)  # Configurable expiration
        }
        

        # Generate JWT token
        token = jwt.encode(payload, METABASE_SECRET_KEY, algorithm='HS256')

        # Generate iframe URL
        iframe_url = f"{METABASE_SITE_URL}/embed/{resource_type}/{token}#bordered=true&titled=true"

        # Prepare response
        response_data = {
            'url': iframe_url,
            'expires_in_minutes': TOKEN_EXPIRATION_MINUTES
        }
        
        logger.info(f"Response data: {json.dumps(response_data, indent=2)}")

        return response_data
        
    except ValueError as e:
        logger.error(f"Request failed - Invalid JSON: {str(e)}")
        response.status = 400
        return {'error': f'Invalid JSON: {str(e)}'}
    except Exception as e:
        logger.error(f"Request failed - Internal server error: {str(e)}", exc_info=True)
        response.status = 500
        return {'error': f'Internal server error: {str(e)}'}

@app.get('/')
def health_check():
    response_data = {'status': 'healthy', 'service': 'metabase-url-server'}
    return response_data

if __name__ == '__main__':
    logger.info("Starting Metabase URL Server on http://0.0.0.0:7070")
    app.run(host='0.0.0.0', port=7070, debug=True)
