import os
import jwt
import time
import logging
import yaml
import hashlib
import hmac
import base64
import uuid
import threading
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

def load_config():
    """Load configuration from config.yml file"""
    config_path = 'conf/config.yml'
    
    if not os.path.exists(config_path):
        logger.error(f"Configuration file {config_path} not found")
        raise FileNotFoundError(f"Configuration file {config_path} not found")
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        # Validate required sections
        required_sections = ['metabase', 'auth_groups']
        for section in required_sections:
            if section not in config:
                logger.error(f"Missing '{section}' section in config.yml")
                raise ValueError(f"Missing '{section}' section in config.yml")
        
        # Validate Metabase configuration
        metabase_config = config['metabase']
        required_metabase_fields = ['site_url', 'secret_key']
        for field in required_metabase_fields:
            if field not in metabase_config:
                logger.error(f"Missing '{field}' in metabase configuration")
                raise ValueError(f"Missing '{field}' in metabase configuration")
        
        # Validate auth groups
        auth_groups = config['auth_groups']
        if not auth_groups:
            logger.error("No authentication groups defined in config.yml")
            raise ValueError("No authentication groups defined in config.yml")
        
        # Validate each group has required fields
        for group_name, group_config in auth_groups.items():
            if not isinstance(group_config, dict):
                logger.error(f"Invalid configuration for group '{group_name}'")
                raise ValueError(f"Invalid configuration for group '{group_name}'")
            
            required_fields = ['app_key', 'app_secret']
            for field in required_fields:
                if field not in group_config:
                    logger.error(f"Missing '{field}' in group '{group_name}'")
                    raise ValueError(f"Missing '{field}' in group '{group_name}'")
            
            # Set default values for optional fields
            if 'enabled' not in group_config:
                group_config['enabled'] = True
            if 'description' not in group_config:
                group_config['description'] = f"Group: {group_name}"
        
        logger.info(f"Configuration loaded successfully with {len(auth_groups)} auth groups")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing config.yml: {str(e)}")
        raise ValueError(f"Error parsing config.yml: {str(e)}")
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        raise

# Global variables for authentication
SECRETS_DB = {}
NONCE_CACHE = {}  # {nonce: timestamp}
TIME_WINDOW_SECONDS = 300  # 5分钟时间窗口
NONCE_CLEANUP_INTERVAL = 60  # 清理间隔（秒）
LAST_CLEANUP_TIME = time.time()

# Thread safety for NONCE_CACHE
NONCE_CACHE_LOCK = threading.RLock()

def initialize_auth_db():
    """Initialize the authentication database from config"""
    global SECRETS_DB
    config = load_config()
    auth_groups = config['auth_groups']
    
    for group_name, group_config in auth_groups.items():
        if group_config.get('enabled', True):
            SECRETS_DB[group_config['app_key']] = group_config['app_secret']
    
    logger.info(f"Authentication database initialized with {len(SECRETS_DB)} active keys")

def cleanup_expired_nonces():
    """清理过期的nonce缓存（线程安全版本）"""
    global NONCE_CACHE, LAST_CLEANUP_TIME
    current_time = time.time()
    
    # 使用锁保护整个清理过程
    with NONCE_CACHE_LOCK:
        # 检查是否需要清理（每60秒清理一次）
        if current_time - LAST_CLEANUP_TIME < NONCE_CLEANUP_INTERVAL:
            return
        
        # 清理过期的nonce
        expired_nonces = []
        for nonce, timestamp in NONCE_CACHE.items():
            if current_time - timestamp > TIME_WINDOW_SECONDS:
                expired_nonces.append(nonce)
        
        # 删除过期的nonce
        for nonce in expired_nonces:
            del NONCE_CACHE[nonce]
        
        if expired_nonces:
            logger.info(f"Cleaned up {len(expired_nonces)} expired nonces. Cache size: {len(NONCE_CACHE)}")
        
        LAST_CLEANUP_TIME = current_time



def verify_signature():
    """Verify HMAC signature for incoming requests"""
    # Extract authentication headers
    app_key = request.headers.get('X-AppKey')
    timestamp_str = request.headers.get('X-Timestamp')
    nonce = request.headers.get('X-Nonce')
    auth_header = request.headers.get('Authorization', '')

    if not all([app_key, timestamp_str, nonce, auth_header]):
        logger.warning("Request rejected: Missing required authentication headers")
        response.status = 401
        return {'error': 'Missing required authentication headers'}

    try:
        client_signature = auth_header.split(' ')[1]
        timestamp = int(timestamp_str)
    except (IndexError, ValueError):
        logger.warning("Request rejected: Invalid authorization or timestamp format")
        response.status = 401
        return {'error': 'Invalid authorization or timestamp format'}

    # Check if app_key exists
    if app_key not in SECRETS_DB:
        logger.warning(f"Request rejected: Invalid AppKey: {app_key}")
        response.status = 401
        return {'error': 'Invalid AppKey'}

    # Check timestamp validity (prevent replay attacks)
    if abs(time.time() - timestamp) > TIME_WINDOW_SECONDS:
        logger.warning(f"Request rejected: Timestamp expired. Server time: {time.time()}, Client time: {timestamp}")
        response.status = 401
        return {'error': 'Request timestamp has expired'}

    # Clean up expired nonces before checking
    cleanup_expired_nonces()
    
    # Check nonce to prevent replay attacks (线程安全)
    with NONCE_CACHE_LOCK:
        if nonce in NONCE_CACHE:
            logger.warning(f"Request rejected: Duplicate nonce detected: {nonce}")
            response.status = 401
            return {'error': 'Duplicate request (replay attack detected)'}

        # Add nonce to cache with timestamp
        NONCE_CACHE[nonce] = time.time()

    # Reconstruct the string to sign
    app_secret = SECRETS_DB[app_key]
    http_method = request.method
    uri_path = request.path
    request_body = request.body.read().decode('utf-8') if request.body else ''

    string_to_sign = (
        f"{http_method}\n"
        f"{uri_path}\n"
        f"{timestamp_str}\n"
        f"{nonce}\n"
        f"{request_body}"
    )

    # Generate server signature
    server_signature_raw = hmac.new(
        app_secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    server_signature = base64.b64encode(server_signature_raw).decode('utf-8')

    # Compare signatures using constant-time comparison
    if not hmac.compare_digest(server_signature, client_signature):
        logger.warning(f"Request rejected: Signature mismatch for app_key: {app_key}")
        response.status = 401
        return {'error': 'Signature mismatch'}

    # Authentication successful
    logger.info(f"Authentication successful for app_key: {app_key}")
    return None

app = Bottle()

# Initialize authentication database
try:
    initialize_auth_db()
    config = load_config()
    logger.info("Configuration loaded successfully")
except Exception as e:
    logger.error(f"Failed to load configuration: {str(e)}")
    raise

# Get configuration from config file
METABASE_SITE_URL = config['metabase']['site_url']
METABASE_SECRET_KEY = config['metabase']['secret_key']

# Get expiration time from environment variable or config (default: 30 minutes)
TOKEN_EXPIRATION_MINUTES = int(os.getenv('TOKEN_EXPIRATION_MINUTES', 
                                        str(config.get('server', {}).get('token_expiration_minutes', 30))))

# Validate required configuration
if not METABASE_SITE_URL or METABASE_SITE_URL == "http://your-metabase-server:port":
    logger.error("METABASE_SITE_URL not properly configured in conf/config.yml")
    raise ValueError("METABASE_SITE_URL not properly configured in conf/config.yml")
if not METABASE_SECRET_KEY or METABASE_SECRET_KEY == "your-metabase-secret-key":
    logger.error("METABASE_SECRET_KEY not properly configured in conf/config.yml")
    raise ValueError("METABASE_SECRET_KEY not properly configured in conf/config.yml")

logger.info(f"Server initialized with METABASE_SITE_URL: {METABASE_SITE_URL}")
logger.info(f"Token expiration set to {TOKEN_EXPIRATION_MINUTES} minutes")
logger.info(f"Authentication groups loaded: {list(config['auth_groups'].keys())}")

@app.post('/api/metabase/urls')
def generate_url():
    # Log incoming request
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    user_agent = request.environ.get('HTTP_USER_AGENT', 'unknown')
    logger.info(f"POST /api/urls - Client IP: {client_ip}, User-Agent: {user_agent}")
    
    try:
        # Verify HMAC signature
        auth_error = verify_signature()
        if auth_error:
            return auth_error
        
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
