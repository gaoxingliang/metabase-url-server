import os
import jwt
import time
import logging
import yaml
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

def authenticate_request(app_key, app_secret):
    """Authenticate request using app_key and app_secret"""
    if not hasattr(authenticate_request, 'config'):
        authenticate_request.config = load_config()
    
    auth_groups = authenticate_request.config['auth_groups']
    
    for group_name, group_config in auth_groups.items():
        if not group_config.get('enabled', True):
            continue
            
        if (group_config['app_key'] == app_key and 
            group_config['app_secret'] == app_secret):
            logger.info(f"Authentication successful for group: {group_name}")
            return True, group_name
    
    logger.warning(f"Authentication failed for app_key: {app_key}")
    return False, None

app = Bottle()

# Load configuration
try:
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
        # Check for authentication headers
        app_key = request.headers.get('X-App-Key')
        app_secret = request.headers.get('X-App-Secret')
        
        if not app_key or not app_secret:
            logger.warning(f"Request rejected: Missing authentication headers - app_key: {bool(app_key)}, app_secret: {bool(app_secret)}")
            response.status = 401
            return {'error': 'Authentication required. Please provide X-App-Key and X-App-Secret headers'}
        
        # Authenticate the request
        is_authenticated, group_name = authenticate_request(app_key, app_secret)
        if not is_authenticated:
            logger.warning(f"Request rejected: Authentication failed for app_key: {app_key}")
            response.status = 401
            return {'error': 'Authentication failed. Invalid app_key or app_secret'}
        
        logger.info(f"Request authenticated for group: {group_name}")
        
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

@app.get('/api/auth/groups')
def list_auth_groups():
    """List available authentication groups (admin endpoint)"""
    try:
        # Load current config
        current_config = load_config()
        auth_groups = current_config['auth_groups']
        
        # Return only group names and descriptions (not secrets)
        groups_info = {}
        for group_name, group_config in auth_groups.items():
            groups_info[group_name] = {
                'description': group_config.get('description', ''),
                'enabled': group_config.get('enabled', True)
            }
        
        return {
            'groups': groups_info,
            'total_groups': len(groups_info)
        }
        
    except Exception as e:
        logger.error(f"Error listing auth groups: {str(e)}")
        response.status = 500
        return {'error': f'Internal server error: {str(e)}'}

if __name__ == '__main__':
    logger.info("Starting Metabase URL Server on http://0.0.0.0:7070")
    app.run(host='0.0.0.0', port=7070, debug=True)
