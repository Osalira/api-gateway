from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import requests
import logging
import os
from dotenv import load_dotenv
import json
from functools import wraps
from datetime import datetime
import time

# Load environment variables
load_dotenv()

# Configure basic logging first (will be enhanced after app creation)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/api_gateway.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app - MOVED UP before any app references
app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

# Configure CORS
CORS(app)

# Service URLs
AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://auth-service:5000')
TRADING_SERVICE_URL = os.getenv('TRADING_SERVICE_URL', 'http://trading-service:8000')
MATCHING_ENGINE_URL = os.getenv('MATCHING_ENGINE_URL', 'http://matching-engine:8080')
LOGGING_SERVICE_URL = os.getenv('LOGGING_SERVICE_URL', 'http://logging-service:5000')

# Request timeout
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))

# Rate limiting settings
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', 100))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60))

# Circuit breaker settings
CIRCUIT_BREAKER_ENABLED = os.getenv('CIRCUIT_BREAKER_ENABLED', 'True').lower() == 'true'
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', 5))
CIRCUIT_BREAKER_TIMEOUT = int(os.getenv('CIRCUIT_BREAKER_TIMEOUT', 60))

# Authorization middleware that delegates token validation to Auth Service
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Extract token from various sources
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                token = auth_header
        elif 'token' in request.headers:
            token = request.headers['token']
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        try:
            # Call Auth Service to validate token
            response = requests.post(
                f"{AUTH_SERVICE_URL}/authentication/validate-token",
                headers={"Content-Type": "application/json"},
                json={"token": token},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code != 200:
                error_msg = response.json().get('error', 'Invalid token')
                return jsonify({'success': False, 'error': error_msg}), 401
                
            # Extract user info from response
            response_data = response.json()
            if not response_data.get('success', False):
                error_msg = response_data.get('error', 'Token validation failed')
                return jsonify({'success': False, 'error': error_msg}), 401
                
            user_info = response_data['data']['user']
            
            # Set user info on request object
            request.user = user_info
            request.user_id = user_info.get('id')
            request.username = user_info.get('username')
            request.account_type = user_info.get('account_type')
            
            return f(*args, **kwargs)
            
        except requests.exceptions.Timeout:
            return jsonify({'success': False, 'error': 'Authentication service timeout'}), 504
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Authentication service unavailable'}), 503
        except Exception as e:
            return jsonify({'success': False, 'error': f'Authentication error: {str(e)}'}), 500
    
    return decorated

# Function to format all responses to match JMeter expectations
def format_response_for_jmeter(response):
    """
    Takes an API response and ensures it matches the format expected by JMeter:
    {
        "success": true/false,
        "data": { ... original response content ... }
    }
    """
    # Don't transform responses that are not JSON
    if not response.is_json:
        return response
    
    # Get the response data
    response_data = response.get_json()
    
    # If the response already has a 'success' field at the top level, it's already correctly formatted
    if 'success' in response_data:
        return response
        
    # Create the transformed response
    transformed_data = {
        "success": response.status_code < 400,  # Success is true for HTTP 2xx and 3xx
        "data": response_data
    }
    
    # Create a new response with the transformed data
    return jsonify(transformed_data), response.status_code

# Function to forward request to a service
def forward_request(service_url, path, method='GET', headers=None, data=None, params=None):
    try:
        url = f"{service_url}{path}"
        logger.info(f"Forwarding {method} request to {url}")
        
        # Prepare headers
        if headers is None:
            headers = {}
        
        # Remove host header to avoid conflicts
        if 'Host' in headers:
            del headers['Host']
            
        # Ensure proper content type headers for Django
        # Check for both /api/ and api/ formats to be safe
        if 'api/transaction/' in path or 'api/setup/' in path:
            # Force application/json content-type for Django
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            
        # Handle JWT token authentication formats
        token = None
        
        # Extract token from Authorization header with Bearer prefix
        if 'Authorization' in headers and headers['Authorization'].startswith('Bearer '):
            token = headers['Authorization'].split('Bearer ')[1]
            # Don't modify the Authorization header as it's already properly formatted
            # But also add token header for services that expect it
            headers['token'] = token
            logger.debug("Found and extracted token from Authorization header")
            
        # Or use token header directly if Authorization not available
        elif 'token' in headers:
            token = headers['token']
            # Add the token to Authorization header for services that expect that format
            headers['Authorization'] = f"Bearer {token}"
            logger.debug("Found token in token header, added to Authorization header")
            
        # Add detailed debugging for headers
        for key, value in headers.items():
            # Only show first/last 10 chars of long values like tokens
            value_log = value
            if len(value) > 30 and (key.lower() == 'authorization' or key.lower() == 'token'):
                value_log = f"{value[:10]}...{value[-10:]}"
            logger.debug(f"Header: {key}: {value_log}")
            
        # Log the request headers and data for debugging
        logger.debug(f"Request data: {data}")
            
        # Forward the request to the service
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=data,  # Use json parameter for JSON data
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        
        # Log the response
        logger.info(f"Response from {url}: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        
        # Try to parse the response as JSON
        try:
            json_data = response.json()
            # Format the response to match JMeter expectations
            return jsonify({
                "success": response.status_code < 400,
                "data": json_data
            }), response.status_code
        except ValueError:
            # Response is not JSON, return it as is
            logger.warning(f"Non-JSON response from {url}: {response.text[:200]}")
            return response.content, response.status_code, {"Content-Type": response.headers.get("Content-Type", "text/plain")}
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout when forwarding to {service_url}{path}")
        return jsonify({
            "success": False,
            "data": {"error": "Service timeout"}
        }), 504
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error when forwarding to {service_url}{path}")
        return jsonify({
            "success": False,
            "data": {"error": "Service unavailable"}
        }), 503
    except Exception as e:
        logger.error(f"Error forwarding request to {service_url}{path}: {str(e)}")
        return jsonify({
            "success": False,
            "data": {"error": f"Internal server error: {str(e)}"}
        }), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "api-gateway"})

# Authentication routes
@app.route('/authentication/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def auth_service_proxy(path):
    # Log the authentication request
    logger.info(f"Authentication request: {request.method} {path}")
    
    return forward_request(
        service_url=AUTH_SERVICE_URL,
        path=f"/authentication/{path}",
        method=request.method,
        headers=dict(request.headers),
        data=request.get_json() if request.is_json else None,
        params=request.args
    )

# Transaction routes (require authentication)
@app.route('/transaction/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def transaction_service_proxy(path):
    # Log the transaction request
    logger.info(f"Transaction request: {request.method} {path}")
    
    # Create a copy of the headers and add user_id
    headers = dict(request.headers)
    if hasattr(request, 'user_id'):
        headers['user_id'] = str(request.user_id)
    
    # Handle data appropriately based on request method
    data = None
    if request.method in ['POST', 'PUT'] and request.is_json:
        data = request.get_json()
    
    # For GET requests, ensure we don't send a body
    params = request.args
    if request.method == 'GET':
        data = None
    
    # Make sure we're using the correct URL format for Django
    # Django API endpoints include 'api/' in the URL path
    django_path = path
    if not path.startswith('api/'):
        django_path = f"api/transaction/{path}"
    
    return forward_request(
        service_url=TRADING_SERVICE_URL,
        path=f"/{django_path}",
        method=request.method,
        headers=headers,
        data=data,
        params=params
    )

# Engine routes (require authentication)
@app.route('/engine/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def engine_service_proxy(path):
    # Log the engine request
    logger.info(f"Engine request: {request.method} {path}")
    
    # Create a copy of the headers and add user_id
    headers = dict(request.headers)
    if hasattr(request, 'user_id'):
        headers['user_id'] = str(request.user_id)
    
    # Handle data appropriately based on request method
    data = None
    if request.method in ['POST', 'PUT'] and request.is_json:
        data = request.get_json()
    
    # For GET requests, ensure we don't send a body
    params = request.args
    if request.method == 'GET':
        data = None
    
    # Make sure we're using the correct URL format for the engine
    # Engine API endpoints include 'api/' in the URL path
    if not path.startswith('api/'):
        path = f"api/{path}"
    
    return forward_request(
        service_url=MATCHING_ENGINE_URL,
        path=f"/{path}",
        method=request.method,
        headers=headers,
        data=data,
        params=params
    )

# Setup routes (admin only, require authentication)
@app.route('/setup/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def setup_service_proxy(path):
    # Verify admin privileges
    if not hasattr(request, 'account_type') or request.account_type != 'admin':
        return jsonify({"success": False, "error": "Admin privileges required"}), 403
    
    # Log the setup request
    logger.info(f"Setup request: {request.method} {path}")
    
    # Create a copy of the headers and add user_id
    headers = dict(request.headers)
    if hasattr(request, 'user_id'):
        headers['user_id'] = str(request.user_id)
    
    # Handle data appropriately based on request method
    data = None
    if request.method in ['POST', 'PUT'] and request.is_json:
        data = request.get_json()
    
    # For GET requests, ensure we don't send a body
    params = request.args
    if request.method == 'GET':
        data = None
    
    # Make sure we're using the correct URL format for Django
    # Django API endpoints include 'api/' in the URL path
    django_path = path
    if not path.startswith('api/'):
        django_path = f"api/setup/{path}"
    
    return forward_request(
        service_url=TRADING_SERVICE_URL,
        path=f"/{django_path}",
        method=request.method,
        headers=headers,
        data=data,
        params=params
    )

# Logging routes (admin only, require authentication)
@app.route('/logs/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def logging_service_proxy(path):
    # Verify admin privileges
    if not hasattr(request, 'account_type') or request.account_type != 'admin':
        return jsonify({"success": False, "error": "Admin privileges required"}), 403
    
    # Log the logging request
    logger.info(f"Logging request: {request.method} {path}")
    
    # Create a copy of the headers and add user_id
    headers = dict(request.headers)
    if hasattr(request, 'user_id'):
        headers['user_id'] = str(request.user_id)
    
    # Handle data appropriately based on request method
    data = None
    if request.method in ['POST', 'PUT'] and request.is_json:
        data = request.get_json()
    
    # For GET requests, ensure we don't send a body
    params = request.args
    if request.method == 'GET':
        data = None
    
    return forward_request(
        service_url=LOGGING_SERVICE_URL,
        path=f"/{path}",
        method=request.method,
        headers=headers,
        data=data,
        params=params
    )

# Catch-all route for 404s
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    return jsonify({"success": False, "error": f"Endpoint '/{path}' not found"}), 404

if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true') 