import logging
import json
import requests
from flask import Blueprint, request, Response, jsonify
from src.config import Config

# Configure logging
logger = logging.getLogger(__name__)

# Create Blueprint for JMeter-compatible routes
# These routes directly map to service endpoints without using the /api/v1 prefix
jmeter_bp = Blueprint('jmeter', __name__)

@jmeter_bp.route('/authentication/<path:path>', methods=['GET', 'POST'])
def auth_route(path):
    """JMeter-compatible route that forwards requests to the authentication service"""
    logger.info(f"JMeter auth route called: {path}")
    
    # Forward the request to the authentication service
    target_url = f"{Config.AUTH_SERVICE_URL}/api/auth/{path}"
    logger.debug(f"Forwarding to: {target_url}")
    
    try:
        # Handle GET and POST requests differently
        if request.method == 'GET':
            # For GET requests, extract query parameters
            json_data = {}
            for key, value in request.args.items():
                json_data[key] = value
            logger.debug(f"GET request to auth/{path} with parameters: {json_data}")
        else:
            # For POST requests, extract JSON data from request body
            json_data = request.get_json(silent=True) or {}
            logger.debug(f"POST request to auth/{path} with JSON: {json_data}")
        
        # Extract authentication token from different possible sources
        auth_token = None
        if 'token' in request.headers:
            auth_token = request.headers.get('token')
            logger.info(f"Found token header: {auth_token[:10]}...")
        elif 'Authorization' in request.headers:
            auth_token = request.headers.get('Authorization')
            logger.info(f"Found Authorization header: {auth_token[:10]}...")
        else:
            logger.warning("No authentication token found in request headers")
            logger.debug(f"Headers received: {dict(request.headers)}")
        
        headers = {}
        if auth_token:
            if not auth_token.startswith('Bearer '):
                auth_token = f"Bearer {auth_token}"
                logger.info("Added 'Bearer ' prefix to auth token")
            headers['Authorization'] = auth_token
            logger.info(f"Using auth token in forwarded request: {auth_token[:15]}...")
        else:
            logger.warning("No auth token to forward to the backend service")
        
        logger.debug(f"Forwarding with headers: {headers}")
        
        # Forward the request
        if request.method == 'GET':
            # For GET requests, pass parameters as query params
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.args,
                timeout=Config.REQUEST_TIMEOUT
            )
        else:
            # For POST requests, include JSON in the body
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                json=json_data,
                timeout=Config.REQUEST_TIMEOUT
            )
        
        logger.debug(f"Auth response status: {resp.status_code}")
        logger.debug(f"Auth response content: {resp.content}")
        
        # Try to parse JSON response and format it for JMeter
        try:
            resp_data = resp.json()
            # For login responses, ensure token is included in the data
            if path == 'login' and resp.status_code == 200 and 'token' in resp_data:
                logger.info("Successfully processed login request")
                jmeter_response = {
                    "success": True,
                    "data": {
                        "token": resp_data.get('token', ''),
                        "account_type": resp_data.get('account_type', 'user')
                    }
                }
            else:
                # Standard response format
                jmeter_response = {
                    "success": resp.status_code < 400,  # Consider any non-error status as success
                    "data": resp_data.get('data', resp_data)
                }
                
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"Error parsing JSON response: {str(json_err)}")
            # Return a properly formatted JSON response even for non-JSON responses
            return Response(
                json.dumps({
                    "success": resp.status_code < 400,
                    "data": {"message": resp.text}
                }),
                status=resp.status_code,
                mimetype='application/json'
            )
    except Exception as e:
        logger.error(f"Error forwarding auth request: {str(e)}")
        return jsonify({"success": False, "data": {"error": str(e)}}), 500

@jmeter_bp.route('/transaction/<path:path>', methods=['GET', 'POST'])
def transaction_route(path):
    """JMeter-compatible route that forwards requests to the trading service"""
    logger.info(f"JMeter transaction route called: {path}")
    
    # Map transaction endpoints to proper trading service endpoints
    transaction_paths = {
        'getWalletBalance': 'wallet/balance/',
        'addMoneyToWallet': 'wallet/add-money/',
        'getStockPrices': 'stocks/prices/',
        'getStockPortfolio': 'stocks/portfolio/',
        'getStockTransactions': 'orders/list/',
        'getWalletTransactions': 'wallet/transactions/',
    }
    
    # Get the mapped path or use the original if not found
    normalized_path = transaction_paths.get(path, path)
    
    # Add debug logging for path mapping
    logger.info(f"Path mapping: '{path}' -> '{normalized_path}'")
    
    # Forward the request to the trading service
    target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
    logger.info(f"Forwarding to: {target_url}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request headers: {dict(request.headers)}")
    logger.info(f"Request args: {dict(request.args)}")
    
    try:
        # Extract authentication token from different possible sources
        auth_token = None
        if 'token' in request.headers:
            auth_token = request.headers.get('token')
        elif 'Authorization' in request.headers:
            auth_token = request.headers.get('Authorization')
        
        headers = {}
        if auth_token:
            if not auth_token.startswith('Bearer '):
                auth_token = f"Bearer {auth_token}"
            headers['Authorization'] = auth_token
        
        # Copy content type if present
        if 'Content-Type' in request.headers:
            headers['Content-Type'] = request.headers.get('Content-Type')
        
        # Handle GET and POST requests differently
        if request.method == 'GET':
            # For GET requests, forward query parameters
            resp = requests.get(target_url, headers=headers, params=request.args)
            logger.info(f"GET response status: {resp.status_code}")
            logger.debug(f"GET response content: {resp.text[:200]}...")
        else:
            # For POST requests, forward JSON data from request body
            json_data = request.get_json(silent=True) or {}
            logger.info(f"POST data: {json_data}")
            resp = requests.post(target_url, headers=headers, json=json_data)
            logger.info(f"POST response status: {resp.status_code}")
            logger.debug(f"POST response content: {resp.text[:200]}...")
        
        # Log unsuccessful responses with more detail
        if resp.status_code >= 400:
            logger.error(f"Error response from backend: {resp.status_code}")
            logger.error(f"Response content: {resp.text}")
            
        # Return the response from the service with the same status code
        return Response(resp.text, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    
    except Exception as e:
        logger.error(f"Error forwarding request to trading service: {str(e)}", exc_info=True)
        error_response = {"success": False, "data": {"detail": f"Error processing request: {str(e)}"}}
        return jsonify(error_response), 500

@jmeter_bp.route('/engine/<path:path>', methods=['GET', 'POST'])
def engine_route(path):
    """JMeter-compatible route that forwards requests to the matching engine"""
    logger.info(f"JMeter engine route called: {path}")
    
    # Map engine endpoints to proper trading service endpoints
    engine_paths = {
        'placeStockOrder': 'stocks/order/',
        'cancelStockTransaction': 'stocks/cancel-transaction/',
    }
    
    # Get the mapped path or use the original if not found
    normalized_path = engine_paths.get(path, path)
    
    # Forward the request to the trading service, not the matching engine
    target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
    logger.info(f"Forwarding to: {target_url}")
    
    try:
        # Extract authentication token from different possible sources
        auth_token = None
        if 'token' in request.headers:
            auth_token = request.headers.get('token')
        elif 'Authorization' in request.headers:
            auth_token = request.headers.get('Authorization')
        
        headers = {}
        if auth_token:
            if not auth_token.startswith('Bearer '):
                auth_token = f"Bearer {auth_token}"
            headers['Authorization'] = auth_token
        
        # Copy content type if present
        if 'Content-Type' in request.headers:
            headers['Content-Type'] = request.headers.get('Content-Type')
            
        # Handle GET and POST requests differently
        if request.method == 'GET':
            # For GET requests, forward query parameters
            resp = requests.get(target_url, headers=headers, params=request.args)
            logger.info(f"GET response status: {resp.status_code}")
        else:
            # For POST requests, forward JSON data from request body
            json_data = request.get_json(silent=True) or {}
            logger.info(f"POST data: {json_data}")
            resp = requests.post(target_url, headers=headers, json=json_data)
            logger.info(f"POST response status: {resp.status_code}")
        
        # Process the response
        try:
            resp_data = resp.json()
            # Format the response as expected by JMeter test
            jmeter_response = {
                "success": resp.status_code < 400,
                "data": resp_data.get('data', resp_data)
            }
            
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"Error parsing JSON response: {str(json_err)}")
            # Return a properly formatted JSON response even for non-JSON responses
            return Response(
                json.dumps({
                    "success": resp.status_code < 400,
                    "data": {"message": resp.text}
                }),
                status=resp.status_code,
                mimetype='application/json'
            )
    except Exception as e:
        logger.error(f"Error forwarding engine request: {str(e)}")
        return jsonify({"success": False, "data": {"error": str(e)}}), 500

@jmeter_bp.route('/setup/<path:path>', methods=['GET', 'POST'])
def setup_route(path):
    """JMeter-compatible route that forwards setup requests to the trading service"""
    logger.info(f"JMeter setup route called: {path}")
    
    # Map setup endpoints to proper trading service endpoints
    setup_paths = {
        'createStock': 'stocks/create/',
        'addStockToUser': 'stocks/add-to-user/',
        # Adding any other mappings needed by JMeter tests
        'addMoneyToWallet': 'wallet/add-money/',
        'getWalletBalance': 'wallet/balance/'
    }
    
    # Get the mapped path or use the original if not found
    normalized_path = setup_paths.get(path, path)
    target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
    
    logger.debug(f"Setup proxy mapping {path} to {normalized_path}")
    logger.debug(f"Forwarding to target URL: {target_url}")
    
    try:
        # Handle GET and POST requests differently
        if request.method == 'GET':
            # For GET requests, extract query parameters
            json_data = {}
            for key, value in request.args.items():
                json_data[key] = value
            logger.debug(f"GET request to setup/{path} with parameters: {json_data}")
        else:
            # For POST requests, extract JSON data from request body
            json_data = request.get_json(silent=True) or {}
            logger.debug(f"POST request to setup/{path} with JSON: {json_data}")
        
        # Extract authentication token from different possible sources
        auth_token = None
        if 'Authorization' in request.headers:
            auth_token = request.headers['Authorization']
            logger.debug(f"Found token in Authorization header: {auth_token[:20]}...")
        elif 'token' in request.headers:
            auth_token = f"Bearer {request.headers['token']}"
            logger.debug(f"Found token in token header: {auth_token[:20]}...")
        elif 'token' in json_data:
            auth_token = f"Bearer {json_data['token']}"
            logger.debug(f"Found token in JSON data: {auth_token[:20]}...")
            # Remove token from JSON data to avoid duplication
            json_data.pop('token', None)
        elif 'token' in request.args:
            auth_token = f"Bearer {request.args.get('token')}"
            logger.debug(f"Found token in query parameters: {auth_token[:20]}...")
        
        # Create headers dictionary with authentication if available
        headers = {'Content-Type': 'application/json'}
        if auth_token:
            headers['Authorization'] = auth_token
        
        logger.debug(f"Forwarding with headers: {headers}")
        
        # Forward the request
        if request.method == 'GET':
            # For GET requests, pass parameters as query params
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.args,
                timeout=Config.REQUEST_TIMEOUT
            )
        else:
            # For POST requests, include JSON in the body
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                json=json_data,
                timeout=Config.REQUEST_TIMEOUT
            )
        
        logger.debug(f"Response status: {resp.status_code}")
        logger.debug(f"Response content: {resp.content}")
        
        # Get response JSON if available
        try:
            resp_data = resp.json()
            # Format response to match JMeter test expectations
            jmeter_response = {
                "success": resp.status_code < 400,  # Consider any non-error status as success
                "data": resp_data.get('data', resp_data)
            }
            
            # Return formatted response
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"Error parsing JSON response: {str(json_err)}")
            # Return a properly formatted JSON response even for non-JSON responses
            return Response(
                json.dumps({
                    "success": resp.status_code < 400,
                    "data": {"message": resp.text}
                }),
                status=resp.status_code,
                mimetype='application/json'
            )
        
    except requests.Timeout:
        logger.error(f"Timeout connecting to trading service")
        return Response(
            json.dumps({"success": False, "data": {"error": "Trading service timeout"}}),
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError:
        logger.error(f"Connection error with trading service")
        return Response(
            json.dumps({"success": False, "data": {"error": "Trading service unavailable"}}),
            status=503,
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"Error forwarding setup request: {str(e)}")
        return jsonify({"success": False, "data": {"error": str(e)}}), 500