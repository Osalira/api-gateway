from flask import Blueprint, request, Response, current_app, jsonify
import requests
from functools import wraps
import time
from prometheus_client import Counter, Histogram
from ..config import Config
import logging
import websocket
import json

# Create logger
logger = logging.getLogger(__name__)

# Create Blueprint
gateway_bp = Blueprint('gateway', __name__)

# Metrics
REQUEST_COUNT = Counter('gateway_requests_total', 'Total gateway requests', ['service', 'endpoint', 'method', 'status'])
REQUEST_LATENCY = Histogram('gateway_request_latency_seconds', 'Request latency', ['service', 'endpoint'])

# WebSocket client connections
ws_clients = {}

def handle_websocket(ws):
    """Handle WebSocket connections and message forwarding"""
    client_id = id(ws)
    me_ws = None
    auth_token = None
    
    try:
        logger.info(f"New WebSocket connection established. Client ID: {client_id}")
        
        # Get and validate protocols
        requested_protocols = ws.environ.get('HTTP_SEC_WEBSOCKET_PROTOCOL', '').split(',')
        requested_protocols = [p.strip() for p in requested_protocols if p.strip()]
        
        if not requested_protocols or 'trading-protocol' not in requested_protocols:
            logger.warning(f"Client {client_id} did not request trading-protocol")
            ws.send(json.dumps({
                "type": "error",
                "message": "Protocol 'trading-protocol' is required"
            }))
            return

        # Send initial success message
        ws.send(json.dumps({
            "type": "connection",
            "status": "connecting",
            "message": "WebSocket connection established with API Gateway"
        }))

        # Wait for authentication message
        try:
            auth_message = ws.receive(timeout=5.0)  # 5 second timeout for auth
            if not auth_message:
                logger.warning(f"Client {client_id} did not send authentication message")
                ws.send(json.dumps({
                    "type": "error",
                    "message": "Authentication timeout"
                }))
                return
            
            try:
                data = json.loads(auth_message)
                if data.get('type') != 'auth' or not data.get('token'):
                    logger.warning(f"Client {client_id} sent invalid authentication message")
                    ws.send(json.dumps({
                        "type": "error",
                        "message": "Invalid authentication message"
                    }))
                    return
                auth_token = data['token']
            except json.JSONDecodeError:
                logger.warning(f"Client {client_id} sent invalid JSON for authentication")
                ws.send(json.dumps({
                    "type": "error",
                    "message": "Invalid authentication format"
                }))
                return
        except Exception as e:
            logger.warning(f"Authentication error for client {client_id}: {str(e)}")
            ws.send(json.dumps({
                "type": "error",
                "message": "Authentication failed"
            }))
            return

        # Connect to matching engine with retry logic
        max_retries = 3
        retry_delay = 1  # seconds
        me_ws_url = f"ws://{Config.MATCHING_ENGINE_URL.replace('http://', '')}/ws"
        
        for attempt in range(max_retries):
            try:
                logger.debug(f"Attempt {attempt + 1}/{max_retries} to connect to matching engine at {me_ws_url}")
                
                me_ws = websocket.create_connection(
                    me_ws_url,
                    subprotocols=['trading-protocol'],
                    header={
                        "Authorization": f"Bearer {auth_token}",
                        "Origin": ws.environ.get('HTTP_ORIGIN', 'http://localhost:5173')
                    },
                    enable_multithread=True,
                    timeout=10  # 10 second timeout for connection
                )
                
                logger.info(f"Successfully connected to matching engine WebSocket on attempt {attempt + 1}")
                
                # Send success message to client
                ws.send(json.dumps({
                    "type": "connection",
                    "status": "ready",
                    "message": "Connected to trading service"
                }))
                
                break
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {str(e)}", exc_info=True)
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("Failed to connect to matching engine after all retries")
                    ws.send(json.dumps({
                        "type": "error",
                        "message": "Failed to connect to trading service",
                        "details": str(e)
                    }))
                    return

        # Message forwarding loop with improved error handling
        last_ping_time = time.time()
        ping_interval = 30  # seconds
        
        while not ws.closed and not (me_ws and me_ws.closed):
            try:
                # Send ping if needed
                current_time = time.time()
                if current_time - last_ping_time >= ping_interval:
                    ws.send(json.dumps({"type": "ping"}))
                    last_ping_time = current_time
                
                # Handle client messages with timeout
                try:
                    message = ws.receive(timeout=1.0)
                    if message:
                        try:
                            data = json.loads(message)
                            if data.get('type') == 'pong':
                                continue
                            me_ws.send(message)
                        except json.JSONDecodeError:
                            logger.warning(f"Received invalid JSON from client: {message}")
                            continue
                except Exception as e:
                    if "timed out" not in str(e).lower():
                        raise

                # Handle matching engine messages with timeout
                if me_ws and me_ws.connected:
                    try:
                        me_ws.settimeout(0.1)
                        response = me_ws.recv()
                        if response:
                            ws.send(response)
                    except websocket.WebSocketTimeoutException:
                        continue
                    except Exception as e:
                        logger.error(f"Error receiving from matching engine: {str(e)}")
                        break

            except Exception as e:
                if "timed out" not in str(e).lower():
                    logger.error(f"Error in message forwarding loop: {str(e)}")
                    break

    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {str(e)}", exc_info=True)
        try:
            if not ws.closed:
                ws.send(json.dumps({
                    "type": "error",
                    "message": "Internal server error",
                    "details": str(e)
                }))
        except:
            pass
            
    finally:
        logger.info(f"Cleaning up WebSocket connection for client {client_id}")
        if me_ws:
            try:
                me_ws.close()
                logger.debug("Closed matching engine connection")
            except Exception as e:
                logger.error(f"Error closing matching engine connection: {str(e)}")
        
        if not ws.closed:
            try:
                ws.close()
                logger.debug("Closed client connection")
            except Exception as e:
                logger.error(f"Error closing client connection: {str(e)}")
                
        logger.info("WebSocket cleanup complete")

# Circuit breaker state
circuit_breakers = {
    'auth': {'failures': 0, 'last_failure': 0, 'state': 'closed'},
    'trading': {'failures': 0, 'last_failure': 0, 'state': 'closed'},
    'matching-engine': {'failures': 0, 'last_failure': 0, 'state': 'closed'},
    'logging': {'failures': 0, 'last_failure': 0, 'state': 'closed'}
}

def check_circuit_breaker(service):
    """Circuit breaker decorator for service calls"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            breaker = circuit_breakers[service]
            
            # Check if circuit is open
            if breaker['state'] == 'open':
                # Check if timeout has passed
                if time.time() - breaker['last_failure'] > Config.CIRCUIT_BREAKER_TIMEOUT:
                    breaker['state'] = 'half-open'
                else:
                    return Response(
                        '{"error": "Service temporarily unavailable"}',
                        status=503,
                        mimetype='application/json'
                    )
            
            try:
                result = f(*args, **kwargs)
                
                # Reset circuit breaker on success
                if breaker['state'] == 'half-open':
                    breaker['state'] = 'closed'
                    breaker['failures'] = 0
                
                return result
                
            except Exception as e:
                breaker['failures'] += 1
                breaker['last_failure'] = time.time()
                
                # Open circuit if threshold reached
                if breaker['failures'] >= Config.CIRCUIT_BREAKER_THRESHOLD:
                    breaker['state'] = 'open'
                
                raise e
                
        return wrapped
    return decorator

def proxy_request(target_url, include_headers=None):
    """
    Forward request to target service and return response
    
    Args:
        target_url (str): URL to forward request to
        include_headers (list): List of headers to forward
    """
    # Start timing
    start_time = time.time()
    
    try:
        # Get headers to forward
        headers = {}
        if include_headers:
            for header in include_headers:
                if header in request.headers:
                    print(f"Forwarding header: {header}")
                    headers[header] = request.headers[header]
        
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        # Update metrics
        REQUEST_COUNT.labels(
            service=target_url.split('/')[2],
            endpoint=request.path,
            method=request.method,
            status=resp.status_code
        ).inc()
        
        REQUEST_LATENCY.labels(
            service=target_url.split('/')[2],
            endpoint=request.path
        ).observe(time.time() - start_time)
        
        # Return response
        return Response(
            resp.content,
            status=resp.status_code,
            mimetype=resp.headers.get('content-type', 'application/json')
        )
        
    except requests.Timeout:
        return Response(
            '{"error": "Service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError:
        return Response(
            '{"error": "Service unavailable"}',
            status=503,
            mimetype='application/json'
        )
    except Exception as e:
        current_app.logger.error(f"Proxy error: {str(e)}")
        return Response(
            '{"error": "Internal server error"}',
            status=500,
            mimetype='application/json'
        )

# Auth Service Routes
@gateway_bp.route('/auth/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('auth')
def auth_proxy(path):
    """Proxy requests to auth service"""
    target_url = f"{Config.AUTH_SERVICE_URL}/api/auth/{path}"
    return proxy_request(target_url, include_headers=['Authorization'])

# Trading Service Routes
@gateway_bp.route('/trading/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@check_circuit_breaker('trading')
def trading_proxy(path):
    """Proxy requests to trading service"""
    # Log request details
    logger.debug(f"Trading proxy received request for path: {path}")
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request headers: {request.headers}")
    logger.debug(f"Request data: {request.get_json() if request.is_json else None}")
    
    # Always append trailing slash for Django
    normalized_path = path.rstrip('/') + '/'
    
    # Construct target URL with trailing slash
    target_url = f"{Config.SERVICE_REGISTRY['trading']['url']}/api/trading/{normalized_path}"
    logger.debug(f"Forwarding to target URL: {target_url}")
    
    # Forward the Authorization and Content-Type headers
    headers_to_forward = ['Authorization', 'Content-Type']
    headers = {}
    for header in headers_to_forward:
        if header in request.headers:
            logger.debug(f"Forwarding header: {header}")
            headers[header] = request.headers[header]
    
    start_time = time.time()
    
    try:
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        # Update metrics
        REQUEST_COUNT.labels(
            service='trading',
            endpoint=request.path,
            method=request.method,
            status=resp.status_code
        ).inc()
        
        REQUEST_LATENCY.labels(
            service='trading',
            endpoint=request.path
        ).observe(time.time() - start_time)
        
        return Response(
            resp.content,
            status=resp.status_code,
            mimetype=resp.headers.get('content-type', 'application/json')
        )
        
    except requests.Timeout:
        return Response(
            '{"error": "Trading service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError:
        return Response(
            '{"error": "Trading service unavailable"}',
            status=503,
            mimetype='application/json'
        )

# Matching Engine Routes
@gateway_bp.route('/matching/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('matching-engine')
def matching_proxy(path):
    """Proxy requests to matching engine"""
    target_url = f"{Config.MATCHING_ENGINE_URL}/api/{path}"
    return proxy_request(target_url, include_headers=['Authorization'])

# Test script routes - Authentication endpoints
@gateway_bp.route('/authentication/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('auth')
def auth_test_proxy(path):
    """Proxy test script authentication requests to auth service"""
    logger.debug(f"[AUTH TEST PROXY] Received request for path: {path}")
    logger.debug(f"[AUTH TEST PROXY] Request method: {request.method}")
    logger.debug(f"[AUTH TEST PROXY] Request headers: {request.headers}")
    logger.debug(f"[AUTH TEST PROXY] Request JSON data: {request.get_json() if request.is_json else None}")
    
    target_url = f"{Config.AUTH_SERVICE_URL}/api/auth/{path}"
    logger.debug(f"[AUTH TEST PROXY] Forwarding to: {target_url}")
    
    try:
        # Get headers to forward
        headers = {}
        for header in ['Authorization', 'Content-Type']:
            if header in request.headers:
                headers[header] = request.headers[header]
        
        logger.debug(f"[AUTH TEST PROXY] Forwarding headers: {headers}")
        
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        logger.debug(f"[AUTH TEST PROXY] Response status: {resp.status_code}")
        logger.debug(f"[AUTH TEST PROXY] Response headers: {resp.headers}")
        logger.debug(f"[AUTH TEST PROXY] Response content: {resp.content}")
        
        # Get response JSON if available
        try:
            resp_data = resp.json()
            logger.debug(f"[AUTH TEST PROXY] Parsed JSON: {resp_data}")
            
            # Format response to match JMeter test expectations
            jmeter_response = {
                "success": resp_data.get('success', True),
                "data": resp_data.get('data', {})
            }
            
            logger.debug(f"[AUTH TEST PROXY] Formatted response: {jmeter_response}")
            
            # Return formatted response
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"[AUTH TEST PROXY] JSON parsing error: {str(json_err)}")
            # Return the raw response if not JSON
            return Response(
                resp.content,
                status=resp.status_code,
                mimetype=resp.headers.get('content-type', 'application/json')
            )
        
    except requests.Timeout:
        logger.error("[AUTH TEST PROXY] Request timed out")
        return Response(
            '{"success": false, "error": "Auth service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError as conn_err:
        logger.error(f"[AUTH TEST PROXY] Connection error: {str(conn_err)}")
        return Response(
            '{"success": false, "error": "Auth service unavailable"}',
            status=503,
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"[AUTH TEST PROXY] Unexpected error: {str(e)}")
        return Response(
            f'{{"success": false, "error": "{str(e)}"}}',
            status=500,
            mimetype='application/json'
        )

# Test script routes - Transaction endpoints
@gateway_bp.route('/transaction/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('trading')
def transaction_test_proxy(path):
    """Proxy test script transaction requests to trading service"""
    # Map transaction endpoints to proper trading service endpoints
    trading_paths = {
        'getStockPrices': 'stocks/prices/',
        'getStockPortfolio': 'stocks/portfolio/',
        'getStockTransactions': 'orders/list/',
        'addMoneyToWallet': 'wallet/add-money/',
        'getWalletBalance': 'wallet/balance/',
        'getWalletTransactions': 'wallet/transactions/',
    }
    
    logger.debug(f"[TRANSACTION TEST PROXY] Received request for path: {path}")
    logger.debug(f"[TRANSACTION TEST PROXY] Request method: {request.method}")
    logger.debug(f"[TRANSACTION TEST PROXY] Request headers: {request.headers}")
    logger.debug(f"[TRANSACTION TEST PROXY] Request JSON data: {request.get_json() if request.is_json else None}")
    
    # Get the mapped path or use the original if not found
    normalized_path = trading_paths.get(path, path)
    target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
    
    logger.debug(f"[TRANSACTION TEST PROXY] Transaction proxy mapping {path} to {normalized_path}")
    logger.debug(f"[TRANSACTION TEST PROXY] Forwarding to target URL: {target_url}")
    
    try:
        # Get headers to forward
        headers = {}
        for header in ['Authorization', 'Content-Type', 'token']:
            if header in request.headers:
                # Special handling for token header
                if header == 'token':
                    headers['Authorization'] = f"Bearer {request.headers['token']}"
                else:
                    headers[header] = request.headers[header]
        
        logger.debug(f"[TRANSACTION TEST PROXY] Forwarding headers: {headers}")
        
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        logger.debug(f"[TRANSACTION TEST PROXY] Response status: {resp.status_code}")
        logger.debug(f"[TRANSACTION TEST PROXY] Response headers: {resp.headers}")
        logger.debug(f"[TRANSACTION TEST PROXY] Response content: {resp.content}")
        
        # Get response JSON if available
        try:
            resp_data = resp.json()
            logger.debug(f"[TRANSACTION TEST PROXY] Parsed JSON: {resp_data}")
            
            # Format response to match JMeter test expectations
            jmeter_response = {
                "success": True,
                "data": resp_data.get('data', resp_data)
            }
            
            logger.debug(f"[TRANSACTION TEST PROXY] Formatted response: {jmeter_response}")
            
            # Return formatted response
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"[TRANSACTION TEST PROXY] JSON parsing error: {str(json_err)}")
            # Return the raw response if not JSON
            return Response(
                resp.content,
                status=resp.status_code,
                mimetype=resp.headers.get('content-type', 'application/json')
            )
        
    except requests.Timeout:
        logger.error("[TRANSACTION TEST PROXY] Request timed out")
        return Response(
            '{"success": false, "error": "Trading service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError as conn_err:
        logger.error(f"[TRANSACTION TEST PROXY] Connection error: {str(conn_err)}")
        return Response(
            '{"success": false, "error": "Trading service unavailable"}',
            status=503,
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"[TRANSACTION TEST PROXY] Unexpected error: {str(e)}")
        return Response(
            f'{{"success": false, "error": "{str(e)}"}}',
            status=500,
            mimetype='application/json'
        )

# Test script routes - Engine endpoints
@gateway_bp.route('/engine/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('matching-engine')
def engine_test_proxy(path):
    """Proxy test script engine requests to matching engine"""
    logger.debug(f"[ENGINE TEST PROXY] Received request for path: {path}")
    logger.debug(f"[ENGINE TEST PROXY] Request method: {request.method}")
    logger.debug(f"[ENGINE TEST PROXY] Request headers: {request.headers}")
    logger.debug(f"[ENGINE TEST PROXY] Request JSON data: {request.get_json() if request.is_json else None}")
    
    # Map engine endpoints to proper endpoints
    engine_paths = {
        'placeStockOrder': 'orders/place/',
        'cancelStockTransaction': 'orders/cancel/',
    }
    
    # Get the mapped path or use the original if not found
    if path in engine_paths:
        # Use trading service for these operations
        normalized_path = engine_paths.get(path, path)
        target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
        logger.debug(f"[ENGINE TEST PROXY] Engine proxy mapping {path} to trading service: {normalized_path}")
    else:
        # Use matching engine as fallback
        target_url = f"{Config.MATCHING_ENGINE_URL}/{path}"
        logger.debug(f"[ENGINE TEST PROXY] Using matching engine fallback for {path}")
    
    logger.debug(f"[ENGINE TEST PROXY] Forwarding to target URL: {target_url}")
    
    try:
        # Get headers to forward
        headers = {}
        for header in ['Authorization', 'Content-Type', 'token']:
            if header in request.headers:
                # Special handling for token header
                if header == 'token':
                    headers['Authorization'] = f"Bearer {request.headers['token']}"
                else:
                    headers[header] = request.headers[header]
        
        logger.debug(f"[ENGINE TEST PROXY] Forwarding headers: {headers}")
        
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        logger.debug(f"[ENGINE TEST PROXY] Response status: {resp.status_code}")
        logger.debug(f"[ENGINE TEST PROXY] Response headers: {resp.headers}")
        logger.debug(f"[ENGINE TEST PROXY] Response content: {resp.content}")
        
        # Get response JSON if available
        try:
            resp_data = resp.json()
            logger.debug(f"[ENGINE TEST PROXY] Parsed JSON: {resp_data}")
            
            # Format response to match JMeter test expectations
            jmeter_response = {
                "success": True,
                "data": resp_data.get('data', resp_data)
            }
            
            logger.debug(f"[ENGINE TEST PROXY] Formatted response: {jmeter_response}")
            
            # Return formatted response
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except Exception as json_err:
            logger.error(f"[ENGINE TEST PROXY] JSON parsing error: {str(json_err)}")
            # Return the raw response if not JSON
            return Response(
                resp.content,
                status=resp.status_code,
                mimetype=resp.headers.get('content-type', 'application/json')
            )
        
    except requests.Timeout:
        logger.error("[ENGINE TEST PROXY] Request timed out")
        return Response(
            '{"success": false, "error": "Service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError as conn_err:
        logger.error(f"[ENGINE TEST PROXY] Connection error: {str(conn_err)}")
        return Response(
            '{"success": false, "error": "Service unavailable"}',
            status=503,
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"[ENGINE TEST PROXY] Unexpected error: {str(e)}")
        return Response(
            f'{{"success": false, "error": "{str(e)}"}}',
            status=500,
            mimetype='application/json'
        )

# Test script routes - Setup endpoints
@gateway_bp.route('/setup/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('trading')
def setup_test_proxy(path):
    """Proxy test script setup requests to trading service"""
    # Map setup endpoints to proper trading service endpoints
    setup_paths = {
        'createStock': 'stocks/create/',
        'addStockToUser': 'stocks/add-to-user/',
    }
    
    # Get the mapped path or use the original if not found
    normalized_path = setup_paths.get(path, path)
    target_url = f"{Config.TRADING_SERVICE_URL}/api/trading/{normalized_path}"
    
    logger.debug(f"Setup proxy mapping {path} to {normalized_path}")
    logger.debug(f"Forwarding to target URL: {target_url}")
    
    try:
        # Get headers to forward
        headers = {}
        for header in ['Authorization', 'Content-Type', 'token']:
            if header in request.headers:
                # Special handling for token header
                if header == 'token':
                    headers['Authorization'] = f"Bearer {request.headers['token']}"
                else:
                    headers[header] = request.headers[header]
        
        # Forward the request
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            json=request.get_json() if request.is_json else None,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        # Get response JSON if available
        try:
            resp_data = resp.json()
            # Format response to match JMeter test expectations
            jmeter_response = {
                "success": True,
                "data": resp_data.get('data', resp_data)
            }
            
            # Return formatted response
            return Response(
                json.dumps(jmeter_response),
                status=resp.status_code,
                mimetype='application/json'
            )
        except:
            # Return the raw response if not JSON
            return Response(
                resp.content,
                status=resp.status_code,
                mimetype=resp.headers.get('content-type', 'application/json')
            )
        
    except requests.Timeout:
        return Response(
            '{"success": false, "error": "Trading service timeout"}',
            status=504,
            mimetype='application/json'
        )
    except requests.ConnectionError:
        return Response(
            '{"success": false, "error": "Trading service unavailable"}',
            status=503,
            mimetype='application/json'
        )

# Logging Service Routes
@gateway_bp.route('/logs/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('logging')
def logging_proxy(path):
    """Proxy requests to logging service"""
    target_url = f"{Config.LOGGING_SERVICE_URL}/api/v1/logs/{path}"
    return proxy_request(target_url, include_headers=['Authorization'])

# Health Check Routes
@gateway_bp.route('/health')
def health():
    """Check health of all services"""
    services_health = {}
    
    for service, config in Config.SERVICE_REGISTRY.items():
        try:
            resp = requests.get(
                f"{config['url']}/health",
                timeout=config['timeout']
            )
            services_health[service] = {
                'status': 'healthy' if resp.status_code == 200 else 'unhealthy',
                'code': resp.status_code
            }
        except Exception:
            services_health[service] = {
                'status': 'unhealthy',
                'code': 503
            }
    
    overall_status = all(
        s['status'] == 'healthy' for s in services_health.values()
    )
    
    return {
        'status': 'healthy' if overall_status else 'degraded',
        'services': services_health
    }, 200 if overall_status else 503 