from flask import Blueprint, request, Response, current_app, jsonify
import requests
from functools import wraps
import time
from prometheus_client import Counter, Histogram
from ..config import Config
import logging
import websocket
from flask_sock import Sock
import json

# Create logger
logger = logging.getLogger(__name__)

# Create Blueprint
gateway_bp = Blueprint('gateway', __name__)

# Initialize Sock with the blueprint
sock = Sock(gateway_bp)

# Metrics
REQUEST_COUNT = Counter('gateway_requests_total', 'Total gateway requests', ['service', 'endpoint', 'method', 'status'])
REQUEST_LATENCY = Histogram('gateway_request_latency_seconds', 'Request latency', ['service', 'endpoint'])

# WebSocket client connections
ws_clients = {}

def handle_websocket(ws):
    """Handle WebSocket connections and proxy them to the matching engine"""
    client_id = id(ws)
    ws_clients[client_id] = ws
    
    logger.info(f"New WebSocket connection established. Client ID: {client_id}")
    
    try:
        # Connect to matching engine WebSocket
        me_ws = websocket.WebSocket()
        me_ws_url = f"{Config.MATCHING_ENGINE_URL.replace('http', 'ws')}/ws"
        logger.debug(f"Connecting to matching engine WebSocket at {me_ws_url}")
        
        try:
            me_ws.connect(
                me_ws_url,
                ping_interval=Config.WS_PING_INTERVAL,
                ping_timeout=Config.WS_PING_TIMEOUT,
                max_size=Config.WS_MAX_MESSAGE_SIZE
            )
            logger.info("Successfully connected to matching engine WebSocket")
            
        except Exception as e:
            logger.error(f"Failed to connect to matching engine WebSocket: {str(e)}")
            ws.send(json.dumps({
                "type": "error",
                "message": "Failed to connect to matching engine"
            }))
            return
        
        while True:
            try:
                # Forward messages from client to matching engine
                message = ws.receive()
                if message:
                    logger.debug(f"Received message from client: {message}")
                    try:
                        # Parse message to validate JSON
                        msg_data = json.loads(message)
                        logger.debug(f"Forwarding message to matching engine: {msg_data}")
                        me_ws.send(message)
                    except json.JSONDecodeError:
                        logger.warning(f"Received invalid JSON from client: {message}")
                        ws.send(json.dumps({
                            "type": "error",
                            "message": "Invalid JSON message"
                        }))
                        continue
                
                # Forward messages from matching engine to client
                try:
                    message = me_ws.recv()
                    if message:
                        logger.debug(f"Received message from matching engine: {message}")
                        try:
                            # Parse message to validate JSON
                            msg_data = json.loads(message)
                            logger.debug(f"Forwarding message to client: {msg_data}")
                            ws.send(message)
                        except json.JSONDecodeError:
                            logger.warning(f"Received invalid JSON from matching engine: {message}")
                            continue
                except websocket.WebSocketConnectionClosedException:
                    logger.warning("WebSocket connection to matching engine closed")
                    break
                    
            except websocket.WebSocketConnectionClosedException:
                logger.warning("Client WebSocket connection closed")
                break
            except Exception as e:
                logger.error(f"Error in WebSocket communication: {str(e)}")
                try:
                    ws.send(json.dumps({
                        "type": "error",
                        "message": "Internal communication error"
                    }))
                except:
                    pass
                break
                
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        try:
            me_ws.close()
        except:
            pass
        
        if client_id in ws_clients:
            del ws_clients[client_id]
        logger.info(f"WebSocket connection closed. Client ID: {client_id}")

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
    
    try:
        # Make the direct request with trailing slash to avoid redirect
        response = requests.request(
            method=request.method,  # Preserve original method
            url=target_url,
            headers=headers,
            json=request.get_json() if request.is_json else None,
            params=request.args,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        logger.debug(f"Received response status: {response.status_code}")
        logger.debug(f"Response content: {response.text}")
        
        # Return the response with original content type
        return Response(
            response.content,
            status=response.status_code,
            mimetype=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Error proxying request to trading service: {str(e)}")
        return jsonify({
            'success': False,
            'data': {
                'error': 'Failed to proxy request to trading service',
                'details': str(e)
            }
        }), 500

# Matching Engine Routes
@gateway_bp.route('/matching/<path:path>', methods=['GET', 'POST'])
@check_circuit_breaker('matching-engine')
def matching_proxy(path):
    """Proxy requests to matching engine"""
    target_url = f"{Config.MATCHING_ENGINE_URL}/api/{path}"
    return proxy_request(target_url, include_headers=['Authorization'])

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

# WebSocket route with CORS
@sock.route('/ws')
def ws_route(ws):
    """WebSocket route with CORS validation"""
    # Check origin
    origin = request.headers.get('Origin')
    if origin not in Config.CORS_ORIGINS:
        logger.warning(f"Rejected WebSocket connection from unauthorized origin: {origin}")
        ws.send(json.dumps({
            "type": "error",
            "message": "Unauthorized origin"
        }))
        ws.close()
        return
        
    handle_websocket(ws) 