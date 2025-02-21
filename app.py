from flask import Flask, request
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from flask_sock import Sock
import logging
import sys
from logging.handlers import RotatingFileHandler
import os
import json
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer

from src.routes.gateway_routes import gateway_bp, handle_websocket
from src.config import Config

def create_app():
    """Initialize and configure the Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Initialize WebSocket support first
    sock = Sock(app)
    
    # Configure CORS with WebSocket support
    CORS(app, 
         origins=Config.CORS_ORIGINS,
         supports_credentials=True,
         allow_headers=['*'],
         expose_headers=['*'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         resources={
             r"/*": {"origins": Config.CORS_ORIGINS},
             r"/ws": {  # Changed from /ws/* to /ws
                 "origins": Config.CORS_ORIGINS,
                 "allow_headers": ["*"],
                 "methods": ["GET", "OPTIONS", "UPGRADE", "CONNECTION"]  # Added UPGRADE and CONNECTION
             }
         })
    
    # Configure WebSocket specific settings
    app.config['SOCK_SERVER_OPTIONS'] = {
        'ping_interval': 25,  # Send ping every 25 seconds
        'ping_timeout': 10,   # Wait 10 seconds for pong
        'subprotocols': ['trading-protocol']
    }
    
    # Configure logging with more detailed WebSocket logs
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('logs/api_gateway.log')
        ]
    )
    
    # Set Flask logger to use the same configuration
    app.logger.handlers = []
    app.logger.addHandler(logging.StreamHandler(sys.stdout))
    app.logger.setLevel(logging.DEBUG)
    
    # Add WebSocket specific logger
    ws_logger = logging.getLogger('websocket')
    ws_logger.setLevel(logging.DEBUG)
    ws_logger.addHandler(logging.StreamHandler(sys.stdout))
    
    # Register WebSocket route before other routes
    @sock.route('/ws')
    def ws_handler(ws):
        """Handle WebSocket connections"""
        try:
            # Get and validate origin
            origin = request.headers.get('Origin', '')
            app.logger.info(f"WebSocket connection received from origin: {origin}")
            
            if origin not in Config.CORS_ORIGINS:
                app.logger.warning(f"Rejected WebSocket connection from unauthorized origin: {origin}")
                return
            
            handle_websocket(ws)
            
        except Exception as e:
            app.logger.error(f"WebSocket error: {str(e)}", exc_info=True)
    
    # Register blueprints for HTTP routes
    app.register_blueprint(gateway_bp, url_prefix=Config.API_PREFIX)
    
    # Add Prometheus metrics endpoint
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
        '/metrics': make_wsgi_app()
    })
    
    @app.route('/health')
    def health_check():
        app.logger.info("Health check endpoint called")
        return {'status': 'healthy'}, 200
    
    return app

if __name__ == '__main__':
    app = create_app()
    http_server = WSGIServer(('0.0.0.0', 4000), app, handler_class=WebSocketHandler)
    http_server.serve_forever() 