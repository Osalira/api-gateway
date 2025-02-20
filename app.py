from flask import Flask
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from flask_sock import Sock
import logging
import sys
from logging.handlers import RotatingFileHandler
import os
import json

from src.routes.gateway_routes import gateway_bp, handle_websocket
from src.config import Config

def create_app():
    """Initialize and configure the Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Configure CORS with WebSocket support
    CORS(app, 
         origins=Config.CORS_ORIGINS,
         supports_credentials=True,
         allow_headers=['*'],
         expose_headers=['*'],
         allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         resources={
             r"/*": {"origins": Config.CORS_ORIGINS},
             r"/ws": {"origins": Config.CORS_ORIGINS}
         },
         allow_private_network=True)
    
    # Initialize WebSocket support with custom settings
    sock = Sock(app)
    app.sock = sock  # Store for use in routes
    
    # Configure WebSocket specific settings
    app.config['SOCK_SERVER_OPTIONS'] = {
        'max_message_size': Config.WS_MAX_MESSAGE_SIZE
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
    
    # Register WebSocket route at root level
    @sock.route('/ws')
    def ws_handler(ws):
        app.logger.info("WebSocket connection received at root level")
        return handle_websocket(ws)
    
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
    
    # Start server with WebSocket support
    port = int(os.getenv('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=True) 