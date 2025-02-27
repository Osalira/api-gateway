import os
import time
import logging
import json
import sys
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_sock import Sock
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from prometheus_client import make_wsgi_app
import requests
from src.config import Config
from src.routes.gateway_routes import gateway_bp, handle_websocket
from src.routes.jmeter_routes import jmeter_bp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def create_app():
    """Initialize and configure the Flask application"""
    app = Flask(__name__)
    
    # Load configuration from the Config class
    app.config.from_object(Config)
    
    # Set up CORS with WebSocket support
    CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)
    
    # Set up WebSockets
    sock = Sock(app)
    
    # Register the WebSocket route
    @sock.route('/ws')
    def ws_handler(ws):
        handle_websocket(ws)
    
    # Register the gateway blueprint for HTTP routes (API routes)
    app.register_blueprint(gateway_bp, url_prefix=Config.API_PREFIX)
    
    # Register the JMeter routes blueprint for direct access without API prefix
    app.register_blueprint(jmeter_bp)
    
    # Add Prometheus metrics endpoint
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
        '/metrics': make_wsgi_app()
    })
    
    @app.route('/health')
    def health_check():
        app.logger.info("Health check endpoint called")
        return {'status': 'healthy'}, 200
    
    @app.route('/debug/routes')
    def debug_routes():
        """Debug endpoint to list all registered routes"""
        app.logger.info("Debug routes endpoint called")
        
        # Get all registered routes
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'rule': str(rule)
            })
        
        # Log all routes for debugging
        app.logger.info(f"Registered routes: {routes}")
        return {'routes': routes}, 200
    
    return app

# Create app instance for gunicorn
app = create_app()

if __name__ == '__main__':
    # This server is WebSocket-capable for local development
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True) 