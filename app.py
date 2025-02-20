from flask import Flask
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
import logging
import sys
from logging.handlers import RotatingFileHandler
import os

from src.routes.gateway_routes import gateway_bp
from src.config import Config

def create_app():
    """Initialize and configure the Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Configure CORS
    CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)
    
    # Configure logging
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
    
    # Register blueprints
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
    
    # Start server
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 