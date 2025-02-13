from flask import Flask
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
import logging
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
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    handler = RotatingFileHandler(
        'logs/api_gateway.log',
        maxBytes=10000000,  # 10MB
        backupCount=10
    )
    handler.setFormatter(logging.Formatter(Config.LOG_FORMAT))
    app.logger.addHandler(handler)
    app.logger.setLevel(getattr(logging, Config.LOG_LEVEL))
    
    # Register blueprints
    app.register_blueprint(gateway_bp, url_prefix=Config.API_PREFIX)
    
    # Add Prometheus metrics endpoint
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
        '/metrics': make_wsgi_app()
    })
    
    @app.route('/health')
    def health_check():
        return {'status': 'healthy'}, 200
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Start server
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 