import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')  # Has to be changed in production
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Service URLs
    AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:5000')
    TRADING_SERVICE_URL = os.getenv('TRADING_SERVICE_URL', 'http://localhost:8000')
    MATCHING_ENGINE_URL = os.getenv('MATCHING_ENGINE_URL', 'http://localhost:8080')
    LOGGING_SERVICE_URL = os.getenv('LOGGING_SERVICE_URL', 'http://localhost:5002')
    
    # API Configuration
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    
    # Request timeouts (in seconds)
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))  # requests per window
    RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # window in seconds
    
    # Circuit Breaker
    CIRCUIT_BREAKER_ENABLED = os.getenv('CIRCUIT_BREAKER_ENABLED', 'True').lower() == 'true'
    CIRCUIT_BREAKER_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', '5'))  # failures before opening
    CIRCUIT_BREAKER_TIMEOUT = int(os.getenv('CIRCUIT_BREAKER_TIMEOUT', '60'))  # seconds to wait before half-open
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Service Registry (for future service discovery)
    SERVICE_REGISTRY = {
        'auth': {
            'url': AUTH_SERVICE_URL,
            'routes': ['/login', '/register'],
            'timeout': REQUEST_TIMEOUT,
            'retry_count': 3
        },
        'trading': {
            'url': TRADING_SERVICE_URL,
            'routes': ['/orders', '/portfolio', '/wallets'],
            'timeout': REQUEST_TIMEOUT,
            'retry_count': 3
        },
        'matching-engine': {
            'url': MATCHING_ENGINE_URL,
            'routes': ['/orders'],
            'timeout': REQUEST_TIMEOUT,
            'retry_count': 3
        },
        'logging': {
            'url': LOGGING_SERVICE_URL,
            'routes': ['/logs'],
            'timeout': REQUEST_TIMEOUT,
            'retry_count': 3
        }
    } 