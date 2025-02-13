# API Gateway

This service acts as the entry point for the Day Trading System, routing external client requests to the appropriate backend microservices.

## Features

- Request routing to backend services
- Circuit breaker pattern for fault tolerance
- Request/response metrics with Prometheus
- CORS support
- Health checks
- Request timeout handling
- Error handling and logging
- Rate limiting (configurable)

## Prerequisites

- Python 3.8+
- Virtual Environment (recommended)

## Setup

1. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (create a .env file):
```env
# Flask settings
FLASK_SECRET_KEY=your-secret-key-here
FLASK_DEBUG=True

# Service URLs
AUTH_SERVICE_URL=http://localhost:5000
TRADING_SERVICE_URL=http://localhost:8000
MATCHING_ENGINE_URL=http://localhost:8080
LOGGING_SERVICE_URL=http://localhost:5002

# Gateway settings
PORT=5000
REQUEST_TIMEOUT=30
CORS_ORIGINS=http://localhost:3000

# Rate limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Circuit breaker
CIRCUIT_BREAKER_ENABLED=True
CIRCUIT_BREAKER_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=60

# Logging
LOG_LEVEL=INFO
```

## Running the Service

Start the service:
```bash
python app.py
```

The service will run on `http://localhost:5000`

## API Routes

### Authentication Service
- `POST /api/v1/auth/login` → Forwards to Auth Service
- `POST /api/v1/auth/register` → Forwards to Auth Service

### Trading Service
- `POST /api/v1/trading/orders` → Forwards to Trading Service
- `GET /api/v1/trading/portfolio` → Forwards to Trading Service
- `GET /api/v1/trading/wallets` → Forwards to Trading Service

### Matching Engine
- `POST /api/v1/matching/orders` → Forwards to Matching Engine

### Logging Service
- `POST /api/v1/logs` → Forwards to Logging Service
- `GET /api/v1/logs` → Forwards to Logging Service

### Monitoring
- `GET /health` - Gateway health check
- `GET /metrics` - Prometheus metrics

## Circuit Breaker States

1. **Closed**: Normal operation, requests are forwarded
2. **Open**: Service is failing, requests are rejected
3. **Half-Open**: Testing if service has recovered

## Metrics

The following metrics are available at `/metrics`:
- Total requests by service/endpoint
- Request latency by service/endpoint
- Circuit breaker state
- Error rates

## Development

- Run with debug mode:
```bash
FLASK_DEBUG=True python app.py
```

- Format code:
```bash
black .
```

## Security Notes

- All sensitive configuration is managed through environment variables
- CORS is configured to allow only specified origins
- Rate limiting prevents abuse
- Circuit breakers prevent cascade failures
- All requests maintain original authentication headers 