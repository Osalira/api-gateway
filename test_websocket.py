import websocket
import json
import time
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def on_message(ws, message):
    """Handle incoming messages"""
    logger.info(f"Received message: {message}")
    try:
        data = json.loads(message)
        logger.info(f"Parsed message: {json.dumps(data, indent=2)}")
    except json.JSONDecodeError:
        logger.warning(f"Received non-JSON message: {message}")

def on_error(ws, error):
    """Handle errors"""
    logger.error(f"WebSocket error: {error}")

def on_close(ws, close_status_code, close_msg):
    """Handle connection close"""
    logger.info(f"WebSocket connection closed: {close_status_code} - {close_msg}")

def on_open(ws):
    """Handle connection open"""
    logger.info("WebSocket connection established")
    
    # Send a test heartbeat message
    heartbeat = json.dumps({"type": "heartbeat"})
    logger.info(f"Sending heartbeat: {heartbeat}")
    ws.send(heartbeat)
    
    # Send a test trade notification
    trade = json.dumps({
        "type": "trade_notification",
        "data": {
            "order_id": "test_order_123",
            "symbol": "AAPL",
            "quantity": 100,
            "price": 150.50,
            "status": "FILLED"
        }
    })
    logger.info(f"Sending trade notification: {trade}")
    ws.send(trade)

def main():
    """Main test function"""
    websocket.enableTrace(True)
    # Connect through API Gateway (using Docker host port)
    ws_url = "ws://localhost:4000/ws"
    
    logger.info(f"Connecting to API Gateway at {ws_url}")
    
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    
    ws.run_forever(
        ping_interval=30,
        ping_timeout=10
    )

if __name__ == "__main__":
    main() 