import pika
import json
import logging
import os
from datetime import datetime
import threading
import time
import functools

logger = logging.getLogger(__name__)

class RabbitMQClient:
    """RabbitMQ client for publishing and consuming events"""
    
    def __init__(self):
        """Initialize RabbitMQ client"""
        self.host = os.getenv('RABBITMQ_HOST', 'rabbitmq')
        self.port = int(os.getenv('RABBITMQ_PORT', 5672))
        self.username = os.getenv('RABBITMQ_USER', 'user')
        self.password = os.getenv('RABBITMQ_PASSWORD', 'password')
        self.connection = None
        self.channel = None
        self.consumer_threads = []
        
        # Define exchanges
        self.exchanges = {
            'user_events': 'topic',
            'order_events': 'topic',
            'system_events': 'topic'
        }

    def connect(self):
        """Establish connection to RabbitMQ"""
        if self.connection is None or self.connection.is_closed:
            credentials = pika.PlainCredentials(self.username, self.password)
            parameters = pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                virtual_host='/',
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            
            # Try to connect with retry logic
            max_retries = 5
            retry_interval = 2
            for attempt in range(max_retries):
                try:
                    self.connection = pika.BlockingConnection(parameters)
                    self.channel = self.connection.channel()
                    
                    # Declare exchanges
                    for exchange, exchange_type in self.exchanges.items():
                        self.channel.exchange_declare(
                            exchange=exchange,
                            exchange_type=exchange_type,
                            durable=True
                        )
                    
                    logger.info("Successfully connected to RabbitMQ")
                    return True
                except Exception as e:
                    logger.warning(f"Failed to connect to RabbitMQ (attempt {attempt+1}/{max_retries}): {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_interval)
            
            logger.error("Failed to connect to RabbitMQ after multiple attempts")
            return False
        return True

    def publish_event(self, exchange, routing_key, message, retry=True):
        """Publish an event to RabbitMQ"""
        try:
            if not self.connect():
                logger.error("Cannot publish event because RabbitMQ connection failed")
                return False
                
            # Add timestamp if not present
            if 'timestamp' not in message:
                message['timestamp'] = datetime.now().isoformat()
                
            # Add trace_id if not present
            if 'trace_id' not in message:
                import uuid
                message['trace_id'] = uuid.uuid4().hex[:8]
            
            # Publish message
            self.channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json'
                )
            )
            
            logger.info(f"Published event to {exchange} with routing key {routing_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to publish event: {str(e)}")
            
            # Retry once if connection was lost
            if retry and (self.connection is None or self.connection.is_closed):
                logger.info("Attempting to reconnect and retry publishing event")
                self.connection = None
                return self.publish_event(exchange, routing_key, message, retry=False)
                
            return False

    def start_consumer(self, queue_name, routing_keys, exchange, callback):
        """Start a consumer for the given queue and routing keys"""
        def consumer_thread():
            while True:
                try:
                    if not self.connect():
                        logger.error("Cannot start consumer because RabbitMQ connection failed")
                        time.sleep(5)
                        continue
                    
                    # Declare queue
                    result = self.channel.queue_declare(
                        queue=queue_name, 
                        durable=True
                    )
                    
                    # Bind queue to exchange with routing keys
                    for key in routing_keys:
                        self.channel.queue_bind(
                            exchange=exchange,
                            queue=queue_name,
                            routing_key=key
                        )
                    
                    # Define callback wrapper to handle acknowledgments
                    def callback_wrapper(ch, method, properties, body):
                        try:
                            callback(json.loads(body))
                            ch.basic_ack(delivery_tag=method.delivery_tag)
                        except Exception as e:
                            logger.error(f"Error processing message: {str(e)}")
                            # Negative acknowledgment with requeue
                            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    
                    # Set up consumer
                    self.channel.basic_qos(prefetch_count=1)
                    self.channel.basic_consume(
                        queue=queue_name,
                        on_message_callback=callback_wrapper
                    )
                    
                    logger.info(f"Started consuming from {queue_name} bound to {exchange}")
                    self.channel.start_consuming()
                    
                except (pika.exceptions.ConnectionClosedByBroker, 
                        pika.exceptions.AMQPChannelError,
                        pika.exceptions.AMQPConnectionError) as e:
                    logger.warning(f"RabbitMQ connection error: {str(e)}")
                    time.sleep(5)
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error in consumer: {str(e)}")
                    time.sleep(5)
                    continue
        
        # Start consumer in a separate thread
        consumer = threading.Thread(target=consumer_thread)
        consumer.daemon = True
        consumer.start()
        self.consumer_threads.append(consumer)
        
        return consumer

    def close(self):
        """Close the RabbitMQ connection"""
        if self.connection and self.connection.is_open:
            self.connection.close()
            logger.info("RabbitMQ connection closed")

# Create a global RabbitMQ client instance
rabbitmq_client = RabbitMQClient()

# Helper function to publish an event
def publish_event(exchange, routing_key, message):
    """Publish an event to RabbitMQ"""
    return rabbitmq_client.publish_event(exchange, routing_key, message)

# Helper function to start a consumer
def start_consumer(queue_name, routing_keys, exchange, callback):
    """Start a consumer for the given queue and routing keys"""
    return rabbitmq_client.start_consumer(queue_name, routing_keys, exchange, callback)

# Decorator to automatically publish events
def publish_event_on_success(exchange, routing_key, event_creator):
    """
    Decorator to automatically publish an event when the decorated function completes successfully.
    
    Args:
        exchange (str): The exchange to publish to
        routing_key (str): The routing key to use
        event_creator (callable): A function that takes the decorated function's result and creates an event message
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # If function was successful, publish event
            try:
                # Check if result is a tuple with status code
                if isinstance(result, tuple) and len(result) >= 2:
                    response, status_code = result[0], result[1]
                    
                    # Only publish if successful (2xx status code)
                    if 200 <= status_code < 300:
                        event_data = event_creator(response, *args, **kwargs)
                        publish_event(exchange, routing_key, event_data)
                else:
                    # If not a tuple with status code, assume success and publish
                    event_data = event_creator(result, *args, **kwargs)
                    publish_event(exchange, routing_key, event_data)
            except Exception as e:
                logger.error(f"Failed to publish event after function execution: {str(e)}")
                
            return result
        return wrapper
    return decorator 