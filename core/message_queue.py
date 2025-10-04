"""
Message queue system for inter-agent communication using Redis.
"""

import json
import asyncio
from typing import Dict, Any, Optional, List
import redis.asyncio as redis
from agents.base.exceptions import MessageQueueException
from core.logging import get_agent_logger

class MessageQueue:
    """
    Redis-based message queue for asynchronous communication between agents.
    
    Handles message publishing, consumption, and queue management for the
    multi-agent system.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """
        Initialize the message queue connection.
        
        Args:
            redis_url: Redis connection URL
        """
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.logger = get_agent_logger("message_queue")
        
        # Queue names for different message types
        self.queue_names = {
            "cti_reports": "queue:cti_reports",
            "extracted_ttps": "queue:extracted_ttps", 
            "generated_rules": "queue:generated_rules",
            "detection_events": "queue:detection_events",
            "feedback": "queue:feedback"
        }
    
    async def connect(self) -> None:
        """Establish connection to Redis"""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # Test connection
            await self.redis_client.ping()
            self.logger.info("Connected to Redis message queue")
            
        except Exception as e:
            raise MessageQueueException(
                f"Failed to connect to Redis: {str(e)}"
            )
    
    async def disconnect(self) -> None:
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            self.logger.info("Disconnected from Redis message queue")
    
    async def publish(
        self, 
        queue_name: str, 
        message: Dict[str, Any],
        priority: int = 0
    ) -> bool:
        """
        Publish a message to a queue.
        
        Args:
            queue_name: Name of the queue
            message: Message data to publish
            priority: Message priority (higher = more priority)
            
        Returns:
            True if message was published successfully
        """
        try:
            if not self.redis_client:
                await self.connect()
            
            # Add metadata to message
            message_with_metadata = {
                "data": message,
                "timestamp": asyncio.get_event_loop().time(),
                "priority": priority,
                "queue": queue_name
            }
            
            serialized_message = json.dumps(message_with_metadata, default=str)
            
            # Use Redis list for queue (LPUSH for publish, BRPOP for consume)
            queue_key = self.queue_names.get(queue_name, f"queue:{queue_name}")
            await self.redis_client.lpush(queue_key, serialized_message)
            
            self.logger.info(f"Published message to {queue_name}", 
                           queue=queue_name, message_size=len(serialized_message))
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish message to {queue_name}: {str(e)}")
            raise MessageQueueException(f"Publish failed: {str(e)}")
    
    async def consume(
        self, 
        queue_name: str, 
        timeout: int = 0
    ) -> Optional[Dict[str, Any]]:
        """
        Consume a message from a queue.
        
        Args:
            queue_name: Name of the queue to consume from
            timeout: Timeout in seconds (0 = block indefinitely)
            
        Returns:
            Message data or None if timeout
        """
        try:
            if not self.redis_client:
                await self.connect()
            
            queue_key = self.queue_names.get(queue_name, f"queue:{queue_name}")
            
            # BRPOP blocks until message available or timeout
            result = await self.redis_client.brpop(queue_key, timeout=timeout)
            
            if result:
                _, serialized_message = result
                message_with_metadata = json.loads(serialized_message)
                
                self.logger.info(f"Consumed message from {queue_name}",
                               queue=queue_name)
                
                # Return just the data part, not metadata
                return message_with_metadata.get("data")
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to consume from {queue_name}: {str(e)}")
            raise MessageQueueException(f"Consume failed: {str(e)}")
    
    async def get_queue_length(self, queue_name: str) -> int:
        """
        Get the current length of a queue.
        
        Args:
            queue_name: Name of the queue
            
        Returns:
            Number of messages in queue
        """
        try:
            if not self.redis_client:
                await self.connect()
            
            queue_key = self.queue_names.get(queue_name, f"queue:{queue_name}")
            length = await self.redis_client.llen(queue_key)
            return length
            
        except Exception as e:
            self.logger.error(f"Failed to get queue length for {queue_name}: {str(e)}")
            return 0
    
    async def clear_queue(self, queue_name: str) -> int:
        """
        Clear all messages from a queue.
        
        Args:
            queue_name: Name of the queue to clear
            
        Returns:
            Number of messages removed
        """
        try:
            if not self.redis_client:
                await self.connect()
            
            queue_key = self.queue_names.get(queue_name, f"queue:{queue_name}")
            removed_count = await self.redis_client.delete(queue_key)
            
            self.logger.info(f"Cleared queue {queue_name}, removed {removed_count} messages")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Failed to clear queue {queue_name}: {str(e)}")
            return 0
    
    async def list_queues(self) -> List[str]:
        """
        List all available message queues.
        
        Returns:
            List of queue names
        """
        try:
            if not self.redis_client:
                await self.connect()
            
            # Get all keys matching our queue pattern
            queue_keys = await self.redis_client.keys("queue:*")
            queue_names = [key.replace("queue:", "") for key in queue_keys]
            
            return queue_names
            
        except Exception as e:
            self.logger.error(f"Failed to list queues: {str(e)}")
            return []

# Global message queue instance
_message_queue_instance: Optional[MessageQueue] = None

def get_message_queue(redis_url: str = "redis://localhost:6379") -> MessageQueue:
    """
    Get the global message queue instance.
    
    Args:
        redis_url: Redis connection URL
        
    Returns:
        MessageQueue instance
    """
    global _message_queue_instance
    
    if _message_queue_instance is None:
        _message_queue_instance = MessageQueue(redis_url)
    
    return _message_queue_instance
