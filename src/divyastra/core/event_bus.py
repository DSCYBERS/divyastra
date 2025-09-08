"""
DIVYASTRA Event Bus System
Event-driven architecture for next-generation web penetration testing
"""

import asyncio
from typing import Dict, List, Callable, Any, Optional
from collections import defaultdict
import logging
from datetime import datetime

log = logging.getLogger(__name__)

class EventBus:
    """Asynchronous event bus for DIVYASTRA components"""
    
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._middleware: List[Callable] = []
        self._event_history: List[Dict] = []
        self._max_history = 1000
    
    def on(self, event_name: str):
        """Decorator to register event handler"""
        def decorator(handler: Callable):
            self._handlers[event_name].append(handler)
            log.debug(f"Registered handler for event: {event_name}")
            return handler
        return decorator
    
    def subscribe(self, event_name: str, handler: Callable):
        """Subscribe handler to event"""
        self._handlers[event_name].append(handler)
        log.debug(f"Subscribed handler for event: {event_name}")
    
    def unsubscribe(self, event_name: str, handler: Callable):
        """Unsubscribe handler from event"""
        if handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)
            log.debug(f"Unsubscribed handler for event: {event_name}")
    
    async def emit(self, event_name: str, data: Any = None, **kwargs):
        """Emit event to all registered handlers"""
        event = {
            'name': event_name,
            'data': data,
            'kwargs': kwargs,
            'timestamp': datetime.now().isoformat(),
            'handlers_called': 0
        }
        
        # Add to history
        self._add_to_history(event)
        
        # Apply middleware
        for middleware in self._middleware:
            try:
                await middleware(event)
            except Exception as e:
                log.warning(f"Middleware error for event {event_name}: {e}")
        
        # Call handlers
        handlers = self._handlers.get(event_name, [])
        if handlers:
            tasks = []
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        tasks.append(handler(data, **kwargs))
                    else:
                        # Run sync handler in executor
                        tasks.append(asyncio.get_event_loop().run_in_executor(
                            None, handler, data, **kwargs
                        ))
                    event['handlers_called'] += 1
                except Exception as e:
                    log.error(f"Handler error for event {event_name}: {e}")
            
            # Wait for all handlers to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        
        log.debug(f"Emitted event: {event_name} to {event['handlers_called']} handlers")
    
    def add_middleware(self, middleware: Callable):
        """Add middleware function"""
        self._middleware.append(middleware)
        log.debug("Added middleware to event bus")
    
    def _add_to_history(self, event: Dict):
        """Add event to history with size limit"""
        self._event_history.append(event)
        
        # Trim history if too large
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]
    
    def get_event_history(self, event_name: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get event history, optionally filtered by event name"""
        history = self._event_history
        
        if event_name:
            history = [e for e in history if e['name'] == event_name]
        
        return history[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics"""
        return {
            'total_events': len(self._event_history),
            'registered_events': list(self._handlers.keys()),
            'handler_counts': {event: len(handlers) for event, handlers in self._handlers.items()},
            'middleware_count': len(self._middleware)
        }
