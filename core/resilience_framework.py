#!/usr/bin/env python3
"""
BSI Resilience Framework
Handles retries, timeouts, and graceful degradation
"""

import time
import logging
from typing import Callable, Any, Optional, Dict, List
from functools import wraps
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategy types"""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_DELAY = "fixed_delay"


class RetryConfig:
    """Configuration for retry behavior"""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
        backoff_multiplier: float = 2.0,
        retryable_exceptions: Optional[List[type]] = None
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.strategy = strategy
        self.backoff_multiplier = backoff_multiplier
        self.retryable_exceptions = retryable_exceptions or [
            TimeoutError,
            ConnectionError,
            OSError,
            Exception  # Catch-all for network errors
        ]

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        if self.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.initial_delay * (self.backoff_multiplier ** attempt)
        elif self.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.initial_delay * (attempt + 1)
        else:  # FIXED_DELAY
            delay = self.initial_delay
        
        return min(delay, self.max_delay)


class TimeoutConfig:
    """Configuration for timeout behavior"""
    
    def __init__(
        self,
        timeout_seconds: float,
        allow_partial: bool = True,
        degradation_strategy: Optional[str] = None
    ):
        self.timeout_seconds = timeout_seconds
        self.allow_partial = allow_partial
        self.degradation_strategy = degradation_strategy  # e.g., "reduce_scope", "skip_deep_scan"


def retry_with_backoff(
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, Exception], None]] = None
):
    """
    Decorator for retrying functions with exponential backoff
    
    Args:
        config: RetryConfig instance
        on_retry: Callback function called on each retry
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Check if exception is retryable
                    is_retryable = any(isinstance(e, exc_type) for exc_type in config.retryable_exceptions)
                    
                    if not is_retryable or attempt == config.max_retries:
                        raise
                    
                    last_exception = e
                    delay = config.get_delay(attempt)
                    
                    logger.warning(
                        f"Attempt {attempt + 1}/{config.max_retries + 1} failed for {func.__name__}: {str(e)}. "
                        f"Retrying in {delay}s..."
                    )
                    
                    if on_retry:
                        on_retry(attempt + 1, e)
                    
                    time.sleep(delay)
            
            raise last_exception
        
        return wrapper
    
    return decorator


def timeout_handler(
    timeout_seconds: float,
    allow_partial: bool = True,
    on_timeout: Optional[Callable[[], None]] = None
):
    """
    Decorator for handling function timeouts
    
    Args:
        timeout_seconds: Timeout in seconds
        allow_partial: Whether to allow partial results
        on_timeout: Callback function called on timeout
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            import signal
            
            def timeout_handler_signal(signum, frame):
                raise TimeoutError(f"Function {func.__name__} exceeded timeout of {timeout_seconds}s")
            
            # Set signal handler (Unix only)
            try:
                old_handler = signal.signal(signal.SIGALRM, timeout_handler_signal)
                signal.alarm(int(timeout_seconds))
            except (ValueError, AttributeError):
                # Windows or signal not available
                logger.warning("Timeout handler not available on this platform")
                return func(*args, **kwargs)
            
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            except TimeoutError as e:
                if on_timeout:
                    on_timeout()
                raise
            finally:
                signal.alarm(0)  # Cancel alarm
                try:
                    signal.signal(signal.SIGALRM, old_handler)
                except (ValueError, AttributeError):
                    pass
        
        return wrapper
    
    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern for preventing cascading failures
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        name: str = "circuit_breaker"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.name = name
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function through circuit breaker"""
        
        # Check if we should attempt recovery
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                logger.info(f"Circuit breaker {self.name} entering half-open state")
            else:
                raise Exception(f"Circuit breaker {self.name} is open")
        
        try:
            result = func(*args, **kwargs)
            
            # Success - reset
            if self.state == "half_open":
                self.state = "closed"
                self.failure_count = 0
                logger.info(f"Circuit breaker {self.name} closed")
            
            return result
        
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(
                    f"Circuit breaker {self.name} opened after {self.failure_count} failures"
                )
            
            raise


class AdaptiveScanner:
    """
    Adaptive scanning that degrades gracefully under load
    """
    
    def __init__(self):
        self.scan_depth = 3  # 1=shallow, 2=normal, 3=deep
        self.request_timeout = 30.0
        self.max_concurrent_requests = 10
        self.performance_history: List[float] = []

    def record_performance(self, duration: float):
        """Record step duration"""
        self.performance_history.append(duration)
        
        # Keep last 10 measurements
        if len(self.performance_history) > 10:
            self.performance_history.pop(0)
        
        # Check if we should degrade
        avg_duration = sum(self.performance_history) / len(self.performance_history)
        
        if avg_duration > 30.0 and self.scan_depth > 1:
            self.scan_depth -= 1
            logger.warning(f"Degrading scan depth to {self.scan_depth} due to slow performance")
        
        elif avg_duration < 5.0 and self.scan_depth < 3:
            self.scan_depth += 1
            logger.info(f"Upgrading scan depth to {self.scan_depth} due to good performance")

    def get_scan_config(self) -> Dict[str, Any]:
        """Get current scan configuration"""
        return {
            "scan_depth": self.scan_depth,
            "request_timeout": self.request_timeout,
            "max_concurrent_requests": self.max_concurrent_requests
        }


class PartialResultHandler:
    """
    Handles partial results from timed-out or failed operations
    """
    
    @staticmethod
    def merge_partial_results(
        primary: Dict[str, Any],
        partial: Dict[str, Any],
        merge_strategy: str = "union"
    ) -> Dict[str, Any]:
        """
        Merge partial results with primary results
        
        Args:
            primary: Primary result set
            partial: Partial result set
            merge_strategy: "union" (combine all), "primary" (keep primary), "partial" (prefer partial)
        
        Returns:
            Merged result
        """
        if merge_strategy == "union":
            result = {**primary}
            for key, value in partial.items():
                if key not in result:
                    result[key] = value
                elif isinstance(value, list) and isinstance(result[key], list):
                    result[key].extend(value)
                elif isinstance(value, dict) and isinstance(result[key], dict):
                    result[key].update(value)
            return result
        
        elif merge_strategy == "primary":
            return primary
        
        elif merge_strategy == "partial":
            return partial
        
        else:
            return primary

    @staticmethod
    def mark_partial_data(data: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Mark data as partial"""
        return {
            **data,
            "_partial": True,
            "_partial_reason": reason,
            "_partial_timestamp": time.time()
        }


class FailureRecovery:
    """
    Handles failure recovery and fallback strategies
    """
    
    def __init__(self):
        self.fallback_strategies: Dict[str, List[Callable]] = {}

    def register_fallback(self, operation: str, fallback_func: Callable):
        """Register a fallback strategy for an operation"""
        if operation not in self.fallback_strategies:
            self.fallback_strategies[operation] = []
        self.fallback_strategies[operation].append(fallback_func)

    def execute_with_fallback(self, operation: str, primary_func: Callable, *args, **kwargs) -> Any:
        """Execute with fallback strategies"""
        try:
            return primary_func(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Primary operation {operation} failed: {str(e)}")
            
            fallbacks = self.fallback_strategies.get(operation, [])
            
            for i, fallback_func in enumerate(fallbacks):
                try:
                    logger.info(f"Attempting fallback {i + 1}/{len(fallbacks)} for {operation}")
                    result = fallback_func(*args, **kwargs)
                    logger.info(f"Fallback {i + 1} succeeded for {operation}")
                    return result
                except Exception as fallback_error:
                    logger.warning(f"Fallback {i + 1} failed: {str(fallback_error)}")
                    continue
            
            # All fallbacks failed
            logger.error(f"All fallback strategies failed for {operation}")
            raise


# Global instances
_circuit_breaker = CircuitBreaker()
_adaptive_scanner = AdaptiveScanner()
_failure_recovery = FailureRecovery()


def get_circuit_breaker() -> CircuitBreaker:
    """Get global circuit breaker"""
    return _circuit_breaker


def get_adaptive_scanner() -> AdaptiveScanner:
    """Get global adaptive scanner"""
    return _adaptive_scanner


def get_failure_recovery() -> FailureRecovery:
    """Get global failure recovery"""
    return _failure_recovery
