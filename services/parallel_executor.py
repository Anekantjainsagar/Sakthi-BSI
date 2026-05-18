#!/usr/bin/env python3
"""
Parallel Execution Service
Handles parallel API calls, DNS queries, and other I/O operations
"""

import asyncio
import aiohttp
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional, Coroutine
from functools import wraps
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("parallel-executor")


class ParallelExecutor:
    """
    Handles parallel execution of tasks with proper error handling and timeouts
    """
    
    def __init__(self, max_workers: int = 5, timeout: int = 30):
        """
        Initialize parallel executor
        
        Args:
            max_workers: Maximum number of concurrent workers
            timeout: Timeout for each task in seconds
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.results = {}
        self.errors = {}
    
    def execute_parallel(self, tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute multiple tasks in parallel
        
        Args:
            tasks: List of task dicts with 'name', 'func', and 'args'
        
        Returns:
            Dictionary with results and errors
        """
        futures = {}
        results = {}
        errors = {}
        
        logger.info(f"Starting parallel execution of {len(tasks)} tasks")
        start_time = time.time()
        
        # Submit all tasks
        for task in tasks:
            name = task.get('name', 'unknown')
            func = task.get('func')
            args = task.get('args', ())
            kwargs = task.get('kwargs', {})
            
            if not func:
                logger.warning(f"Task {name} has no function")
                continue
            
            try:
                future = self.executor.submit(func, *args, **kwargs)
                futures[name] = future
            except Exception as e:
                logger.error(f"Error submitting task {name}: {e}")
                errors[name] = str(e)
        
        # Collect results as they complete
        for name, future in futures.items():
            try:
                result = future.result(timeout=self.timeout)
                results[name] = result
                logger.info(f"✓ Task {name} completed successfully")
            except TimeoutError:
                error_msg = f"Task {name} timed out after {self.timeout}s"
                logger.error(error_msg)
                errors[name] = error_msg
            except Exception as e:
                error_msg = f"Task {name} failed: {str(e)}"
                logger.error(error_msg)
                errors[name] = error_msg
        
        elapsed = time.time() - start_time
        logger.info(f"Parallel execution completed in {elapsed:.2f}s")
        logger.info(f"Results: {len(results)} successful, {len(errors)} failed")
        
        return {
            'results': results,
            'errors': errors,
            'elapsed_time': elapsed,
            'success_count': len(results),
            'error_count': len(errors)
        }
    
    def execute_with_retry(self, task: Dict[str, Any], max_retries: int = 3) -> Any:
        """
        Execute a task with automatic retry on failure
        
        Args:
            task: Task dict with 'name', 'func', 'args', 'kwargs'
            max_retries: Maximum number of retries
        
        Returns:
            Task result or None if all retries failed
        """
        name = task.get('name', 'unknown')
        func = task.get('func')
        args = task.get('args', ())
        kwargs = task.get('kwargs', {})
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Executing {name} (attempt {attempt + 1}/{max_retries})")
                result = func(*args, **kwargs)
                logger.info(f"✓ {name} succeeded on attempt {attempt + 1}")
                return result
            except Exception as e:
                logger.warning(f"✗ {name} failed on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
        
        logger.error(f"✗ {name} failed after {max_retries} attempts")
        return None
    
    def shutdown(self):
        """Shutdown the executor"""
        self.executor.shutdown(wait=True)
        logger.info("Executor shutdown complete")


class AsyncParallelExecutor:
    """
    Handles parallel async execution of tasks (for I/O-bound operations)
    """
    
    def __init__(self, max_concurrent: int = 10, timeout: int = 30):
        """
        Initialize async parallel executor
        
        Args:
            max_concurrent: Maximum concurrent async tasks
            timeout: Timeout for each task in seconds
        """
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def execute_parallel_async(self, tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute multiple async tasks in parallel
        
        Args:
            tasks: List of task dicts with 'name' and 'coro' (coroutine)
        
        Returns:
            Dictionary with results and errors
        """
        logger.info(f"Starting async parallel execution of {len(tasks)} tasks")
        start_time = time.time()
        
        async def run_with_semaphore(name: str, coro: Coroutine):
            async with self.semaphore:
                try:
                    result = await asyncio.wait_for(coro, timeout=self.timeout)
                    logger.info(f"✓ Async task {name} completed")
                    return name, result, None
                except asyncio.TimeoutError:
                    error = f"Async task {name} timed out after {self.timeout}s"
                    logger.error(error)
                    return name, None, error
                except Exception as e:
                    error = f"Async task {name} failed: {str(e)}"
                    logger.error(error)
                    return name, None, error
        
        # Create all coroutines
        coroutines = [
            run_with_semaphore(task.get('name', 'unknown'), task.get('coro'))
            for task in tasks
        ]
        
        # Run all concurrently
        results_list = await asyncio.gather(*coroutines, return_exceptions=False)
        
        # Organize results
        results = {}
        errors = {}
        for name, result, error in results_list:
            if error:
                errors[name] = error
            else:
                results[name] = result
        
        elapsed = time.time() - start_time
        logger.info(f"Async execution completed in {elapsed:.2f}s")
        logger.info(f"Results: {len(results)} successful, {len(errors)} failed")
        
        return {
            'results': results,
            'errors': errors,
            'elapsed_time': elapsed,
            'success_count': len(results),
            'error_count': len(errors)
        }


class APICallOptimizer:
    """
    Optimizes API calls by batching, caching, and parallelizing
    """
    
    def __init__(self, cache_manager=None):
        """
        Initialize API optimizer
        
        Args:
            cache_manager: Optional cache manager for caching responses
        """
        self.cache_manager = cache_manager
        self.parallel_executor = ParallelExecutor(max_workers=5, timeout=30)
    
    def parallelize_api_calls(self, api_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute multiple API calls in parallel
        
        Args:
            api_calls: List of API call dicts with 'name', 'func', 'args', 'kwargs'
        
        Returns:
            Dictionary with results and errors
        """
        logger.info(f"Parallelizing {len(api_calls)} API calls")
        
        # Check cache first
        uncached_calls = []
        cached_results = {}
        
        for call in api_calls:
            cache_key = call.get('cache_key')
            if cache_key and self.cache_manager:
                cached = self.cache_manager.get(cache_key)
                if cached:
                    logger.info(f"✓ Cache hit for {call.get('name')}")
                    cached_results[call.get('name')] = cached
                    continue
            uncached_calls.append(call)
        
        # Execute uncached calls in parallel
        if uncached_calls:
            parallel_results = self.parallel_executor.execute_parallel(uncached_calls)
            
            # Cache successful results
            for call in uncached_calls:
                name = call.get('name')
                if name in parallel_results['results']:
                    cache_key = call.get('cache_key')
                    if cache_key and self.cache_manager:
                        ttl = call.get('cache_ttl', 3600)
                        self.cache_manager.set(
                            cache_key,
                            parallel_results['results'][name],
                            ttl=ttl
                        )
            
            # Combine cached and parallel results
            all_results = {**cached_results, **parallel_results['results']}
            all_errors = parallel_results['errors']
        else:
            all_results = cached_results
            all_errors = {}
        
        return {
            'results': all_results,
            'errors': all_errors,
            'cached_count': len(cached_results),
            'executed_count': len(uncached_calls)
        }
    
    def batch_api_calls(self, api_calls: List[Dict[str, Any]], batch_size: int = 5) -> List[Dict[str, Any]]:
        """
        Batch API calls to avoid rate limiting
        
        Args:
            api_calls: List of API calls
            batch_size: Number of calls per batch
        
        Returns:
            List of batches
        """
        batches = []
        for i in range(0, len(api_calls), batch_size):
            batch = api_calls[i:i + batch_size]
            batches.append(batch)
        
        logger.info(f"Created {len(batches)} batches of {batch_size} calls")
        return batches
    
    def execute_batched_calls(self, api_calls: List[Dict[str, Any]], batch_size: int = 5, delay_between_batches: float = 1.0) -> Dict[str, Any]:
        """
        Execute API calls in batches with delay between batches
        
        Args:
            api_calls: List of API calls
            batch_size: Number of calls per batch
            delay_between_batches: Delay in seconds between batches
        
        Returns:
            Combined results from all batches
        """
        batches = self.batch_api_calls(api_calls, batch_size)
        all_results = {}
        all_errors = {}
        
        for i, batch in enumerate(batches):
            logger.info(f"Executing batch {i + 1}/{len(batches)}")
            batch_result = self.parallel_executor.execute_parallel(batch)
            
            all_results.update(batch_result['results'])
            all_errors.update(batch_result['errors'])
            
            if i < len(batches) - 1:
                logger.info(f"Waiting {delay_between_batches}s before next batch...")
                time.sleep(delay_between_batches)
        
        return {
            'results': all_results,
            'errors': all_errors,
            'total_batches': len(batches),
            'total_calls': len(api_calls)
        }
    
    def shutdown(self):
        """Shutdown the optimizer"""
        self.parallel_executor.shutdown()


def parallel_task(max_workers: int = 5, timeout: int = 30):
    """
    Decorator to run a function in parallel with other parallel tasks
    
    Usage:
        @parallel_task(max_workers=5, timeout=30)
        def my_api_call():
            return requests.get(url).json()
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            executor = ThreadPoolExecutor(max_workers=max_workers)
            future = executor.submit(func, *args, **kwargs)
            try:
                result = future.result(timeout=timeout)
                return result
            except Exception as e:
                logger.error(f"Parallel task failed: {e}")
                raise
            finally:
                executor.shutdown(wait=False)
        return wrapper
    return decorator


def retry_on_failure(max_retries: int = 3, backoff_factor: float = 2.0):
    """
    Decorator to retry a function on failure with exponential backoff
    
    Usage:
        @retry_on_failure(max_retries=3, backoff_factor=2.0)
        def my_api_call():
            return requests.get(url).json()
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed")
                        raise
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    # Example 1: Parallel execution
    def sample_task(name, duration):
        time.sleep(duration)
        return f"{name} completed in {duration}s"
    
    executor = ParallelExecutor(max_workers=3, timeout=10)
    
    tasks = [
        {'name': 'Task 1', 'func': sample_task, 'args': ('Task 1', 2)},
        {'name': 'Task 2', 'func': sample_task, 'args': ('Task 2', 3)},
        {'name': 'Task 3', 'func': sample_task, 'args': ('Task 3', 1)},
    ]
    
    result = executor.execute_parallel(tasks)
    print(f"Results: {result}")
    executor.shutdown()
