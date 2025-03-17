#!/usr/bin/env python3
"""
Test utilities for PwnAI.
"""

import os
import signal
import subprocess
import time
from contextlib import contextmanager
from typing import Optional, Union

class TimeoutError(Exception):
    """Custom timeout error."""
    pass

@contextmanager
def timeout(seconds: int):
    """
    Context manager for timeout.
    
    Args:
        seconds: Number of seconds before timeout
        
    Raises:
        TimeoutError: If the operation takes longer than the specified time
    """
    def timeout_handler(signum, frame):
        raise TimeoutError("Operation timed out")
    
    # Set the signal handler
    original_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Restore the original handler
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)

def run_process_with_timeout(
    cmd: Union[str, list],
    timeout_seconds: int = 30,
    **kwargs
) -> "tuple[int, str, str]":
    """
    Run a process with timeout.
    
    Args:
        cmd: Command to run (string or list)
        timeout_seconds: Number of seconds before timeout
        **kwargs: Additional arguments to pass to subprocess.Popen
        
    Returns:
        Tuple of (returncode, stdout, stderr)
        
    Raises:
        TimeoutError: If the process takes longer than the specified time
    """
    with timeout(timeout_seconds):
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr

def cleanup_process(process: subprocess.Popen) -> None:
    """
    Clean up a process.
    
    Args:
        process: The process to clean up
    """
    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    except ProcessLookupError:
        pass  # Process already terminated

class ProcessManager:
    """Manager for subprocesses with timeout and cleanup."""
    
    def __init__(self, timeout_seconds: int = 30):
        """
        Initialize the process manager.
        
        Args:
            timeout_seconds: Default timeout in seconds
        """
        self.timeout_seconds = timeout_seconds
        self.processes = []
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
    
    def run(
        self,
        cmd: Union[str, list],
        timeout_seconds: Optional[int] = None,
        **kwargs
    ) -> "tuple[int, str, str]":
        """
        Run a process with timeout.
        
        Args:
            cmd: Command to run (string or list)
            timeout_seconds: Optional override for default timeout
            **kwargs: Additional arguments to pass to subprocess.Popen
            
        Returns:
            Tuple of (returncode, stdout, stderr)
            
        Raises:
            TimeoutError: If the process takes longer than the specified time
        """
        timeout = timeout_seconds or self.timeout_seconds
        returncode, stdout, stderr = run_process_with_timeout(
            cmd,
            timeout_seconds=timeout,
            **kwargs
        )
        return returncode, stdout, stderr
    
    def start_process(
        self,
        cmd: Union[str, list],
        **kwargs
    ) -> subprocess.Popen:
        """
        Start a process and track it.
        
        Args:
            cmd: Command to run (string or list)
            **kwargs: Additional arguments to pass to subprocess.Popen
            
        Returns:
            The started process
        """
        process = subprocess.Popen(
            cmd,
            **kwargs
        )
        self.processes.append(process)
        return process
    
    def cleanup(self) -> None:
        """Clean up all tracked processes."""
        for process in self.processes:
            cleanup_process(process)
        self.processes.clear()

class PwntoolsProcess:
    """Wrapper for pwntools-style process interaction."""
    
    def __init__(
        self,
        cmd: Union[str, list],
        timeout_seconds: int = 30,
        **kwargs
    ):
        """
        Initialize the pwntools process.
        
        Args:
            cmd: Command to run (string or list)
            timeout_seconds: Number of seconds before timeout
            **kwargs: Additional arguments to pass to subprocess.Popen
        """
        self.timeout_seconds = timeout_seconds
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            **kwargs
        )
    
    def sendline(self, data: str) -> None:
        """
        Send a line to the process.
        
        Args:
            data: Data to send
        """
        self.process.stdin.write(data + "\n")
        self.process.stdin.flush()
    
    def recvuntil(self, delim: str, timeout: Optional[int] = None) -> str:
        """
        Receive data until delimiter is found.
        
        Args:
            delim: Delimiter to look for
            timeout: Optional timeout in seconds
            
        Returns:
            Received data
            
        Raises:
            TimeoutError: If timeout is reached
        """
        timeout = timeout or self.timeout_seconds
        start_time = time.time()
        buffer = ""
        
        while time.time() - start_time < timeout:
            char = self.process.stdout.read(1)
            if not char:
                break
            buffer += char
            if delim in buffer:
                return buffer
        
        raise TimeoutError("Timeout waiting for delimiter")
    
    def recvline(self, timeout: Optional[int] = None) -> str:
        """
        Receive a line from the process.
        
        Args:
            timeout: Optional timeout in seconds
            
        Returns:
            Received line
            
        Raises:
            TimeoutError: If timeout is reached
        """
        return self.recvuntil("\n", timeout)
    
    def interactive(self) -> None:
        """
        Start interactive mode.
        
        This is a simple implementation that just forwards stdin/stdout.
        """
        try:
            while True:
                if self.process.poll() is not None:
                    break
                char = os.read(0, 1)
                if not char:
                    break
                self.process.stdin.write(char)
                self.process.stdin.flush()
                output = self.process.stdout.read(1)
                if output:
                    os.write(1, output.encode())
        except KeyboardInterrupt:
            pass
        finally:
            self.close()
    
    def close(self) -> None:
        """Close the process."""
        cleanup_process(self.process) 