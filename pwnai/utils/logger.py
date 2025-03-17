"""
Logging utilities for PwnAI.
"""

import logging
import sys
from typing import Optional

import colorlog


def setup_logger(level: int = logging.INFO, name: Optional[str] = None) -> logging.Logger:
    """
    Set up and configure a logger with colored output.
    
    Args:
        level: The logging level (default: INFO)
        name: The logger name (default: pwnai)
        
    Returns:
        A configured logger instance
    """
    name = name or "pwnai"
    logger = logging.getLogger(name)
    
    if logger.handlers:
        # Logger already configured
        return logger
    
    logger.setLevel(level)
    
    # Create console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    
    # Create formatter
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
    
    console.setFormatter(formatter)
    logger.addHandler(console)
    
    return logger 