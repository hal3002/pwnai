"""
Logging configuration for PwnAI.
"""

import logging
import os
import sys
from typing import Optional

try:
    import colorlog
    HAS_COLORLOG = True
except ImportError:
    HAS_COLORLOG = False

# Keep track of configured loggers to prevent duplicates
CONFIGURED_LOGGERS = set()

def setup_logger(
    name: str = "pwnai",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    force: bool = False
) -> logging.Logger:
    """
    Set up and configure a logger.
    
    Args:
        name: Logger name
        level: Logging level
        log_file: Optional path to log file
        force: Force reconfiguration even if logger was previously configured
        
    Returns:
        Configured logger
    """
    # Check if this logger has already been configured
    if name in CONFIGURED_LOGGERS and not force:
        return logging.getLogger(name)
        
    # Add to set of configured loggers
    CONFIGURED_LOGGERS.add(name)
    
    # Get or create logger
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
    
    # Set level
    logger.setLevel(level)
    
    # Create console handler with color support if available
    console_handler = logging.StreamHandler(sys.stdout)
    
    if HAS_COLORLOG:
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
    else:
        formatter = logging.Formatter(
            fmt="[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if log_file is provided
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        # Use a simpler formatter for file logging
        file_formatter = logging.Formatter(
            fmt="[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger 