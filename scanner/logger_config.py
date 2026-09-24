"""
Logging configuration for the keylogger detection system.
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Default log directory (relative to CWD). Created lazily inside
# setup_logger() rather than here at import time -- this module is only
# ever imported once per process (Python caches modules), so a one-time
# mkdir() here would bind "logs/" to whatever the CWD happened to be at
# first import, even if a caller changes directory afterward and a new
# logger is set up later (e.g. tests using monkeypatch.chdir()).
LOG_DIR = Path("logs")

# Log file path
LOG_FILE = LOG_DIR / "keylogger_detection.log"

# Default log level
DEFAULT_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


def setup_logger(name: str, log_level: str = None) -> logging.Logger:
    """
    Set up and configure a logger with both file and console handlers.
    
    Args:
        name: Logger name (typically __name__)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
                   If None, uses DEFAULT_LOG_LEVEL
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Don't add handlers if they already exist
    if logger.handlers:
        return logger
    
    # Set log level
    level = getattr(logging, log_level or DEFAULT_LOG_LEVEL, logging.INFO)
    logger.setLevel(level)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # File handler with rotation (10MB max, keep 5 backups)
    LOG_DIR.mkdir(exist_ok=True)
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # Log everything to file
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)  # Use configured level for console
    console_handler.setFormatter(console_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

