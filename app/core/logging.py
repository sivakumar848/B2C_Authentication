import logging
import sys
from pythonjsonlogger import jsonlogger

def setup_logging():
    # Create logger
    logger = logging.getLogger("b2c_auth_api")
    logger.setLevel(logging.WARNING)
    
    # Clear any existing handlers to prevent duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Prevent duplicate logs from parent loggers
    logger.propagate = False
    
    # JSON formatter for structured logging
    json_formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(name)s %(levelname)s %(funcName)s %(lineno)d %(message)s"
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(json_formatter)
    console_handler.setLevel(logging.WARNING)
    
    # File handler (optional - for production)
    # file_handler = logging.FileHandler("app.log")
    # file_handler.setFormatter(json_formatter)
    # file_handler.setLevel(logging.INFO)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    # logger.addHandler(file_handler)
    
    return logger

# Create a single logger instance
logger = setup_logging()