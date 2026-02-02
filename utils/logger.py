import logging
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler
from pathlib import Path

def get_logger(name: str = "vipsqli", log_file: str = None):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    
    # Console (warnings only by default to keep UI clean)
    console = RichHandler(show_time=False, show_path=False)
    console.setLevel(logging.WARNING)
    logger.addHandler(console)
    
    # File (all levels)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger
