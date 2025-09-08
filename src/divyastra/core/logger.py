"""
DIVYASTRA Logging System
Advanced logging configuration for next-generation web penetration testing
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

def setup_logger(name: str, level: str = 'INFO', log_file: Optional[str] = None) -> logging.Logger:
    """Setup logger with DIVYASTRA formatting and handlers"""
    
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Set level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # File gets everything
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        # Add color to levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        
        # Format the message
        formatted = super().format(record)
        
        # Reset levelname for future use
        record.levelname = levelname
        
        return formatted


def get_audit_logger() -> logging.Logger:
    """Get audit logger for security events"""
    audit_logger = logging.getLogger('divyastra.audit')
    
    if not audit_logger.handlers:
        # Ensure audit log directory exists
        audit_dir = Path.home() / '.divyastra' / 'audit'
        audit_dir.mkdir(parents=True, exist_ok=True)
        
        # Create audit log file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d')
        audit_file = audit_dir / f'divyastra_audit_{timestamp}.log'
        
        # File handler for audit logs
        file_handler = logging.FileHandler(audit_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Detailed formatter for audit logs
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s - PID:%(process)d',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(audit_formatter)
        
        audit_logger.addHandler(file_handler)
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False  # Don't propagate to root logger
    
    return audit_logger
