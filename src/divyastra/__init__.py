"""
DIVYASTRA - Next-Generation AI-Powered Web Penetration Testing Suite
🗡️ Advanced CLI-based web application security testing framework

GitHub Repository: https://github.com/DSCYBERS/divyastra
Author: DSCYBERS Team
License: Enterprise/Academic/Government License
"""

__version__ = "2.0.0-nextgen"
__author__ = "DSCYBERS Team"
__email__ = "security@dscybers.org"
__license__ = "Enterprise License"
__description__ = "Next-Generation AI-Powered Web Penetration Testing Suite"
__url__ = "https://github.com/DSCYBERS/divyastra"
__download_url__ = "https://github.com/DSCYBERS/divyastra/releases"

# Core imports
from .modules.reconnaissance import Reconnaissance
from .core.config import Config
from .core.logger import setup_logger

# Version information
VERSION_INFO = {
    'version': __version__,
    'build_date': '2024-01-15',
    'python_version': '3.9+',
    'features': [
        'Next-Gen Web Framework Testing',
        'AI-Powered Zero-Day Discovery', 
        'Advanced API Security Testing',
        'Business Logic Vulnerability Detection',
        'SPA Deep Analysis',
        'GraphQL Security Assessment'
    ],
    'repository': __url__,
    'documentation': 'https://docs.dscybers.org/divyastra',
    'community': 'https://discord.gg/dscybers-security'
}

def get_banner() -> str:
    """Get DIVYASTRA ASCII banner"""
    return f"""
🗡️  DIVYASTRA v{__version__} - Next-Generation Web Penetration Testing Suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ██████╗ ██╗██╗   ██╗██╗   ██╗ █████╗ ███████╗████████╗██████╗  █████╗ 
    ██╔══██╗██║██║   ██║╚██╗ ██╔╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
    ██║  ██║██║██║   ██║ ╚████╔╝ ███████║███████╗   ██║   ██████╔╝███████║
    ██║  ██║██║╚██╗ ██╔╝  ╚██╔╝  ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
    ██████╔╝██║ ╚████╔╝    ██║   ██║  ██║███████║   ██║   ██║  ██║██║  ██║
    ╚═════╝ ╚═╝  ╚═══╝     ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 AI-Powered | 🚀 Next-Gen Frameworks | 🔒 Zero-Day Discovery
📊 Business Logic | 🌐 API Security | ⚡ Real-time Analysis

Repository: {__url__}
Documentation: https://docs.dscybers.org/divyastra
Community: https://discord.gg/dscybers-security

🗡️ "धर्म की रक्षा, प्रौद्योगिकी से" (Protecting righteousness through technology)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

def get_version_info() -> dict:
    """Get detailed version information"""
    return VERSION_INFO

# Initialize logging
logger = setup_logger(__name__)

# Export main classes and functions
__all__ = [
    'Reconnaissance',
    'Config', 
    'get_banner',
    'get_version_info',
    'VERSION_INFO',
    '__version__'
]

# Startup message
logger.info(f"DIVYASTRA v{__version__} initialized")
logger.info(f"Repository: {__url__}")