"""
ImagePayloadInjection (IPI) - Educational tools for image security analysis

This package provides tools for analyzing, detecting, and demonstrating
image-based security vulnerabilities and payload injection techniques.
"""

__version__ = "1.0.0"
__author__ = "Modern Dime Security"
__license__ = "MIT"
__copyright__ = "Copyright 2025 Modern Dime"

import logging
import sys
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('ipi')

# Check required dependencies
DEPENDENCIES = {
    'required': ['PIL'],
    'optional': ['numpy', 'magic', 'cv2', 'rawpy', 'sklearn']
}

def check_dependencies() -> Dict[str, bool]:
    """
    Check if required and optional dependencies are available
    
    Returns:
        Dict[str, bool]: Dictionary with dependency status
    """
    status = {}
    
    # Check required dependencies
    for dep in DEPENDENCIES['required']:
        try:
            __import__(dep)
            status[dep] = True
        except ImportError:
            status[dep] = False
            logger.error(f"Required dependency '{dep}' is missing")
    
    # Check optional dependencies
    for dep in DEPENDENCIES['optional']:
        try:
            __import__(dep)
            status[dep] = True
        except ImportError:
            status[dep] = False
            logger.debug(f"Optional dependency '{dep}' is not available")
    
    return status

# Make core modules available at package level
try:
    from .analyzer import ImageSecurityAnalyzer
    from .detector import PayloadDetector
    from .injector import PayloadInjector
    from .utils import FileUtils
except ImportError as e:
    logger.error(f"Error importing core modules: {e}")

# Run dependency check on import
dependency_status = check_dependencies()

# Ensure critical dependencies are available
if not all(dependency_status.get(dep, False) for dep in DEPENDENCIES['required']):
    logger.warning("Some required dependencies are missing. Install them with: pip install pillow")