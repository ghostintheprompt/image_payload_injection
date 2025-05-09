#!/usr/bin/env python3
"""
Utility functions for the ImagePayloadInjection package

This module provides helper functions for file operations, type checking,
and various utility features used throughout the package.
"""

import os
import sys
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Union, Optional, Dict, List, Tuple, BinaryIO, Iterator, Any

# Configure logging
logger = logging.getLogger('ipi.utils')

class FileUtils:
    """
    Utility class for file operations with memory-efficient methods
    """
    
    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256', 
                      chunk_size: int = 8192) -> str:
        """
        Calculate file hash using specified algorithm with memory-efficient streaming
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')
            chunk_size: Size of chunks to read from file
            
        Returns:
            str: Hexadecimal digest of file hash
        """
        if algorithm.lower() not in ('md5', 'sha1', 'sha256', 'sha512'):
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
        try:
            hash_obj = getattr(hashlib, algorithm.lower())()
            
            with open(file_path, 'rb') as f:
                for chunk in FileUtils.read_in_chunks(f, chunk_size):
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            raise
    
    @staticmethod
    def read_in_chunks(file_obj: BinaryIO, chunk_size: int = 8192) -> Iterator[bytes]:
        """
        Generator to read a file in chunks
        
        Args:
            file_obj: File object opened in binary mode
            chunk_size: Size of each chunk in bytes
            
        Yields:
            bytes: File chunk
        """
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    @staticmethod
    def get_mime_type(file_path: Union[str, Path]) -> str:
        """
        Get MIME type of a file using multiple methods for reliability
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: MIME type or 'unknown' if unable to determine
        """
        # Try python-magic if available
        try:
            import magic
            try:
                mime = magic.Magic(mime=True).from_file(str(file_path))
                if mime:
                    return mime
            except Exception as e:
                logger.warning(f"Error with python-magic: {str(e)}")
        except ImportError:
            pass
        
        # Try mimetypes standard library
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type:
            return mime_type
        
        # Check file extension as fallback
        ext = os.path.splitext(str(file_path))[1].lower()
        extension_map = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.svg': 'image/svg+xml',
            '.webp': 'image/webp',
            '.tiff': 'image/tiff',
            '.tif': 'image/tiff',
        }
        
        return extension_map.get(ext, 'unknown')
    
    @staticmethod
    def create_temp_file(content: bytes = None, suffix: str = None) -> Tuple[str, str]:
        """
        Create a temporary file with optional content
        
        Args:
            content: Content to write to the file
            suffix: File extension
            
        Returns:
            Tuple[str, str]: Temp file path and name
        """
        try:
            fd, path = tempfile.mkstemp(suffix=suffix)
            
            if content:
                with os.fdopen(fd, 'wb') as f:
                    f.write(content)
            else:
                os.close(fd)
                
            return path, os.path.basename(path)
        except Exception as e:
            logger.error(f"Error creating temporary file: {str(e)}")
            raise
    
    @staticmethod
    def is_valid_image(file_path: Union[str, Path]) -> bool:
        """
        Check if file is a valid image
        
        Args:
            file_path: Path to the file
            
        Returns:
            bool: True if file is a valid image
        """
        try:
            from PIL import Image
            try:
                with Image.open(file_path) as img:
                    img.verify()  # Verify image integrity
                return True
            except Exception:
                return False
        except ImportError:
            logger.warning("PIL not available for image validation")
            
            # Fallback to checking extension
            valid_extensions = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', 
                '.webp', '.tiff', '.tif', '.svg'
            }
            ext = os.path.splitext(str(file_path))[1].lower()
            return ext in valid_extensions
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of binary data
        
        Args:
            data: Binary data
            
        Returns:
            float: Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
            
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        total = len(data)
        
        for freq in frequencies.values():
            probability = freq / total
            entropy -= probability * (math.log(probability, 2))
            
        return entropy
    
    @staticmethod
    def memory_efficient_copy(input_path: Union[str, Path], 
                             output_path: Union[str, Path], 
                             chunk_size: int = 8192) -> None:
        """
        Copy a file with memory-efficient streaming
        
        Args:
            input_path: Source file path
            output_path: Destination file path
            chunk_size: Size of chunks to read/write
            
        Returns:
            None
        """
        try:
            with open(input_path, 'rb') as in_file:
                with open(output_path, 'wb') as out_file:
                    for chunk in FileUtils.read_in_chunks(in_file, chunk_size):
                        out_file.write(chunk)
        except Exception as e:
            logger.error(f"Error copying file: {str(e)}")
            raise

# Import missing modules that might be referenced
import math