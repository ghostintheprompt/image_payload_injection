#!/usr/bin/env python3
"""
Enhanced Image Payload Analyzer

This module provides comprehensive analysis capabilities for detecting potentially
malicious content in images, including:
- Trailing data after EOF markers
- Suspicious metadata
- Steganography detection
- Format-based exploits
- Custom/suspicious chunks
- JavaScript in SVG files
- RAW camera file analysis
- Color histogram anomalies
- Machine learning-based detection
"""

import os
import re
import sys
import json
import logging
import argparse
import tempfile
import subprocess
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Any, Union, BinaryIO, TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np

# Try to import optional dependencies
try:
    import numpy as np
    from PIL import Image, ExifTags
    from PIL.PngImagePlugin import PngInfo
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import rawpy
    RAW_AVAILABLE = True
except ImportError:
    RAW_AVAILABLE = False

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

try:
    import sklearn
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('image-analyzer')

# Define constants
TEMP_DIR = tempfile.gettempdir()
MAX_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks for stream processing

# Recognized RAW file extensions
RAW_EXTENSIONS = {
    '.arw': 'Sony',
    '.cr2': 'Canon',
    '.cr3': 'Canon',
    '.crw': 'Canon', 
    '.dng': 'Adobe/Generic',
    '.nef': 'Nikon',
    '.nrw': 'Nikon',
    '.orf': 'Olympus',
    '.pef': 'Pentax',
    '.raf': 'Fujifilm',
    '.raw': 'Generic',
    '.rw2': 'Panasonic',
    '.srw': 'Samsung'
}

class ImageSecurityAnalyzer:
    """
    Comprehensive image security analysis tool
    """
    def __init__(self, image_path: str, verbose: bool = False):
        """
        Initialize the analyzer with the path to an image file
        
        Args:
            image_path (str): Path to the image file to analyze
            verbose (bool): Enable verbose output
        """
        self.image_path = os.path.abspath(image_path)
        self.verbose = verbose
        self.file_extension = os.path.splitext(image_path)[1].lower()
        self.file_size = os.path.getsize(image_path)
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        
        # Initialize results structure
        self.results = {
            'file_info': {},
            'threats': {},
            'risk_level': 'Unknown'
        }

    def analyze(self) -> Dict:
        """
        Perform a comprehensive security analysis of the image
        
        Returns:
            Dict: Analysis results
        """
        if not os.path.exists(self.image_path):
            self.results['risk_level'] = 'Error'
            logger.error(f"File does not exist: {self.image_path}")
            return self.results
        
        try:
            # Get basic file information
            self._get_file_info()
            
            # Analyze file in streaming mode when possible
            with open(self.image_path, 'rb') as f:
                # Detect format-based exploits (needs full file scan)
                self._detect_format_exploits(f)
                
                # Reset file pointer for other scans
                f.seek(0)
                
                # Detect trailing data
                self._detect_trailing_data(f)
            
            # Run detection methods that require specific libraries
            detection_futures = []
            
            # Start metadata detection in parallel
            detection_futures.append(self.thread_pool.submit(self._detect_suspicious_metadata))
            
            # Format-specific checks (can run in parallel)
            if self.file_extension == '.png':
                detection_futures.append(self.thread_pool.submit(self._detect_suspicious_chunks))
            elif self.file_extension == '.svg':
                detection_futures.append(self.thread_pool.submit(self._detect_svg_javascript))
            elif self.file_extension in RAW_EXTENSIONS:
                detection_futures.append(self.thread_pool.submit(self._analyze_raw_file))
            
            # Advanced analysis techniques (can be run in parallel)
            detection_futures.append(self.thread_pool.submit(self._detect_steganography))
            detection_futures.append(self.thread_pool.submit(self._analyze_color_histograms))
            detection_futures.append(self.thread_pool.submit(self._perform_ml_analysis))
            
            # Wait for all detection methods to complete
            for future in concurrent.futures.as_completed(detection_futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in detection method: {str(e)}")
            
            # Determine overall risk level
            self._determine_risk_level()
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            self.results['risk_level'] = 'Error'
        
        return self.results

    def _get_file_info(self) -> None:
        """
        Gather basic information about the file
        """
        file_info = {
            'filename': os.path.basename(self.image_path),
            'size': self.file_size,
            'last_modified': datetime.fromtimestamp(
                os.path.getmtime(self.image_path)
            ).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Get MIME type if python-magic is available
        if MAGIC_AVAILABLE:
            try:
                file_info['mime'] = magic.Magic(mime=True).from_file(self.image_path)
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Failed to get MIME type: {str(e)}")
        
        # Get image dimensions if Pillow is available
        if PILLOW_AVAILABLE:
            try:
                with Image.open(self.image_path) as img:
                    file_info['dimensions'] = f"{img.width}x{img.height}"
                    file_info['format'] = img.format
                    file_info['mode'] = img.mode
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Failed to get image dimensions: {str(e)}")
        
        self.results['file_info'] = file_info

    def _detect_trailing_data(self, file_handle: BinaryIO) -> None:
        """
        Detect data appended after the image's end marker
        """
        has_trailing = False
        trailing_data = None
        
        try:
            # Read first few bytes to determine file type
            file_handle.seek(0)
            header = file_handle.read(8)
            file_handle.seek(0)
            
            # Check for PNG
            if header.startswith(b'\x89PNG'):
                # Stream through file looking for IEND chunk
                chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                file_pos = 0
                
                while chunk_data:
                    iend_pos = chunk_data.rfind(b'IEND')
                    if iend_pos != -1:
                        # Found IEND, check if there's data after it
                        end_pos = file_pos + iend_pos + 8  # IEND chunk + CRC (4 + 4 bytes)
                        file_handle.seek(end_pos)
                        trailing_bytes = file_handle.read()
                        if trailing_bytes:
                            has_trailing = True
                            trailing_data = trailing_bytes
                        break
                    
                    # Continue reading
                    file_pos += len(chunk_data) - 3  # Overlap by 3 bytes to catch split markers
                    file_handle.seek(file_pos)
                    chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                    if not chunk_data:
                        break
            
            # Check for JPEG
            elif header.startswith(b'\xff\xd8'):
                # Stream through file looking for EOI marker
                file_handle.seek(0)
                chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                file_pos = 0
                
                while chunk_data:
                    eoi_pos = chunk_data.rfind(b'\xff\xd9')
                    if eoi_pos != -1:
                        # Found EOI, check if there's data after it
                        end_pos = file_pos + eoi_pos + 2
                        file_handle.seek(end_pos)
                        trailing_bytes = file_handle.read()
                        if trailing_bytes:
                            has_trailing = True
                            trailing_data = trailing_bytes
                        break
                    
                    # Continue reading
                    file_pos += len(chunk_data) - 1  # Overlap by 1 byte to catch split markers
                    file_handle.seek(file_pos)
                    chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                    if not chunk_data:
                        break
            
            # Check for GIF
            elif header.startswith(b'GIF'):
                # GIF trailer is 0x3B (;)
                file_handle.seek(0)
                chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                file_pos = 0
                
                while chunk_data:
                    trailer_pos = chunk_data.rfind(b'\x3b')
                    if trailer_pos != -1:
                        # Found trailer, check if there's data after it
                        end_pos = file_pos + trailer_pos + 1
                        file_handle.seek(end_pos)
                        trailing_bytes = file_handle.read()
                        if trailing_bytes:
                            has_trailing = True
                            trailing_data = trailing_bytes
                        break
                    
                    # Continue reading
                    file_pos += len(chunk_data) - 1  # Overlap by 1 byte
                    file_handle.seek(file_pos)
                    chunk_data = file_handle.read(MAX_CHUNK_SIZE)
                    if not chunk_data:
                        break
        
            details = None
            if has_trailing:
                # Analyze trailing data
                details = f"Found {len(trailing_data)} bytes after EOF marker"
                
                # Check for executable signatures in trailing data
                exe_signatures = [
                    (b'MZ', 'DOS/Windows executable'),
                    (b'\x7fELF', 'Linux executable'),
                    (b'\xca\xfe\xba\xbe', 'Mach-O binary'),
                    (b'\x50\x4b\x03\x04', 'ZIP/JAR/APK'),
                    (b'<%', 'Script (possibly PHP)'),
                    (b'<script', 'JavaScript')
                ]
                
                for sig, desc in exe_signatures:
                    if trailing_data.startswith(sig) or sig in trailing_data[:min(100, len(trailing_data))]:
                        details += f". Possible {desc} detected"
                        break
            
            self.results['threats']['trailing_data'] = (has_trailing, details)
        
        except Exception as e:
            logger.error(f"Error in trailing data detection: {str(e)}")
            self.results['threats']['trailing_data'] = (False, f"Error: {str(e)}")

    def _detect_suspicious_metadata(self) -> None:
        """
        Check image metadata for suspicious content
        """
        suspicious = False
        details = None
        
        try:
            if PILLOW_AVAILABLE:
                try:
                    with Image.open(self.image_path) as img:
                        # Extract metadata
                        metadata = {}
                        
                        # Get EXIF data for JPEG
                        if hasattr(img, '_getexif') and img._getexif():
                            exif = img._getexif()
                            if exif:  # Check if exif is not None
                                for tag, value in exif.items():
                                    if tag in ExifTags.TAGS:
                                        metadata[ExifTags.TAGS[tag]] = value
                        
                        # Get PNG text chunks
                        if hasattr(img, 'text') and img.text:
                            for k, v in img.text.items():
                                metadata[f"PNG:{k}"] = v
                        
                        # Check for suspicious patterns
                        suspicious_patterns = [
                            (r'(?i)script', 'Script reference'),
                            (r'(?i)exec', 'Execution reference'),
                            (r'(?i)eval', 'Evaluation function'),
                            (r'(?i)<.*>', 'HTML/XML tags'),
                            (r'(?i)data:', 'Data URI'),
                            (r'(?i)0x[0-9a-f]{6,}', 'Long hex sequence'),
                            (r'(?i)http', 'URL reference'),
                            (r'(?i)\\x[0-9a-f]{2}', 'Hex escape sequences')
                        ]
                        
                        matches = []
                        
                        for k, v in metadata.items():
                            if isinstance(v, (str, bytes)):
                                v_str = v if isinstance(v, str) else v.decode('utf-8', errors='ignore')
                                for pattern, desc in suspicious_patterns:
                                    if re.search(pattern, v_str):
                                        suspicious = True
                                        matches.append(f"{desc} in {k}")
                        
                        if suspicious:
                            details = f"Suspicious content in metadata: {', '.join(matches)}"
                
                except Exception as e:
                    if self.verbose:
                        logger.warning(f"Failed to analyze metadata: {str(e)}")
            
            # Try with exiftool if available (with retry mechanism)
            if not suspicious and not details:
                retries = 2
                while retries > 0:
                    try:
                        output = subprocess.check_output(
                            ['exiftool', self.image_path], 
                            universal_newlines=True,
                            timeout=30  # Add timeout to prevent hanging
                        )
                        
                        # Define patterns of concern
                        patterns = [
                            r'(?i)script',
                            r'(?i)exec',
                            r'(?i)eval',
                            r'(?i)<.*>',  # Potential HTML/XML/script tags
                            r'(?i)data:',  # Data URIs
                            r'(?i)0x[0-9a-f]{6,}',  # Long hex sequences
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, output)
                            if matches:
                                suspicious = True
                                details = f"Suspicious pattern '{pattern}' found in metadata"
                                break
                        break  # Success, exit retry loop
                            
                    except subprocess.TimeoutExpired:
                        retries -= 1
                        if retries == 0:
                            logger.warning(f"exiftool timed out for {self.image_path}")
                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Failed to run exiftool: {str(e)}")
                        break
        
        except Exception as e:
            logger.error(f"Error in metadata detection: {str(e)}")
        
        self.results['threats']['suspicious_metadata'] = (suspicious, details)

    def _detect_steganography(self) -> None:
        """
        Detect potential steganography in the image using multi-threaded analysis
        """
        suspicious = False
        details = None
        
        if PILLOW_AVAILABLE and OPENCV_AVAILABLE and 'numpy' in sys.modules:
            try:
                # LSB analysis
                img = cv2.imread(self.image_path)
                if img is not None:
                    results = {}
                    
                    # Create separate threads for each color channel analysis
                    futures = {
                        'blue': self.thread_pool.submit(self._analyze_channel_lsb, img[:,:,0]),
                        'green': self.thread_pool.submit(self._analyze_channel_lsb, img[:,:,1]),
                        'red': self.thread_pool.submit(self._analyze_channel_lsb, img[:,:,2])
                    }
                    
                    # Gather results
                    for channel, future in futures.items():
                        try:
                            ratio, entropy = future.result()
                            results[channel] = {'ratio': ratio, 'entropy': entropy}
                        except Exception as e:
                            logger.warning(f"Error analyzing {channel} channel: {str(e)}")
                    
                    # Analyze results
                    if results:
                        # Check for suspicious distribution (should be close to 0.5 for random data)
                        threshold = 0.05  # 5% deviation from expected 0.5
                        high_entropy_threshold = 0.97
                        
                        abnormal_distribution = False
                        high_entropy_detected = False
                        
                        for channel, data in results.items():
                            if abs(data['ratio'] - 0.5) > threshold:
                                abnormal_distribution = True
                            if data['entropy'] > high_entropy_threshold:
                                high_entropy_detected = True
                        
                        if abnormal_distribution:
                            suspicious = True
                            details = f"Suspicious LSB distribution: "
                            details += ", ".join([f"{ch.upper()}={data['ratio']:.4f}" 
                                                for ch, data in results.items()])
                        
                        if high_entropy_detected:
                            suspicious = True
                            if details:
                                details += f". High bit entropy: "
                            else:
                                details = f"High bit entropy suggests hidden data: "
                            details += ", ".join([f"{ch.upper()}={data['entropy']:.4f}" 
                                               for ch, data in results.items()])
            
            except Exception as e:
                logger.error(f"Failed to perform steganography detection: {str(e)}")
        
        self.results['threats']['steganography'] = (suspicious, details)
    
    def _analyze_channel_lsb(self, channel: "np.ndarray") -> Tuple[float, float]:
        """
        Analyze LSB distribution and entropy for a single color channel
        
        Args:
            channel (np.ndarray): The color channel to analyze
            
        Returns:
            Tuple[float, float]: (ratio, entropy) - LSB distribution ratio and entropy
        """
        # Extract LSBs
        lsb = channel & 1
        
        # Calculate distribution ratio
        ratio = np.sum(lsb) / lsb.size
        
        # Calculate entropy
        entropy = self._calculate_bit_entropy(lsb)
        
        return ratio, entropy
    
    def _calculate_bit_entropy(self, bit_plane: "np.ndarray") -> float:
        """
        Calculate Shannon entropy of a bit plane
        
        Args:
            bit_plane (np.ndarray): Binary array with 1s and 0s
            
        Returns:
            float: Entropy value between 0 and 1
        """
        # Calculate probabilities of 0s and 1s
        p0 = np.sum(bit_plane == 0) / bit_plane.size
        p1 = np.sum(bit_plane == 1) / bit_plane.size
        
        # Handle edge cases
        if p0 == 0 or p1 == 0:
            return 0
        
        # Calculate entropy
        entropy = -(p0 * np.log2(p0) + p1 * np.log2(p1))
        
        # Normalize to [0, 1]
        return entropy / 1.0  # Max entropy for binary data is 1.0

    def _detect_format_exploits(self, file_handle: BinaryIO) -> None:
        """
        Detect potential format-based exploits (polyglot files)
        """
        suspicious = False
        details = None
        
        try:
            # Define common file signatures
            file_signatures = {
                b'MZ': 'DOS/Windows executable',
                b'\x7fELF': 'Linux executable',
                b'\xca\xfe\xba\xbe': 'Mach-O binary',
                b'PK\x03\x04': 'ZIP archive',
                b'%PDF': 'PDF document',
                b'\x1f\x8b\x08': 'GZIP archive',
                b'BZh': 'BZIP2 archive',
                b'7z\xbc\xaf\x27\x1c': '7-Zip archive',
                b'Rar!\x1a\x07': 'RAR archive',
                b'wOFF': 'WOFF font file',
                b'<!DOCTYPE html': 'HTML document',
                b'<svg': 'SVG image',
                b'\xd0\xcf\x11\xe0': 'MS Office document',
                b'\x25\x21\x50\x53': 'PostScript file',
                b'\x00\x01\x00\x00\x00': 'TrueType font'
            }
            
            # Get expected format based on file extension
            expected_format = None
            if self.file_extension == '.png':
                expected_format = 'PNG image'
            elif self.file_extension in ['.jpg', '.jpeg']:
                expected_format = 'JPEG image'
            elif self.file_extension == '.gif':
                expected_format = 'GIF image'
            elif self.file_extension == '.bmp':
                expected_format = 'BMP image'
            elif self.file_extension == '.svg':
                expected_format = 'SVG image'
            elif self.file_extension == '.webp':
                expected_format = 'WebP image'
            elif self.file_extension in RAW_EXTENSIONS:
                expected_format = f"{RAW_EXTENSIONS[self.file_extension]} RAW image"
            
            # Scan file in chunks looking for signatures
            detected_formats = []
            
            # Read file in chunks
            file_handle.seek(0)
            
            # Only scan first 32KB for signatures
            scan_size = min(32 * 1024, self.file_size)
            file_content = file_handle.read(scan_size)
            
            # Check each signature
            for signature, format_name in file_signatures.items():
                start_pos = 0
                while True:
                    pos = file_content.find(signature, start_pos)
                    if pos == -1:
                        break
                    
                    # Skip expected format signature at beginning
                    if pos == 0 and expected_format and expected_format.lower() in format_name.lower():
                        start_pos = pos + len(signature)
                        continue
                    
                    detected_formats.append((pos, format_name))
                    start_pos = pos + len(signature)
            
            # Remove duplicates and sort by position
            detected_formats = sorted(set(detected_formats), key=lambda x: x[0])
            
            if len(detected_formats) > 0:
                suspicious = True
                format_list = [f"{fmt} at offset {pos}" for pos, fmt in detected_formats]
                details = f"Multiple format signatures detected: {', '.join(format_list)}"
            
            # Try with binwalk if available
            if not suspicious:
                try:
                    output = subprocess.check_output(
                        ['binwalk', '--no-color', self.image_path], 
                        universal_newlines=True,
                        timeout=30  # Add timeout to prevent hanging
                    )
                    
                    # Look for unexpected formats
                    formats = []
                    format_patterns = [
                        'executable',
                        'archive',
                        'filesystem',
                        'encryption',
                        'certificate',
                        'compressed',
                        'relocatable',
                        'script',
                        'PDF',
                        'HTML',
                        'XML'
                    ]
                    
                    for pattern in format_patterns:
                        if re.search(r'\b' + pattern + r'\b', output, re.IGNORECASE):
                            formats.append(pattern)
                    
                    if formats:
                        suspicious = True
                        details = f"Unexpected data formats detected with binwalk: {', '.join(formats)}"
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                    logger.warning(f"Binwalk error: {str(e)}")
                except FileNotFoundError:
                    if self.verbose:
                        logger.warning("Binwalk not found, skipping advanced format detection")
                except Exception as e:
                    if self.verbose:
                        logger.warning(f"Failed to run binwalk: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error in format exploit detection: {str(e)}")
        
        self.results['threats']['format_exploits'] = (suspicious, details)

    def _detect_suspicious_chunks(self) -> None:
        """
        Detect suspicious chunks in PNG files
        """
        suspicious = False
        details = None
        
        # Only for PNG files
        if not self.image_data.startswith(b'\x89PNG'):
            self.results['threats']['suspicious_chunks'] = (False, None)
            return
        
        # Analyze chunks
        pos = 8  # Skip PNG signature
        suspicious_chunks = []
        
        standard_chunks = {
            b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'cHRM', b'gAMA', 
            b'iCCP', b'sBIT', b'sRGB', b'tEXt', b'zTXt', b'iTXt', b'bKGD', 
            b'pHYs', b'sPLT', b'hIST', b'tIME'
        }
        
        while pos < len(self.image_data) - 12:  # Need at least 12 bytes for chunk header and CRC
            try:
                # Get chunk length and type
                length = int.from_bytes(self.image_data[pos:pos+4], byteorder='big')
                chunk_type = self.image_data[pos+4:pos+8]
                
                # Check for unusual or custom chunks
                if chunk_type not in standard_chunks:
                    suspicious_chunks.append(f"Non-standard chunk: {chunk_type.decode('ascii', errors='ignore')}")
                
                # For text chunks, check content
                if chunk_type in (b'tEXt', b'zTXt', b'iTXt'):
                    chunk_data = self.image_data[pos+8:pos+8+length]
                    suspicious_patterns = [b'script', b'exec', b'eval', b'<', b'0x', b'data:']
                    
                    for pattern in suspicious_patterns:
                        if pattern in chunk_data.lower():
                            suspicious_chunks.append(f"Suspicious content in {chunk_type.decode('ascii', errors='ignore')} chunk")
                            break
                
                # Move to next chunk
                pos += length + 12  # Length(4) + Type(4) + Data(length) + CRC(4)
                
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Error parsing PNG chunks: {str(e)}")
                break
        
        if suspicious_chunks:
            suspicious = True
            details = '. '.join(suspicious_chunks)
        
        self.results['threats']['suspicious_chunks'] = (suspicious, details)

    def _detect_svg_javascript(self) -> None:
        """
        Detect JavaScript and other scripting in SVG files
        """
        suspicious = False
        details = None
        
        # Only for SVG files
        if self.file_extension != '.svg' and not self.image_data.startswith(b'<svg') and b'<?xml' not in self.image_data[:100]:
            self.results['threats']['svg_javascript'] = (False, None)
            return
        
        # Convert binary to string for regex
        svg_content = self.image_data.decode('utf-8', errors='ignore')
        
        # Look for script tags
        script_tags = re.findall(r'<script.*?>.*?</script>', svg_content, re.DOTALL | re.IGNORECASE)
        
        # Look for JavaScript events
        js_events = re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', svg_content, re.IGNORECASE)
        
        # Look for JavaScript URLs
        js_urls = re.findall(r'(?:href|xlink:href)\s*=\s*["\']javascript:.*?["\']', svg_content, re.IGNORECASE)
        
        # Check for embedded scripts in other attributes
        embedded_js = re.findall(r'(?:values|content|style|d)\s*=\s*["\'][^"\']*\b(?:eval|function|alert|document|window|fetch|createElement|innerHTML)\b[^"\']*["\']', svg_content, re.IGNORECASE)
        
        # Check for data URIs
        data_uris = re.findall(r'data:[^;]*;base64,[a-zA-Z0-9+/=]+', svg_content, re.IGNORECASE)
        
        # Suspicious iframes
        iframes = re.findall(r'<iframe.*?</iframe>', svg_content, re.DOTALL | re.IGNORECASE)
        
        # Foreign objects (which can contain HTML)
        foreign_objects = re.findall(r'<foreignObject.*?</foreignObject>', svg_content, re.DOTALL | re.IGNORECASE)
        
        # Check for use elements with external references
        external_uses = re.findall(r'<use[^>]*(?:href|xlink:href)\s*=\s*["\'](?!#)[^"\']*["\']', svg_content, re.IGNORECASE)
        
        # Check for embedded HTML
        embedded_html = re.findall(r'<(?:div|span|iframe|html|body|head|meta)[^>]*>', svg_content, re.IGNORECASE)
        
        # Check for suspicious filters (can be used for remote inclusion)
        suspicious_filters = re.findall(r'<filter[^>]*>.*?<fe(?:Image|Distant|Remote|External)[^>]*(?:href|xlink:href)\s*=\s*["\'][^"\']*["\']', svg_content, re.DOTALL | re.IGNORECASE)
        
        # Look for encoded or obfuscated content
        obfuscated_content = re.findall(r'(?:eval|atob|unescape|decodeURI|String\.fromCharCode)\s*\(', svg_content, re.IGNORECASE)
        
        # Check for event handlers beyond the standard ones
        advanced_events = re.findall(r'(?:onload|onunload|onerror|onresize|onabort|onfocus|onblur|onchange|onsubmit|onreset|onselect|onkeydown|onkeypress|onkeyup|onclick|ondblclick|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onwheel)\s*=', svg_content, re.IGNORECASE)
        
        # Collect all findings
        findings = []
        
        if script_tags:
            findings.append(f"Script tags: {len(script_tags)}")
        
        if js_events:
            findings.append(f"JavaScript event handlers: {len(js_events)}")
        
        if js_urls:
            findings.append(f"JavaScript URLs: {len(js_urls)}")
        
        if embedded_js:
            findings.append(f"Attributes with embedded JavaScript: {len(embedded_js)}")
        
        if data_uris:
            findings.append(f"Data URIs: {len(data_uris)}")
        
        if iframes:
            findings.append(f"iframes: {len(iframes)}")
        
        if foreign_objects:
            findings.append(f"foreignObject elements: {len(foreign_objects)}")
            
        if external_uses:
            findings.append(f"External references in <use> elements: {len(external_uses)}")
            
        if embedded_html:
            findings.append(f"Embedded HTML elements: {len(embedded_html)}")
            
        if suspicious_filters:
            findings.append(f"Suspicious filter elements: {len(suspicious_filters)}")
            
        if obfuscated_content:
            findings.append(f"Potential obfuscated code: {len(obfuscated_content)}")
            
        if advanced_events:
            findings.append(f"Advanced event handlers: {len(advanced_events)}")
        
        if findings:
            suspicious = True
            details = ', '.join(findings)
        
        self.results['threats']['svg_javascript'] = (suspicious, details)

    def _analyze_raw_file(self) -> None:
        """
        Analyze RAW camera files for signs of tampering or embedded content
        """
        suspicious = False
        details = None
        
        # Check if extension is in recognized RAW formats
        if self.file_extension not in RAW_EXTENSIONS and not self.file_extension.lower() in [ext.lower() for ext in RAW_EXTENSIONS]:
            self.results['threats']['raw_file_tampering'] = (False, None)
            return
        
        # Try to analyze with rawpy if available
        if RAW_AVAILABLE:
            try:
                # Create a temporary copy to avoid modification by rawpy
                temp_file = os.path.join(TEMP_DIR, f"temp_raw_{os.path.basename(self.image_path)}")
                with open(temp_file, 'wb') as f:
                    f.write(self.image_data)
                
                # Try to open the RAW file
                with rawpy.imread(temp_file) as raw:
                    # Check for corruption or unexpected patterns
                    
                    # Get raw metadata if available
                    try:
                        metadata = {}
                        metadata['camera_manufacturer'] = raw.camera_manufacturer
                        metadata['camera_model'] = raw.camera_model
                        metadata['raw_pattern'] = str(raw.raw_pattern)
                        metadata['raw_type'] = str(raw.raw_type)
                        self.results['file_info']['raw_metadata'] = metadata
                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Failed to get RAW metadata: {str(e)}")
                    
                    # Look for unusual embedded preview formats
                    try:
                        if hasattr(raw, 'embedded_jpeg_buffer'):
                            jpeg_buffer = raw.embedded_jpeg_buffer
                            if jpeg_buffer is not None and len(jpeg_buffer) > 0:
                                # Save embedded JPEG to temp file for analysis
                                jpeg_temp = os.path.join(TEMP_DIR, "embedded_preview.jpg")
                                with open(jpeg_temp, 'wb') as f:
                                    f.write(jpeg_buffer)
                                
                                # Check embedded JPEG for tampering
                                embedded_analyzer = ImageSecurityAnalyzer(jpeg_temp, verbose=self.verbose)
                                embedded_results = embedded_analyzer.analyze()
                                
                                for threat_name, (is_suspicious, _) in embedded_results['threats'].items():
                                    if is_suspicious:
                                        suspicious = True
                                        if details:
                                            details += f". Suspicious embedded preview: {threat_name}"
                                        else:
                                            details = f"Suspicious embedded preview: {threat_name}"
                                
                                # Clean up
                                os.unlink(jpeg_temp)
                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Failed to analyze embedded preview: {str(e)}")
                
                    # Extract and analyze raw image data
                    try:
                        # Get raw data as numpy array
                        raw_data = raw.raw_image
                        if raw_data is not None:
                            # Check for unusual statistical patterns
                            # Most RAW data should follow a smooth histogram
                            hist, bins = np.histogram(raw_data.flatten(), bins=256)
                            
                            # Calculate smoothness of histogram
                            hist_diff = np.abs(hist[1:] - hist[:-1])
                            smoothness_score = np.sum(hist_diff) / np.sum(hist)
                            
                            # Check for unusual spikes or regularities
                            if smoothness_score > 0.5:  # Threshold determined empirically
                                suspicious = True
                                if details:
                                    details += f". Unusual raw data distribution (smoothness score: {smoothness_score:.2f})"
                                else:
                                    details = f"Unusual raw data distribution (smoothness score: {smoothness_score:.2f})"
                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Failed to analyze raw data: {str(e)}")
                
                # Clean up temp file
                os.unlink(temp_file)
            
            except Exception as e:
                # If rawpy can't open it but it should be a RAW file, this is suspicious
                suspicious = True
                details = f"RAW file appears corrupted or modified: {str(e)}"
        
        # Try with exiftool as a fallback
        if not suspicious and not details:
            try:
                output = subprocess.check_output(
                    ['exiftool', self.image_path], 
                    universal_newlines=True
                )
                
                # Check for modification indicators
                if 'Error' in output and 'File format error' in output:
                    suspicious = True
                    details = "RAW file appears to be corrupted or modified"
                
                # Check for unusual metadata
                manufacturer = RAW_EXTENSIONS.get(self.file_extension)
                if manufacturer:
                    # If we have a mismatch between extension and actual camera, that's suspicious
                    incorrect_manufacturer = False
                    
                    if manufacturer == 'Canon' and not re.search(r'Make.*Canon', output, re.IGNORECASE):
                        incorrect_manufacturer = True
                    elif manufacturer == 'Nikon' and not re.search(r'Make.*Nikon', output, re.IGNORECASE):
                        incorrect_manufacturer = True
                    elif manufacturer == 'Sony' and not re.search(r'Make.*Sony', output, re.IGNORECASE):
                        incorrect_manufacturer = True
                    elif manufacturer == 'Fujifilm' and not re.search(r'Make.*Fuji', output, re.IGNORECASE):
                        incorrect_manufacturer = True
                    
                    if incorrect_manufacturer:
                        suspicious = True
                        if details:
                            details += f". Camera manufacturer mismatch: expected {manufacturer}"
                        else:
                            details = f"Camera manufacturer mismatch: expected {manufacturer}"
                
                # Check for suspicious metadata patterns
                suspicious_patterns = [
                    r'(?i)modified after shooting',
                    r'(?i)software: (?!.*camera)',  # Software that's not camera firmware
                    r'(?i)edit time',
                    r'(?i)photoshop',
                    r'(?i)lightroom',
                    r'(?i)gimp'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, output):
                        suspicious = True
                        if details:
                            details += ". Signs of post-processing detected"
                        else:
                            details = "Signs of post-processing detected"
                        break
                
                # Check for embedded content
                embedded_patterns = [
                    r'(?i)embedded.*file',
                    r'(?i)audio',
                    r'(?i)video',
                    r'(?i)xml',
                    r'(?i)script',
                    r'(?i)document'
                ]
                
                for pattern in embedded_patterns:
                    if re.search(pattern, output):
                        suspicious = True
                        if details:
                            details += ". Unusual embedded content detected"
                        else:
                            details = "Unusual embedded content detected"
                        break
            
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Failed to run exiftool on RAW file: {str(e)}")
        
        # Add a specific check for DNG files, which could be converted from other formats
        if self.file_extension == '.dng':
            try:
                output = subprocess.check_output(
                    ['exiftool', '-DNGVersion', '-OriginalRawFileName', '-DocumentName', self.image_path], 
                    universal_newlines=True
                )
                
                # Check if this is a converted DNG
                if 'Original Raw File Name' in output or 'Document Name' in output:
                    # This is potentially a converted file, which is not inherently suspicious
                    # but should be noted
                    if not suspicious:
                        suspicious = False  # Don't mark as suspicious just for being converted
                        details = "Converted DNG file (not inherently suspicious)"
            
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Failed to check DNG conversion status: {str(e)}")
        
        self.results['threats']['raw_file_tampering'] = (suspicious, details)

    def _analyze_color_histograms(self) -> None:
        """
        Analyze color histograms for anomalies that could indicate steganography
        or other forms of hidden data
        """
        if not self.image:
            self.results['threats']['histogram_anomalies'] = (False, None)
            return
        
        try:
            suspicious = False
            details = None
            
            # Skip for SVG files
            if self.file_extension == '.svg':
                self.results['threats']['histogram_anomalies'] = (False, None)
                return
            
            # Convert to RGB if not already
            img_rgb = self.image
            if img_rgb.mode != 'RGB':
                img_rgb = img_rgb.convert('RGB')
            
            # Convert to numpy array
            img_array = np.array(img_rgb)
            
            # Analyze color channels
            channels = ['Red', 'Green', 'Blue']
            channel_histograms = {}
            channel_anomalies = []
            
            # Calculate histograms for each channel
            for i, channel in enumerate(channels):
                histogram, _ = np.histogram(img_array[:,:,i].flatten(), bins=256, range=(0, 256))
                channel_histograms[channel] = histogram
                
                # Normalize histogram
                norm_hist = histogram / np.sum(histogram)
                
                # Check for unusual distribution
                entropy = -np.sum(norm_hist * np.log2(norm_hist + 1e-10))
                
                # Most natural images have relatively high entropy
                # Very low or very high entropy can indicate tampering or hidden data
                if entropy < 3.0 or entropy > 7.5:  # Thresholds based on analysis of typical images
                    channel_anomalies.append(f"{channel}: unusual entropy ({entropy:.2f})")
                
                # Check for spikes in the histogram that could indicate hidden data
                # Calculate differences between adjacent bins
                hist_diff = np.abs(norm_hist[1:] - norm_hist[:-1])
                max_diff = np.max(hist_diff)
                
                # Check for unusually large spikes
                if max_diff > 0.05:  # Empirical threshold
                    spike_index = np.argmax(hist_diff) + 1
                    channel_anomalies.append(f"{channel}: unusual spike at intensity {spike_index}")
                
                # Check for LSB steganography:
                # In LSB stego, even and odd values tend to be more balanced than in natural images
                even_sum = np.sum(histogram[0::2])
                odd_sum = np.sum(histogram[1::2])
                
                # Calculate evenness ratio - how close to 1.0 (perfect balance)
                if odd_sum > 0:
                    evenness = even_sum / odd_sum
                    
                    # Natural images often have an evenness ratio between 0.9 and 1.1
                    # Significant deviation suggests possible LSB manipulation
                    if evenness < 0.92 or evenness > 1.08:
                        channel_anomalies.append(f"{channel}: unusual even/odd distribution ({evenness:.2f})")
            
            # Check for unusual correlations between channels
            # In natural images, RGB channels are typically correlated
            r_g_corr = np.corrcoef(channel_histograms['Red'], channel_histograms['Green'])[0, 1]
            r_b_corr = np.corrcoef(channel_histograms['Red'], channel_histograms['Blue'])[0, 1]
            g_b_corr = np.corrcoef(channel_histograms['Green'], channel_histograms['Blue'])[0, 1]
            
            # Low correlation could indicate manipulated data
            if r_g_corr < 0.7:
                channel_anomalies.append(f"Low R-G correlation: {r_g_corr:.2f}")
            if r_b_corr < 0.7:
                channel_anomalies.append(f"Low R-B correlation: {r_b_corr:.2f}")
            if g_b_corr < 0.7:
                channel_anomalies.append(f"Low G-B correlation: {g_b_corr:.2f}")
            
            # Analyze bit planes
            # Extract LSB planes which are often used for steganography
            bit_plane_anomalies = []
            for i, channel in enumerate(channels):
                # Extract least significant bit
                lsb_plane = (img_array[:,:,i] & 1)
                
                # Calculate bit plane entropy
                hist, _ = np.histogram(lsb_plane.flatten(), bins=2, range=(0, 1))
                if hist[0] > 0 and hist[1] > 0:  # Avoid division by zero
                    # Normalized entropy (0 to 1)
                    p0, p1 = hist / np.sum(hist)
                    entropy = -p0 * np.log2(p0) - p1 * np.log2(p1)
                    # Maximum entropy is 1.0 (perfect balance of 0s and 1s)
                    
                    # Natural images often have entropy less than 0.95 in LSB
                    # Very high entropy suggests possible hidden data
                    if entropy > 0.98:
                        bit_plane_anomalies.append(f"{channel} LSB: very high entropy ({entropy:.2f})")
                
                # Run test for randomness
                # Convert 2D array to 1D sequence
                lsb_seq = lsb_plane.flatten()
                runs = 1
                for j in range(1, len(lsb_seq)):
                    if lsb_seq[j] != lsb_seq[j-1]:
                        runs += 1
                
                # Expected runs for random sequence
                n = len(lsb_seq)
                n0 = np.sum(lsb_seq == 0)
                n1 = np.sum(lsb_seq == 1)
                
                # Avoid division by zero
                if n0 > 0 and n1 > 0:
                    expected_runs = (2 * n0 * n1) / n + 1
                    std_dev = np.sqrt((2 * n0 * n1 * (2 * n0 * n1 - n)) / (n**2 * (n - 1)))
                    
                    # Calculate z-score
                    if std_dev > 0:
                        z_score = abs((runs - expected_runs) / std_dev)
                        
                        # High z-score suggests non-randomness
                        # Too random is also suspicious (z close to 0)
                        if z_score < 0.2:
                            bit_plane_anomalies.append(f"{channel} LSB: suspiciously random (z={z_score:.2f})")
            
            # Combine all anomalies
            all_anomalies = channel_anomalies + bit_plane_anomalies
            
            if len(all_anomalies) >= 3:  # Threshold for suspiciousness
                suspicious = True
                details = f"Multiple histogram anomalies detected: {', '.join(all_anomalies[:5])}"
                if len(all_anomalies) > 5:
                    details += f" and {len(all_anomalies)-5} more"
            elif len(all_anomalies) > 0:
                # Some anomalies but not enough to mark as suspicious
                suspicious = False
                details = f"Minor histogram anomalies: {', '.join(all_anomalies)}"
            
            self.results['threats']['histogram_anomalies'] = (suspicious, details)
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Error in color histogram analysis: {str(e)}")
                logger.error(traceback.format_exc())
            self.results['threats']['histogram_anomalies'] = (False, None)

    def _perform_ml_analysis(self) -> None:
        """
        Perform machine learning-based detection of potential threats in images
        using pre-trained models or feature extraction techniques
        """
        if not self.image:
            self.results['threats']['ml_detection'] = (False, None)
            return
            
        try:
            suspicious = False
            details = None
            
            # Skip for SVG files
            if self.file_extension == '.svg':
                self.results['threats']['ml_detection'] = (False, None)
                return
                
            # Convert to RGB if not already
            img_rgb = self.image
            if img_rgb.mode != 'RGB':
                img_rgb = img_rgb.convert('RGB')
                
            # Resize image for consistent feature extraction
            img_resized = img_rgb.resize((256, 256))
            
            # Convert to numpy array
            img_array = np.array(img_resized)
            
            # Feature extraction - Basic approach using statistical features
            features = []
            
            # 1. Extract features from each color channel
            for channel in range(3):  # RGB
                channel_data = img_array[:, :, channel]
                
                # Statistical features
                mean = np.mean(channel_data)
                std = np.std(channel_data)
                skew = scipy.stats.skew(channel_data.flatten())
                kurt = scipy.stats.kurtosis(channel_data.flatten())
                
                # Edge features - using Sobel operators
                sobel_h = np.abs(scipy.ndimage.sobel(channel_data, axis=0))
                sobel_v = np.abs(scipy.ndimage.sobel(channel_data, axis=1))
                edge_mean = np.mean(sobel_h + sobel_v)
                edge_std = np.std(sobel_h + sobel_v)
                
                # Add to feature vector
                features.extend([mean, std, skew, kurt, edge_mean, edge_std])
                
            # 2. Noise analysis features
            # Extract noise using wavelet decomposition
            try:
                noise_features = []
                for channel in range(3):
                    channel_data = img_array[:, :, channel].astype(float)
                    # Use simple high-pass filter as approximation for noise
                    channel_blur = scipy.ndimage.gaussian_filter(channel_data, sigma=2)
                    noise = channel_data - channel_blur
                    
                    # Statistical features of noise
                    noise_mean = np.mean(noise)
                    noise_std = np.std(noise)
                    noise_skew = scipy.stats.skew(noise.flatten())
                    noise_kurt = scipy.stats.kurtosis(noise.flatten())
                    
                    noise_features.extend([noise_mean, noise_std, noise_skew, noise_kurt])
                
                features.extend(noise_features)
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Error extracting noise features: {str(e)}")
                # Add zeros if noise extraction fails
                features.extend([0.0] * 12)
                
            # 3. Compression analysis
            # Compare original vs high compression to detect artifacts
            try:
                # Create BytesIO buffer for compression
                buffer = io.BytesIO()
                img_rgb.save(buffer, format="JPEG", quality=10)
                buffer.seek(0)
                img_compressed = Image.open(buffer)
                img_compressed_array = np.array(img_compressed.resize((256, 256)))
                
                # Calculate difference metrics
                mse = np.mean((img_array.astype(float) - img_compressed_array.astype(float)) ** 2)
                if mse > 0:
                    psnr = 10 * np.log10((255 ** 2) / mse)
                else:
                    psnr = 100  # Arbitrary high value for identical images
                
                # Calculate SSIM
                gray_orig = np.dot(img_array[...,:3], [0.299, 0.587, 0.114])
                gray_comp = np.dot(img_compressed_array[...,:3], [0.299, 0.587, 0.114])
                
                # Simple SSIM approximation
                # (using full SSIM calculation would require additional dependencies)
                mu_orig = np.mean(gray_orig)
                mu_comp = np.mean(gray_comp)
                sigma_orig = np.std(gray_orig)
                sigma_comp = np.std(gray_comp)
                cov = np.mean((gray_orig - mu_orig) * (gray_comp - mu_comp))
                
                # Constants to stabilize division
                c1 = (0.01 * 255) ** 2
                c2 = (0.03 * 255) ** 2
                
                # Calculate SSIM
                ssim = ((2 * mu_orig * mu_comp + c1) * (2 * cov + c2)) / \
                       ((mu_orig**2 + mu_comp**2 + c1) * (sigma_orig**2 + sigma_comp**2 + c2))
                
                features.extend([mse, psnr, ssim])
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Error in compression analysis: {str(e)}")
                # Add default values if compression analysis fails
                features.extend([0.0, 100.0, 1.0])
            
            # 4. Feature normalization
            # Simple normalization to [0,1] range for each feature
            try:
                # Define typical min/max ranges for features to avoid outlier issues
                feature_ranges = [
                    # Mean (0-255), StdDev (0-128), Skew (-3,3), Kurt (-3,10) for each channel
                    (0, 255), (0, 128), (-3, 3), (-3, 10),  # Channel statistical features
                    (0, 50), (0, 50),  # Edge features
                ] * 3
                
                # Noise features
                feature_ranges.extend([
                    (-50, 50), (0, 50), (-3, 3), (-3, 10),  # Noise statistical features
                ] * 3)
                
                # Compression features
                feature_ranges.extend([
                    (0, 1000), (10, 50), (0, 1),  # MSE, PSNR, SSIM
                ])
                
                # Normalize each feature
                normalized_features = []
                for i, feat in enumerate(features):
                    if i < len(feature_ranges):
                        min_val, max_val = feature_ranges[i]
                        norm_feat = (feat - min_val) / (max_val - min_val) if max_val > min_val else 0.5
                        # Clip to [0,1]
                        norm_feat = max(0, min(norm_feat, 1))
                        normalized_features.append(norm_feat)
                    else:
                        # If we somehow have more features than ranges, use a default normalization
                        normalized_features.append(0.5)
                
                features = normalized_features
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Error normalizing features: {str(e)}")
            
            # 5. Apply detection rules based on features
            # In a production system, this would use a trained ML model
            # For now, we'll use heuristic rules based on the extracted features
            
            # Check for unusual edge patterns
            edge_features = [features[5+i*6] for i in range(3)]  # Extract edge means
            edge_std_features = [features[6+i*6] for i in range(3)]  # Extract edge stds
            
            avg_edge = sum(edge_features) / 3
            avg_edge_std = sum(edge_std_features) / 3
            
            # Check for histogram-based anomalies
            skew_features = [features[2+i*6] for i in range(3)]  # Extract skewness
            kurt_features = [features[3+i*6] for i in range(3)]  # Extract kurtosis
            
            # Check for noise pattern anomalies
            noise_start_idx = 18  # Starting index of noise features
            noise_means = [features[noise_start_idx+i*4] for i in range(3)]
            noise_stds = [features[noise_start_idx+1+i*4] for i in range(3)]
            
            # Check compression resistance
            mse_idx = 30  # Index of MSE feature
            psnr_idx = 31  # Index of PSNR feature
            ssim_idx = 32  # Index of SSIM feature
            
            # Anomaly score calculation
            anomaly_signals = []
            
            # 1. Check for edges - unusually high or low edge content
            if avg_edge > 0.8 or avg_edge < 0.05:
                anomaly_signals.append(f"Unusual edge patterns (score: {avg_edge:.2f})")
                
            # 2. Check for unusual skewness/kurtosis combinations
            for i, (skew, kurt) in enumerate(['Red', 'Green', 'Blue'], start=0):
                skew = skew_features[i]
                kurt = kurt_features[i]
                # Check for unusual combinations
                if (skew > 0.8 and kurt > 0.8) or (skew < 0.2 and kurt > 0.8):
                    anomaly_signals.append(f"Unusual {i} channel distribution (skew: {skew:.2f}, kurt: {kurt:.2f})")
            
            # 3. Check for noise patterns
            avg_noise_mean = sum(abs(nm) for nm in noise_means) / 3
            avg_noise_std = sum(noise_stds) / 3
            
            if avg_noise_mean > 0.7 or avg_noise_std > 0.7:
                anomaly_signals.append(f"Unusual noise pattern (mean: {avg_noise_mean:.2f}, std: {avg_noise_std:.2f})")
                
            # 4. Check compression resistance
            if features[psnr_idx] < 0.3:  # Low PSNR
                anomaly_signals.append(f"High compression resistance (PSNR: {features[psnr_idx]:.2f})")
            
            if features[ssim_idx] < 0.3:  # Low SSIM
                anomaly_signals.append(f"Unusual compression artifacts (SSIM: {features[ssim_idx]:.2f})")
            
            # Final decision
            if len(anomaly_signals) >= 2:
                suspicious = True
                details = f"ML anomalies detected: {', '.join(anomaly_signals[:3])}"
                if len(anomaly_signals) > 3:
                    details += f" and {len(anomaly_signals)-3} more"
            elif len(anomaly_signals) == 1:
                suspicious = False
                details = f"Minor ML anomaly: {anomaly_signals[0]}"
                
            self.results['threats']['ml_detection'] = (suspicious, details)
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Error in ML analysis: {str(e)}")
                logger.error(traceback.format_exc())
            self.results['threats']['ml_detection'] = (False, None)

    def _determine_risk_level(self) -> None:
        """
        Determine overall risk level based on all detection results
        """
        # Count number of detected threats
        detected_threats = sum(1 for threat, (is_detected, _) in self.results['threats'].items() if is_detected)
        
        # Convert to risk level
        if detected_threats == 0:
            self.results['risk_level'] = 'Low'
        elif detected_threats == 1:
            self.results['risk_level'] = 'Medium'
        elif detected_threats >= 2:
            self.results['risk_level'] = 'High'


def analyze_image(image_path: str, verbose: bool = False) -> Dict:
    """
    Analyze an image file for security issues
    
    Args:
        image_path (str): Path to the image file
        verbose (bool): Enable verbose output
        
    Returns:
        Dict: Analysis results
    """
    analyzer = ImageSecurityAnalyzer(image_path, verbose=verbose)
    return analyzer.analyze()


def main() -> None:
    """
    Main function when script is run directly
    """
    parser = argparse.ArgumentParser(description='Analyze images for security issues')
    parser.add_argument('image_path', help='Path to the image file to analyze')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', '-o', help='Output results to a file')
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.isfile(args.image_path):
        print(f"Error: File '{args.image_path}' does not exist")
        sys.exit(1)
    
    # Analyze image
    results = analyze_image(args.image_path, verbose=args.verbose)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()