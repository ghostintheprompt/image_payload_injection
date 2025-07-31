"""
ImageSanitizer module for cleaning and sanitizing potentially malicious image files.

This module provides tools for sanitizing image files by removing metadata,
normalizing formats, and cleaning potentially malicious content.
"""

import os
import subprocess
import logging
import tempfile
import shutil
from typing import Dict, Tuple, Union, Any, List, Optional


class ImageSanitizer:
    """
    Comprehensive image sanitizer for cleaning potentially malicious image files.
    
    This class provides methods to sanitize image files by removing metadata,
    normalizing formats, and cleaning potentially malicious content.
    """
    
    def __init__(self, logger=None):
        """
        Initialize an ImageSanitizer instance.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Configure logging if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            
        # Check for required tools
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check if required command-line tools are available."""
        missing_tools = []
        
        # Essential tools
        try:
            subprocess.run(['convert', '-version'], capture_output=True)
        except FileNotFoundError:
            missing_tools.append('ImageMagick (convert)')
            
        # Optional but recommended tools
        try:
            subprocess.run(['exiftool', '-ver'], capture_output=True)
        except FileNotFoundError:
            self.logger.warning("ExifTool not found. Some metadata operations will be limited.")
            
        if missing_tools:
            self.logger.warning(f"Missing required tools: {', '.join(missing_tools)}")
            self.logger.warning("Install these tools for full sanitizer functionality.")
    
    def sanitize(self, input_path: str, output_path: str = None, 
                options: Dict[str, Any] = None) -> Tuple[bool, Optional[str]]:
        """
        Sanitize an image file by removing metadata and potentially malicious content.
        
        Args:
            input_path: Path to the input image file
            output_path: Path to save the sanitized image (if None, will use input_path with '_clean' suffix)
            options: Dictionary of sanitization options
            
        Returns:
            Tuple of (success, message)
        """
        if not os.path.exists(input_path):
            return False, f"Input file does not exist: {input_path}"
            
        # Set default options
        default_options = {
            'remove_metadata': True,
            'normalize_format': True,
            'format_conversion': None,  # Auto-detect if None
            'max_dimensions': None,  # No resizing by default
            'force_regeneration': True,  # Decode and re-encode to eliminate hidden data
            'clean_color_profiles': True,  # Clean ICC profiles
            'sanitize_svg': True,  # Sanitize SVG files if applicable
            'png_cleanup': True,  # Special handling for PNG files
            'jpeg_cleanup': True,  # Special handling for JPEG files
        }
        
        # Update with user options
        if options:
            default_options.update(options)
            
        options = default_options
            
        # Determine output path if not provided
        if not output_path:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_clean{ext}"
            
        # Determine file type and use appropriate sanitization method
        file_ext = os.path.splitext(input_path)[1].lower()
        
        # Create temporary working directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_output = os.path.join(temp_dir, "temp_output" + file_ext)
            
            # SVG requires special handling
            if file_ext == '.svg' and options['sanitize_svg']:
                success, message = self._sanitize_svg(input_path, temp_output)
                if not success:
                    return False, message
                    
                # Use the sanitized SVG as input for further processing
                input_path = temp_output
            
            # Determine target format for conversion
            target_format = options['format_conversion']
            if not target_format:
                # Auto-detect based on input format
                if file_ext in ['.jpg', '.jpeg']:
                    target_format = 'JPEG'
                elif file_ext == '.png':
                    target_format = 'PNG'
                elif file_ext == '.gif':
                    target_format = 'GIF'
                elif file_ext == '.webp':
                    target_format = 'WEBP'
                elif file_ext == '.avif':
                    target_format = 'AVIF'
                elif file_ext == '.svg':
                    target_format = 'PNG'  # Convert SVG to PNG for safety
                else:
                    target_format = 'PNG'  # Default to PNG for unknown formats
            
            # Build ImageMagick command
            cmd = ['convert', input_path]
            
            # Add options based on the sanitization settings
            if options['remove_metadata']:
                cmd.extend(['-strip'])
            
            if options['max_dimensions']:
                width, height = options['max_dimensions']
                cmd.extend(['-resize', f'{width}x{height}>'])
            
            if options['force_regeneration']:
                cmd.extend(['-depth', '8'])
                
            if options['clean_color_profiles']:
                # Remove any embedded ICC profiles
                cmd.extend(['+profile', '*'])
                
            # Format-specific options
            if target_format == 'JPEG':
                cmd.extend(['-quality', '95'])
                
                # Special cleanup for JPEG files to ensure no hidden data
                if options['jpeg_cleanup']:
                    cmd.extend(['-interlace', 'none'])
                
            elif target_format == 'PNG':
                # Special cleanup for PNG files
                if options['png_cleanup']:
                    cmd.extend([
                        '-define', 'png:include-chunk=tRNS,cHRM,gAMA,sRGB',
                        '-define', 'png:exclude-chunk=iCCP,iTXt,zTXt,tEXt,oFFs,pHYs,sBIT'
                    ])
                
            # Add output path
            cmd.append(output_path)
            
            # Run the command
            try:
                self.logger.info(f"Sanitizing image: {input_path}")
                self.logger.debug(f"Command: {' '.join(cmd)}")
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    return False, f"Sanitization failed: {result.stderr}"
                
                self.logger.info(f"Image sanitized successfully: {output_path}")
                return True, f"Image sanitized successfully: {output_path}"
                
            except Exception as e:
                self.logger.error(f"Error during sanitization: {e}")
                return False, f"Error during sanitization: {e}"
    
    def _sanitize_svg(self, input_path: str, output_path: str) -> Tuple[bool, Optional[str]]:
        """
        Sanitize an SVG file by removing scripts and potentially dangerous elements.
        
        Args:
            input_path: Path to the input SVG file
            output_path: Path to save the sanitized SVG
            
        Returns:
            Tuple of (success, message)
        """
        try:
            import xml.etree.ElementTree as ET
            import re
            
            # Read SVG content
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Remove script tags
            content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
            
            # Remove event handlers
            event_handlers = [
                'onload', 'onclick', 'onmouseover', 'onmouseout', 'onerror',
                'onactivate', 'onbegin', 'onend', 'onfocusin', 'onfocusout'
            ]
            
            for handler in event_handlers:
                content = re.sub(f' {handler}="[^"]*"', '', content, flags=re.IGNORECASE)
                
            # Remove JavaScript URLs
            content = re.sub(r'javascript:[^\'"]*', '', content, flags=re.IGNORECASE)
            
            # Remove potentially harmful elements that could contain foreign content
            harmful_elements = ['foreignObject', 'iframe', 'embed', 'object']
            
            for element in harmful_elements:
                content = re.sub(f'<{element}[^>]*>.*?</{element}>', '', content, 
                                flags=re.DOTALL | re.IGNORECASE)
            
            # Remove external references
            content = re.sub(r'xlink:href="(?!#)[^"]*"', '', content, flags=re.IGNORECASE)
            
            # Write sanitized SVG
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            self.logger.info(f"SVG sanitized: {output_path}")
            return True, f"SVG sanitized: {output_path}"
            
        except Exception as e:
            self.logger.error(f"Error sanitizing SVG: {e}")
            return False, f"Error sanitizing SVG: {e}"
    
    def batch_sanitize(self, input_dir: str, output_dir: str = None, 
                      options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Sanitize all supported image files in a directory.
        
        Args:
            input_dir: Directory containing images to sanitize
            output_dir: Directory to save sanitized images (created if it doesn't exist)
            options: Dictionary of sanitization options
            
        Returns:
            Dictionary with sanitization results
        """
        if not os.path.isdir(input_dir):
            self.logger.error(f"Input directory does not exist: {input_dir}")
            return {"success": False, "message": f"Input directory does not exist: {input_dir}"}
            
        # Create output directory if it doesn't exist
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        elif not output_dir:
            output_dir = os.path.join(input_dir, "sanitized")
            os.makedirs(output_dir, exist_ok=True)
            
        # Track results
        results = {
            "success": True,
            "total": 0,
            "successful": 0,
            "failed": 0,
            "skipped": 0,
            "details": {}
        }
        
        # Supported image extensions
        supported_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', 
            '.webp', '.avif', '.tiff', '.tif'
        ]
        
        # Process each file
        for root, _, files in os.walk(input_dir):
            for file in files:
                # Check if file is a supported image
                if any(file.lower().endswith(ext) for ext in supported_extensions):
                    input_path = os.path.join(root, file)
                    
                    # Create relative path structure in output directory
                    rel_path = os.path.relpath(input_path, input_dir)
                    output_path = os.path.join(output_dir, rel_path)
                    
                    # Create intermediate directories if needed
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    # Sanitize the image
                    results["total"] += 1
                    success, message = self.sanitize(input_path, output_path, options)
                    
                    if success:
                        results["successful"] += 1
                    else:
                        results["failed"] += 1
                    
                    # Store details
                    results["details"][input_path] = {
                        "success": success,
                        "message": message,
                        "output_path": output_path if success else None
                    }
                    
        # Update overall success flag
        if results["failed"] > 0:
            results["success"] = False
            
        return results
    
    def sanitize_for_web(self, input_path: str, output_path: str = None) -> Tuple[bool, Optional[str]]:
        """
        Sanitize an image specifically for web usage with stricter settings.
        
        Args:
            input_path: Path to the input image file
            output_path: Path to save the sanitized image
            
        Returns:
            Tuple of (success, message)
        """
        web_options = {
            'remove_metadata': True,
            'normalize_format': True,
            'format_conversion': 'PNG',  # Convert to PNG for maximum safety
            'max_dimensions': (2000, 2000),  # Reasonable maximum size
            'force_regeneration': True,
            'clean_color_profiles': True,
            'sanitize_svg': True,
            'png_cleanup': True,
            'jpeg_cleanup': True
        }
        
        return self.sanitize(input_path, output_path, web_options)
    
    def create_sanitization_report(self, results: Dict[str, Any], output_path: str) -> None:
        """
        Create an HTML report of batch sanitization results.
        
        Args:
            results: Dictionary with sanitization results from batch_sanitize
            output_path: Path to save the HTML report
        """
        html_report = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Image Sanitization Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2 { color: #333; }
                .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .success { color: green; }
                .failure { color: red; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f0f0f0; }
                tr:nth-child(even) { background-color: #f9f9f9; }
            </style>
        </head>
        <body>
            <h1>Image Sanitization Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total images processed: {total}</p>
                <p>Successfully sanitized: <span class="success">{successful}</span></p>
                <p>Failed to sanitize: <span class="failure">{failed}</span></p>
                <p>Skipped: {skipped}</p>
            </div>
            
            <h2>Details</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Result</th>
                    <th>Details</th>
                    <th>Output Path</th>
                </tr>
        """.format(
            total=results["total"],
            successful=results["successful"],
            failed=results["failed"],
            skipped=results["skipped"]
        )
        
        # Add details for each file
        for file_path, details in results["details"].items():
            status = "Success" if details["success"] else "Failed"
            status_class = "success" if details["success"] else "failure"
            
            html_report += f"""
            <tr>
                <td>{file_path}</td>
                <td class="{status_class}">{status}</td>
                <td>{details["message"]}</td>
                <td>{details["output_path"] or "N/A"}</td>
            </tr>
            """
            
        html_report += """
            </table>
        </body>
        </html>
        """
        
        # Write the report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_report)


def sanitize_image(input_path: str, output_path: str = None, options: Dict[str, Any] = None) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to sanitize an image without creating a sanitizer instance.
    
    Args:
        input_path: Path to the input image file
        output_path: Path to save the sanitized image
        options: Dictionary of sanitization options
        
    Returns:
        Tuple of (success, message)
    """
    sanitizer = ImageSanitizer()
    return sanitizer.sanitize(input_path, output_path, options)


if __name__ == "__main__":
    # Simple CLI interface when run directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Sanitize images to remove potentially malicious content")
    parser.add_argument("input", help="Input image file or directory")
    parser.add_argument("--output", "-o", help="Output path for sanitized image or directory")
    parser.add_argument("--batch", "-b", action="store_true", help="Batch process a directory of images")
    parser.add_argument("--web", "-w", action="store_true", help="Use stricter sanitization for web usage")
    parser.add_argument("--format", "-f", choices=["jpg", "png", "gif", "webp", "avif"], 
                      help="Convert to specified format")
    parser.add_argument("--keep-metadata", "-k", action="store_true", help="Keep image metadata")
    parser.add_argument("--max-width", type=int, help="Maximum image width")
    parser.add_argument("--max-height", type=int, help="Maximum image height")
    parser.add_argument("--report", "-r", help="Generate HTML report (batch mode only)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=logging_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create sanitizer
    sanitizer = ImageSanitizer()
    
    # Set up options
    options = {
        'remove_metadata': not args.keep_metadata,
        'format_conversion': args.format.upper() if args.format else None
    }
    
    # Set max dimensions if specified
    if args.max_width or args.max_height:
        width = args.max_width or 10000  # Large default value
        height = args.max_height or 10000  # Large default value
        options['max_dimensions'] = (width, height)
    
    # Check if input is a file or directory
    if os.path.isfile(args.input):
        # Single file mode
        if args.batch:
            logging.warning("Batch mode (-b) specified but input is a single file. Ignoring batch option.")
            
        # Use web sanitization if requested
        if args.web:
            success, message = sanitizer.sanitize_for_web(args.input, args.output)
        else:
            success, message = sanitizer.sanitize(args.input, args.output, options)
            
        print(message)
        if not success:
            exit(1)
            
    elif os.path.isdir(args.input):
        # Directory mode
        if not args.batch:
            logging.warning("Input is a directory but batch mode (-b) not specified. Assuming batch mode.")
            
        results = sanitizer.batch_sanitize(args.input, args.output, options)
        
        # Print summary
        print(f"\nSanitization Summary:")
        print(f"Total: {results['total']}")
        print(f"Successful: {results['successful']}")
        print(f"Failed: {results['failed']}")
        print(f"Skipped: {results['skipped']}")
        
        # Generate report if requested
        if args.report:
            sanitizer.create_sanitization_report(results, args.report)
            print(f"\nReport generated: {args.report}")
            
        if results['failed'] > 0:
            exit(1)
            
    else:
        print(f"Error: Input path does not exist: {args.input}")
        exit(1)