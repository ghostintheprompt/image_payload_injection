"""
ImageSanitizer module for cleaning and sanitizing potentially malicious image files.

This module provides tools for sanitizing image files by removing metadata,
normalizing formats, and cleaning potentially malicious content.
"""

import json
import os
import subprocess
import logging
import tempfile
import shutil
import shlex
from typing import Dict, List, Tuple, Union, Any, Optional


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


class RedBlueTester:
    """
    Red vs. Blue sanitization stress-tester.

    Red team: generates payloads using VLM exploit techniques (EXIF injection,
    PNG tEXt chunks, invisible typography, polyglot chunks).
    Blue team: runs each payload through a sanitization pipeline and records
    what survives.

    Measures literal marker retention and reports pixel comparison separately.
    Unknown pixel/model effects are not sanitizer passes or confirmed bypasses.
    Pipeline and generation failures are explicit errors. No model is queried.
    """

    SANITIZATION_PIPELINES = {
        "imagemagick_strip": "convert {input} -strip {output}",
        "imagemagick_full": (
            "convert {input} -strip -depth 8 +profile '*' "
            "-define png:exclude-chunk=tEXt,iTXt,zTXt,iCCP {output}"
        ),
        "pillow_reopen": "_pillow_reopen",
        "pillow_reopen_no_exif": "_pillow_reopen_no_exif",
    }

    TECHNIQUE_LABELS = [
        "exif_usercomment",
        "png_text_chunk",
        "png_polyglot_iipj",
        "invisible_contrast",
        "micro_typography",
        "channel_isolated",
        "adversarial_perturbation",
    ]

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self._check_dependencies()

    def _check_dependencies(self):
        missing = []
        try:
            subprocess.run(["convert", "-version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            missing.append("ImageMagick")
        try:
            import PIL  # noqa: F401
        except ImportError:
            missing.append("Pillow")
        if missing:
            self.logger.warning("RedBlueTester missing tools: %s", ", ".join(missing))

    # ------------------------------------------------------------------
    # Payload generators (red team)
    # ------------------------------------------------------------------

    def _make_exif_usercomment_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Inject instruction into EXIF UserComment (tag 0x9286) via raw struct."""
        import struct, zlib

        # Build a minimal JPEG with EXIF containing the instruction
        # We embed it inside a PNG tEXt chunk named "Raw-profile-type-exif" so
        # Pillow/libpng surfaces it — this mimics what camera-generated PNGs do.
        exif_ascii = ("ASCII\x00\x00\x00" + instruction).encode("latin-1", errors="replace")
        tag_data = struct.pack(">HHHI", 0x9286, 2, len(exif_ascii), 8) + exif_ascii
        ifd = struct.pack(">H", 1) + tag_data + struct.pack(">I", 0)
        tiff_header = b"MM\x00\x2a" + struct.pack(">I", 8) + ifd
        profile_hex = tiff_header.hex().upper()
        chunk_data = b"Raw profile type exif\n\nexif\n" + str(len(tiff_header)).encode() + b"\n"
        chunk_data += (profile_hex + "\n").encode()
        crc = zlib.crc32(b"tEXt" + chunk_data) & 0xFFFFFFFF
        exif_chunk = struct.pack(">I", len(chunk_data)) + b"tEXt" + chunk_data + struct.pack(">I", crc)

        iend_pos = base_png.rfind(b"IEND")
        if iend_pos < 4:
            return base_png
        insert_at = iend_pos - 4
        return base_png[:insert_at] + exif_chunk + base_png[insert_at:]

    def _make_png_text_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Inject instruction into multiple PNG tEXt chunks."""
        import struct, zlib

        chunks = b""
        fields = {
            "Comment": instruction,
            "Description": instruction,
            "Author": "system",
            "Copyright": instruction[:80],
        }
        for key, val in fields.items():
            data = key.encode() + b"\x00" + val.encode("utf-8", errors="replace")
            crc = zlib.crc32(b"tEXt" + data) & 0xFFFFFFFF
            chunks += struct.pack(">I", len(data)) + b"tEXt" + data + struct.pack(">I", crc)

        iend_pos = base_png.rfind(b"IEND")
        if iend_pos < 4:
            return base_png
        insert_at = iend_pos - 4
        return base_png[:insert_at] + chunks + base_png[insert_at:]

    def _make_polyglot_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Inject a custom iiPj chunk (polyglot marker for AI pipeline parsers)."""
        import struct, zlib

        payload = json.dumps({"role": "system", "content": instruction}).encode()
        crc = zlib.crc32(b"iiPj" + payload) & 0xFFFFFFFF
        chunk = struct.pack(">I", len(payload)) + b"iiPj" + payload + struct.pack(">I", crc)
        iend_pos = base_png.rfind(b"IEND")
        if iend_pos < 4:
            return base_png
        insert_at = iend_pos - 4
        return base_png[:insert_at] + chunk + base_png[insert_at:]

    def _make_invisible_text_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Draw near-invisible text (contrast delta=2) over the image using Pillow."""
        try:
            from PIL import Image, ImageDraw
            import io

            img = Image.open(io.BytesIO(base_png)).convert("RGB")
            draw = ImageDraw.Draw(img)
            # Sample background color at top-left and add delta=2
            bg = img.getpixel((0, 0))
            fg = tuple(min(255, c + 2) for c in bg)
            draw.text((2, 2), instruction[:200], fill=fg)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            return base_png

    def _make_micro_typography_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Tile 2px micro-font text across image (requires Pillow)."""
        try:
            from PIL import Image, ImageDraw
            import io

            img = Image.open(io.BytesIO(base_png)).convert("RGB")
            draw = ImageDraw.Draw(img)
            w, h = img.size
            snippet = instruction[:40]
            y = 0
            while y < h:
                x = 0
                while x < w:
                    draw.text((x, y), snippet, fill=(200, 200, 200))
                    x += max(1, len(snippet) * 2)
                y += 4
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            return base_png

    def _make_channel_isolated_payload(self, base_png: bytes, instruction: str) -> bytes:
        """Write instruction text into blue channel only (opacity=15)."""
        try:
            from PIL import Image, ImageDraw
            import io
            import numpy as np

            img = Image.open(io.BytesIO(base_png)).convert("RGBA")
            arr = np.array(img, dtype=np.uint8)
            overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(overlay)
            draw.text((4, 4), instruction[:150], fill=(0, 0, 255, 15))
            ov_arr = np.array(overlay)
            # Blend only blue channel where alpha > 0
            mask = ov_arr[:, :, 3] > 0
            arr[mask, 2] = np.clip(arr[mask, 2].astype(int) + 30, 0, 255).astype(np.uint8)
            result = Image.fromarray(arr, "RGBA").convert("RGB")
            buf = io.BytesIO()
            result.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            return base_png

    def _make_adversarial_perturbation(self, base_png: bytes) -> bytes:
        """Apply frequency-domain adversarial noise (no instruction — pixel-level attack)."""
        try:
            from PIL import Image
            import io
            import numpy as np

            img = Image.open(io.BytesIO(base_png)).convert("RGB")
            arr = np.array(img, dtype=np.float32)
            eps = 4.0 / 255.0
            for c in range(3):
                fft = np.fft.fft2(arr[:, :, c])
                h, w = arr.shape[:2]
                cy, cx = h // 2, w // 2
                r = min(cy, cx) // 3
                mask = np.zeros((h, w))
                for y in range(h):
                    for x in range(w):
                        if (y - cy) ** 2 + (x - cx) ** 2 > r ** 2:
                            mask[y, x] = 1.0
                noise = np.real(np.fft.ifft2(fft * mask))
                noise = np.sign(noise) * eps * 255.0
                arr[:, :, c] = np.clip(arr[:, :, c] + noise, 0, 255)
            result = Image.fromarray(arr.astype(np.uint8), "RGB")
            buf = io.BytesIO()
            result.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            return base_png

    # ------------------------------------------------------------------
    # Sanitization runners (blue team)
    # ------------------------------------------------------------------

    def _run_imagemagick(self, payload: bytes, args: str) -> bytes:
        with tempfile.TemporaryDirectory(prefix="ipi-sanitize-") as folder:
            in_path = os.path.join(folder, "input.png")
            out_path = os.path.join(folder, "output.png")
            with open(in_path, "wb") as handle:
                handle.write(payload)
            command = [part.replace("{input}", in_path).replace("{output}", out_path)
                       for part in shlex.split(args)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            if result.returncode != 0:
                raise RuntimeError("ImageMagick failed: " + result.stderr.decode(errors="replace")[:500])
            if not os.path.isfile(out_path):
                raise RuntimeError("ImageMagick produced no output")
            with open(out_path, "rb") as handle:
                output = handle.read()
            from PIL import Image
            import io
            with Image.open(io.BytesIO(output)) as image:
                image.verify()
            return output

    def _run_pillow_reopen(self, payload: bytes, strip_exif: bool = False) -> bytes:
        from PIL import Image
        import io
        with Image.open(io.BytesIO(payload)) as source:
            img = source.convert("RGB")
            buf = io.BytesIO()
            if strip_exif:
                img.save(buf, format="PNG")
            else:
                img.save(buf, format="PNG", exif=source.getexif())
            return buf.getvalue()

    def _sanitize(self, payload: bytes, pipeline_key: str) -> bytes:
        cmd = self.SANITIZATION_PIPELINES[pipeline_key]
        if cmd == "_pillow_reopen":
            return self._run_pillow_reopen(payload, strip_exif=False)
        if cmd == "_pillow_reopen_no_exif":
            return self._run_pillow_reopen(payload, strip_exif=True)
        return self._run_imagemagick(payload, cmd)

    # ------------------------------------------------------------------
    # Payload survival detection
    # ------------------------------------------------------------------

    def _check_survival(self, sanitized: bytes, instruction: str, technique: str) -> Dict:
        """Literal-byte evidence only; pixel/model survival remains unknown."""
        if not instruction or not instruction.strip():
            raise ValueError("A nonempty marker is required")
        pixel_techniques = {"adversarial_perturbation", "invisible_contrast",
                            "micro_typography", "channel_isolated"}
        if technique in pixel_techniques:
            return {"survived": None, "status": "unknown",
                    "note": "Pixel retention/readability or model effect is not measured by a literal-byte search."}
        present = instruction.encode("utf-8") in sanitized
        return {"survived": present,
                "status": "marker_present" if present else "marker_not_found",
                "note": "Full UTF-8 marker found in output bytes." if present else
                        "Literal UTF-8 marker not found; other encodings and downstream behavior are not assessed."}

    @staticmethod
    def _compare_pixels(before: bytes, after: bytes) -> Dict:
        from PIL import Image
        import io
        with Image.open(io.BytesIO(before)) as first, Image.open(io.BytesIO(after)) as second:
            a, b = first.convert("RGB"), second.convert("RGB")
            return {"pixels_identical": a.size == b.size and a.tobytes() == b.tobytes(),
                    "comparison": "decoded RGB pixels; no OCR or model inference"}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_full_matrix(self, base_png: bytes, instruction: str = "AUDIT_MARKER_TEXT_ONLY") -> Dict:
        """Return measured marker retention, unknown pixel effects, and errors.

        critical_bypasses is a deprecated empty field retained for API clients.
        No marker-retention result is automatically assigned a severity.
        """
        if not instruction or not instruction.strip():
            raise ValueError("A nonempty marker is required")
        generators = {
            "exif_usercomment": self._make_exif_usercomment_payload,
            "png_text_chunk": self._make_png_text_payload,
            "png_polyglot_iipj": self._make_polyglot_payload,
            "invisible_contrast": self._make_invisible_text_payload,
            "micro_typography": self._make_micro_typography_payload,
            "channel_isolated": self._make_channel_isolated_payload,
            "adversarial_perturbation": self._make_adversarial_perturbation,
        }
        summary, findings, retained = {}, [], []
        for technique, generate in generators.items():
            summary[technique] = {}
            try:
                payload = generate(base_png) if technique == "adversarial_perturbation" else generate(base_png, instruction)
                if payload == base_png:
                    raise RuntimeError("Generator returned unchanged input; fixture construction is unconfirmed")
                generation_error = None
            except Exception as exc:
                generation_error = str(exc)
            for pipeline in self.SANITIZATION_PIPELINES:
                try:
                    if generation_error is not None:
                        raise RuntimeError("Generation failed: " + generation_error)
                    sanitized = self._sanitize(payload, pipeline)
                    verdict = self._check_survival(sanitized, instruction, technique)
                    verdict["pipeline_success"] = True
                    if verdict["status"] == "unknown":
                        verdict.update(self._compare_pixels(payload, sanitized))
                except Exception as exc:
                    verdict = {"survived": None, "status": "error", "pipeline_success": False,
                               "note": str(exc)}
                summary[technique][pipeline] = verdict
                row = {"technique": technique, "pipeline": pipeline, **verdict}
                findings.append(row)
                if verdict.get("survived") is True:
                    retained.append(row)
        return {"summary": summary, "findings": findings, "retained_markers": retained,
                "critical_bypasses": [], "model_tested": False,
                "measurement_scope": "Literal UTF-8 marker retention and decoded RGB comparison only; no automatic severity."}

    def report_text(self, matrix: Dict) -> str:
        pipelines = list(self.SANITIZATION_PIPELINES)
        width = 26
        header = f"{'Technique':<30}" + "".join(f"{p:<{width}}" for p in pipelines)
        lines = [header, "-" * len(header)]
        labels = {"marker_present": "MARKER FOUND", "marker_not_found": "MARKER NOT FOUND",
                  "unknown": "UNKNOWN", "error": "ERROR"}
        for technique in self.TECHNIQUE_LABELS:
            cells = matrix["summary"].get(technique, {})
            lines.append(f"{technique:<30}" + "".join(
                f"{labels.get(cells.get(p, {}).get('status'), 'UNKNOWN'):<{width}}" for p in pipelines))
        lines.append(f"\nRetained literal markers: {len(matrix.get('retained_markers', []))}")
        lines.append("Marker absence is not a safety verdict. Pixel/model effects may be unknown; no severity assigned.")
        return "\n".join(lines)


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