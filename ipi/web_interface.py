"""
Web interface for ImagePayloadInjection analysis and sanitization.

This module provides a web-based interface for analyzing and sanitizing images,
making the toolkit accessible through a browser.
"""

import os
import json
import uuid
import tempfile
from datetime import datetime
import logging
from typing import Dict, Any, List

from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

# Import IPI modules
from ipi.analyzer import ImageAnalyzer
from ipi.sanitizer import ImageSanitizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
app.config['UPLOAD_FOLDER'] = os.path.join(tempfile.gettempdir(), 'ipi_uploads')
app.config['RESULT_FOLDER'] = os.path.join(tempfile.gettempdir(), 'ipi_results')

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# Initialize analyzer and sanitizer
analyzer = ImageAnalyzer()
sanitizer = ImageSanitizer()


def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'avif', 'tiff', 'tif', 
                         'cr2', 'nef', 'arw', 'raf', 'dng', 'raw'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_image():
    """
    Analyze an uploaded image file.
    
    Returns:
        JSON response with analysis results
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported'}), 400
        
    try:
        # Generate unique filename
        unique_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        unique_filename = f"{base}_{unique_id}{ext}"
        
        # Save uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Analyze the image
        results = analyzer.scan(file_path)
        
        # Add file info to results
        results['file_info']['original_filename'] = filename
        results['file_info']['unique_id'] = unique_id
        
        # Save results for later reference
        result_path = os.path.join(app.config['RESULT_FOLDER'], f"{unique_id}.json")
        with open(result_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error analyzing image: {e}")
        return jsonify({'error': f"Error analyzing image: {str(e)}"}), 500


@app.route('/sanitize', methods=['POST'])
def sanitize_image():
    """
    Sanitize an uploaded image file.
    
    Returns:
        JSON response with sanitization results
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'File type not supported'}), 400
        
    # Get options
    options = {
        'remove_metadata': request.form.get('remove_metadata', 'true').lower() == 'true',
        'format_conversion': request.form.get('format_conversion', None),
        'sanitize_svg': request.form.get('sanitize_svg', 'true').lower() == 'true',
    }
    
    # Get max dimensions if provided
    max_width = request.form.get('max_width')
    max_height = request.form.get('max_height')
    if max_width and max_height:
        options['max_dimensions'] = (int(max_width), int(max_height))
    
    try:
        # Generate unique filename
        unique_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        
        # Determine output extension based on format conversion
        output_ext = ext
        if options['format_conversion']:
            if options['format_conversion'].lower() == 'jpeg':
                output_ext = '.jpg'
            elif options['format_conversion'].lower() == 'png':
                output_ext = '.png'
            elif options['format_conversion'].lower() == 'webp':
                output_ext = '.webp'
            elif options['format_conversion'].lower() == 'avif':
                output_ext = '.avif'
                
        unique_filename = f"{base}_{unique_id}{ext}"
        sanitized_filename = f"{base}_{unique_id}_sanitized{output_ext}"
        
        # Save uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Sanitize the image
        output_path = os.path.join(app.config['RESULT_FOLDER'], sanitized_filename)
        success, message = sanitizer.sanitize(file_path, output_path, options)
        
        if success:
            # Use web-safe URLs
            download_url = f"/download/{sanitized_filename}"
            return jsonify({
                'success': True, 
                'message': message,
                'download_url': download_url,
                'original_filename': filename
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        logger.error(f"Error sanitizing image: {e}")
        return jsonify({'success': False, 'error': f"Error sanitizing image: {str(e)}"}), 500


@app.route('/download/<filename>')
def download_file(filename):
    """
    Download a sanitized image file.
    
    Args:
        filename: Name of the file to download
        
    Returns:
        The requested file
    """
    return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)


@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple uploaded image files.
    
    Returns:
        JSON response with analysis results for all files
    """
    if 'files[]' not in request.files:
        return jsonify({'error': 'No files part'}), 400
        
    files = request.files.getlist('files[]')
    
    if not files or len(files) == 0:
        return jsonify({'error': 'No selected files'}), 400
        
    results = {}
    
    for file in files:
        if file.filename == '':
            continue
            
        if not allowed_file(file.filename):
            results[file.filename] = {'error': 'File type not supported'}
            continue
            
        try:
            # Generate unique filename
            unique_id = str(uuid.uuid4())
            filename = secure_filename(file.filename)
            base, ext = os.path.splitext(filename)
            unique_filename = f"{base}_{unique_id}{ext}"
            
            # Save uploaded file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Analyze the image
            scan_results = analyzer.scan(file_path)
            results[file.filename] = scan_results
            
        except Exception as e:
            logger.error(f"Error analyzing {file.filename}: {e}")
            results[file.filename] = {'error': str(e)}
    
    # Generate unique batch ID and save batch results
    batch_id = str(uuid.uuid4())
    batch_results = {
        'timestamp': datetime.now().isoformat(),
        'batch_id': batch_id,
        'file_count': len(files),
        'results': results
    }
    
    batch_path = os.path.join(app.config['RESULT_FOLDER'], f"batch_{batch_id}.json")
    with open(batch_path, 'w') as f:
        json.dump(batch_results, f, indent=2)
        
    return jsonify(batch_results)


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    API endpoint for analyzing an image.
    
    Returns:
        JSON response with analysis results
    """
    return analyze_image()


@app.route('/api/sanitize', methods=['POST'])
def api_sanitize():
    """
    API endpoint for sanitizing an image.
    
    Returns:
        JSON response with sanitization results
    """
    return sanitize_image()


@app.route('/api/batch_analyze', methods=['POST'])
def api_batch_analyze():
    """
    API endpoint for batch analyzing images.
    
    Returns:
        JSON response with batch analysis results
    """
    return batch_analyze()


def create_app():
    """
    Factory function for creating the Flask app.
    
    Returns:
        Flask application instance
    """
    return app


def _generate_report_html(self, results):
    """Generate detailed HTML report from analysis results"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image Security Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
            .container { max-width: 1000px; margin: 0 auto; }
            h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
            h2 { color: #444; margin-top: 20px; }
            .result-section { margin: 15px 0; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }
            .threat { color: #d9534f; }
            .safe { color: #5cb85c; }
            .warning { color: #f0ad4e; }
            .threat-details { margin-left: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            .metadata-item { margin: 5px 0; }
            .image-preview { max-width: 400px; max-height: 400px; margin: 20px 0; border: 1px solid #ddd; }
            .code-block { background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Image Security Analysis Report</h1>
    """

    # Basic file information
    html += """
            <div class="result-section">
                <h2>File Information</h2>
    """
    if 'file_info' in results:
        info = results['file_info']
        html += f"""
                <p><strong>Filename:</strong> {info.get('filename', 'N/A')}</p>
                <p><strong>File Size:</strong> {info.get('file_size', 'N/A')} bytes</p>
                <p><strong>MIME Type:</strong> {info.get('mime_type', 'N/A')}</p>
                <p><strong>File Extension:</strong> {info.get('file_extension', 'N/A')}</p>
        """
    html += "</div>"

    # Image metadata
    if 'metadata' in results and results['metadata']:
        html += """
            <div class="result-section">
                <h2>Image Metadata</h2>
                <table>
                    <tr>
                        <th>Key</th>
                        <th>Value</th>
                    </tr>
        """
        for key, value in results['metadata'].items():
            if isinstance(value, dict):
                html += f"""
                    <tr>
                        <td>{key}</td>
                        <td>
                """
                for subkey, subvalue in value.items():
                    html += f"<div class='metadata-item'><strong>{subkey}:</strong> {subvalue}</div>"
                html += "</td></tr>"
            else:
                html += f"""
                    <tr>
                        <td>{key}</td>
                        <td>{value}</td>
                    </tr>
                """
        html += """
                </table>
            </div>
        """

    # Threat analysis
    html += """
        <div class="result-section">
            <h2>Security Analysis</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Result</th>
                    <th>Details</th>
                </tr>
    """

    threats = results.get('threats', {})
    
    # Common checks
    checks = [
        ('executable_content', 'Executable Content'),
        ('steganography', 'Steganography'),
        ('metadata_scripts', 'Metadata Scripts'),
        ('comment_scripts', 'Comment Scripts'),
        ('exploitable_svg', 'Exploitable SVG')
    ]
    
    # Enhanced checks
    enhanced_checks = [
        ('svg_javascript', 'SVG JavaScript'),
        ('raw_file_analysis', 'RAW File Analysis'),
        ('color_histogram', 'Color Histogram Analysis'),
        ('ml_detection', 'Machine Learning Detection')
    ]
    
    # Add all checks to the report
    all_checks = checks + enhanced_checks
    
    for check_key, check_name in all_checks:
        if check_key in threats:
            is_threat, details = threats[check_key]
            result_class = 'threat' if is_threat else 'safe'
            result_text = 'DETECTED' if is_threat else 'Not Detected'
            
            html += f"""
                <tr>
                    <td>{check_name}</td>
                    <td class="{result_class}">{result_text}</td>
                    <td>{details if details else 'No details available'}</td>
                </tr>
            """

    html += """
            </table>
        </div>
    """

    # Sanitization recommendations
    if 'sanitization' in results:
        html += """
            <div class="result-section">
                <h2>Sanitization Recommendations</h2>
        """
        
        recommendations = results['sanitization']
        if recommendations:
            html += "<ul>"
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            html += "</ul>"
        else:
            html += "<p>No sanitization needed.</p>"
            
        html += "</div>"

    # Close HTML
    html += """
        </div>
    </body>
    </html>
    """
    
    return html


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Start IPI web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Start the web server
    print(f"\n🔍 ImagePayloadInjection Web Interface")
    print(f"Running on http://{args.host}:{args.port}")
    print(f"Press Ctrl+C to stop the server\n")
    
    app.run(host=args.host, port=args.port, debug=args.debug)