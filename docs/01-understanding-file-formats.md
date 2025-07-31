# Understanding Image File Formats

## Introduction

Image files are more complex than they appear. Understanding their structure is essential for recognizing how they can be manipulated to carry malicious payloads. This document examines the most common image formats and their vulnerabilities.

## Common Image File Formats

### JPEG/JPG

The JPEG (Joint Photographic Experts Group) format is one of the most widely used image formats on the web.

#### Structure Overview
- **Headers**: SOI (Start of Image), APP0 (JFIF identifier)
- **Segments**: Each segment begins with a marker (0xFF followed by a marker code)
- **Entropy-Coded Data**: The actual image data
- **EOI (End of Image)**: Marker that indicates the end of the JPEG file

#### Injection Points
1. **After EOI Marker**: Data added after the EOI marker will be ignored by image renderers
2. **EXIF Metadata**: Can contain executable scripts or malicious data
3. **Comment Sections**: Can hide string-based payloads

### PNG

PNG (Portable Network Graphics) files have a more rigid structure but still offer opportunities for payload injection.

#### Structure Overview
- **Signature**: 8-byte PNG signature (89 50 4E 47 0D 0A 1A 0A)
- **Chunks**: Series of chunks that contain different types of data
  - Critical chunks (IHDR, PLTE, IDAT, IEND)
  - Ancillary chunks (tRNS, gAMA, etc.)

#### Injection Points
1. **Custom Chunks**: Creating non-standard chunks to store payloads
2. **tEXt Chunks**: Text metadata that can contain scripts
3. **After IEND Chunk**: Data placed after the IEND chunk will be ignored by renderers

### GIF

GIF (Graphics Interchange Format) files support animations and have unique vulnerabilities.

#### Structure Overview
- **Header**: "GIF87a" or "GIF89a" signature
- **Logical Screen Descriptor**: Defines global properties
- **Global Color Table**: Palette of colors
- **Blocks**: Data blocks, control blocks, and special purpose blocks
- **Trailer**: A single byte (0x3B) marking the end of the GIF file

#### Injection Points
1. **Application Extension Blocks**: Can contain arbitrary data
2. **Comment Extension Blocks**: Can store hidden data
3. **After Trailer**: Data after the trailer byte is ignored by renderers

### SVG

SVG (Scalable Vector Graphics) is an XML-based vector image format that can contain script elements.

#### Structure Overview
- **XML Declaration**: `<?xml version="1.0" encoding="UTF-8"?>`
- **SVG Element**: Root element containing graphics definitions
- **Various Elements**: Paths, shapes, text, etc.

#### Injection Points
1. **Script Tags**: Can directly execute JavaScript
2. **Event Handlers**: onClick, onload attributes that execute code
3. **href Attributes**: Can trigger JavaScript via `javascript:` protocol
4. **External References**: Can load external resources with malicious code

## Steganography Techniques

Beyond simple payload injection, steganography techniques can be used to hide data:

1. **Least Significant Bit (LSB) Encoding**: Replacing the least significant bits of pixel values
2. **DCT Coefficient Manipulation**: In JPEG files, modifying frequency coefficients
3. **Palette Manipulation**: In indexed color images, manipulating the color table
4. **Spatial Domain Techniques**: Changing pixel values in patterns that are visually imperceptible

## Tools for Inspection

To examine image files for potential payloads:

1. **Hex Editors**: View the raw byte content of files
   - HxD, hexdump, xxd
2. **Metadata Analyzers**: Examine file metadata
   - ExifTool, identify (ImageMagick)
3. **Structure Analyzers**: Verify file integrity and structure
   - pngcheck, jpeginfo
4. **Steganography Detection Tools**: Look for hidden content
   - StegDetect, Stegspy

## Conclusion

Understanding image file structures is the first step in identifying and mitigating image payload injection vulnerabilities. The next document will explore how these vulnerabilities intersect with AI systems and prompt injection techniques.

---

© 2025 Modern Dime Security Research