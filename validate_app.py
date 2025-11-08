#!/usr/bin/env python3
"""
Validation script for ImageGuard application
Checks code syntax and structure without running the server
"""

import ast
import os
import sys
from pathlib import Path

def validate_python_file(filepath):
    """Validate Python file syntax"""
    try:
        with open(filepath, 'r') as f:
            code = f.read()
        ast.parse(code)
        return True, "OK"
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except Exception as e:
        return False, f"Error: {e}"

def check_file_exists(filepath):
    """Check if file exists"""
    return Path(filepath).exists()

def main():
    print("🔍 ImageGuard Application Validation\n")
    print("=" * 50)

    errors = []
    warnings = []

    # Check Python files
    python_files = [
        'ipi/__init__.py',
        'ipi/web_interface.py',
        'ipi/analyzer.py',
        'ipi/sanitizer.py',
        'ipi/utils.py',
        'wsgi.py',
        'generate_icons.py'
    ]

    print("\n📝 Checking Python files...")
    for file in python_files:
        if check_file_exists(file):
            valid, msg = validate_python_file(file)
            if valid:
                print(f"  ✅ {file}: {msg}")
            else:
                print(f"  ❌ {file}: {msg}")
                errors.append(f"{file}: {msg}")
        else:
            print(f"  ⚠️  {file}: Not found")
            warnings.append(f"{file}: Not found")

    # Check static files
    static_files = [
        'ipi/static/app.js',
        'ipi/static/manifest.json',
        'ipi/static/sw.js',
        'ipi/static/icon-192.png',
        'ipi/static/icon-512.png'
    ]

    print("\n📦 Checking static files...")
    for file in static_files:
        if check_file_exists(file):
            print(f"  ✅ {file}: Found")
        else:
            print(f"  ❌ {file}: Not found")
            errors.append(f"{file}: Not found")

    # Check templates
    templates = [
        'ipi/templates/index.html'
    ]

    print("\n📄 Checking templates...")
    for file in templates:
        if check_file_exists(file):
            print(f"  ✅ {file}: Found")
        else:
            print(f"  ❌ {file}: Not found")
            errors.append(f"{file}: Not found")

    # Check deployment files
    deployment_files = [
        'Dockerfile',
        'docker-compose.yml',
        '.env.example',
        'nginx.conf',
        'requirements.txt',
        'DEPLOYMENT.md'
    ]

    print("\n🚀 Checking deployment files...")
    for file in deployment_files:
        if check_file_exists(file):
            print(f"  ✅ {file}: Found")
        else:
            print(f"  ⚠️  {file}: Not found")
            warnings.append(f"{file}: Not found")

    # Summary
    print("\n" + "=" * 50)
    print("\n📊 Validation Summary:")
    print(f"  Errors: {len(errors)}")
    print(f"  Warnings: {len(warnings)}")

    if errors:
        print("\n❌ Errors found:")
        for error in errors:
            print(f"  - {error}")
        return 1
    elif warnings:
        print("\n⚠️  Warnings:")
        for warning in warnings:
            print(f"  - {warning}")
        print("\n✅ Validation passed with warnings")
        return 0
    else:
        print("\n✅ All checks passed!")
        return 0

if __name__ == '__main__':
    sys.exit(main())
