"""
WSGI entry point for ImageGuard
Use this for production deployment with gunicorn or uwsgi
"""

from ipi.web_interface import app

if __name__ == "__main__":
    app.run()
