# ImageGuard Deployment Guide

## Quick Start

### Development Mode

```bash
# Install dependencies
pip install -r requirements.txt

# Run the development server
python ipi/web_interface.py --host 127.0.0.1 --port 5000 --debug
```

Visit `http://localhost:5000` in your browser.

---

## Production Deployment

### Option 1: Docker (Recommended)

#### Prerequisites
- Docker
- Docker Compose

#### Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd image_payload_injection
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   nano .env  # Edit configuration
   ```

3. **Build and run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Access the application**
   - App: `http://localhost:5000`
   - With Nginx: `http://localhost:80`

5. **View logs**
   ```bash
   docker-compose logs -f imageguard
   ```

6. **Stop the application**
   ```bash
   docker-compose down
   ```

#### With Nginx Reverse Proxy

```bash
# Run with nginx profile
docker-compose --profile with-nginx up -d
```

---

### Option 2: Manual Production Deployment

#### Prerequisites
- Python 3.8+
- ImageMagick
- ExifTool
- Nginx (optional)

#### Steps

1. **Install system dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y imagemagick exiftool libmagic1

   # macOS
   brew install imagemagick exiftool
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt gunicorn
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   nano .env
   ```

4. **Run with Gunicorn**
   ```bash
   gunicorn --bind 0.0.0.0:5000 \
            --workers 4 \
            --timeout 120 \
            --access-logfile - \
            --error-logfile - \
            ipi.web_interface:app
   ```

5. **Run as systemd service** (Optional)

   Create `/etc/systemd/system/imageguard.service`:
   ```ini
   [Unit]
   Description=ImageGuard Web Application
   After=network.target

   [Service]
   Type=notify
   User=www-data
   WorkingDirectory=/opt/imageguard
   Environment="PATH=/opt/imageguard/venv/bin"
   ExecStart=/opt/imageguard/venv/bin/gunicorn \
             --bind 0.0.0.0:5000 \
             --workers 4 \
             --timeout 120 \
             ipi.web_interface:app

   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start:
   ```bash
   sudo systemctl enable imageguard
   sudo systemctl start imageguard
   ```

---

### Option 3: Platform as a Service (PaaS)

#### Heroku

1. **Create a Procfile**
   ```
   web: gunicorn ipi.web_interface:app
   ```

2. **Deploy**
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

#### Railway / Render / Fly.io

These platforms can deploy directly from the Dockerfile.

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | Random |
| `FLASK_ENV` | Flask environment (development/production) | `production` |
| `HOST` | Host to bind to | `0.0.0.0` |
| `PORT` | Port to bind to | `5000` |
| `MAX_CONTENT_LENGTH` | Max upload size in bytes | `16777216` (16MB) |
| `UPLOAD_FOLDER` | Temporary upload folder | `/tmp/ipi_uploads` |
| `RESULT_FOLDER` | Results folder | `/tmp/ipi_results` |

### Security Considerations

1. **Change the SECRET_KEY**: Generate a secure random key
   ```bash
   python -c "import os; print(os.urandom(24).hex())"
   ```

2. **Use HTTPS**: Configure SSL/TLS certificates
   - Use Let's Encrypt for free certificates
   - Configure nginx with SSL

3. **Firewall**: Restrict access if needed
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

4. **Rate Limiting**: Consider adding rate limiting for production
   - Use nginx limit_req
   - Or Flask-Limiter extension

---

## Progressive Web App (PWA)

The application is PWA-ready! Users can install it on their devices:

1. Visit the application in a modern browser
2. Click the "Install" button in the address bar
3. The app will be installed like a native application

### PWA Features
- Offline capability (cached resources)
- App-like experience
- Install on desktop and mobile
- Custom app icon

---

## Monitoring & Logs

### Docker Logs
```bash
docker-compose logs -f imageguard
```

### Application Logs
Logs are output to stdout/stderr. In production, configure log aggregation:
- Use Docker logging drivers
- Or send to Elasticsearch/CloudWatch/etc.

### Health Checks
The Docker setup includes health checks:
```bash
curl http://localhost:5000/
```

---

## Scaling

### Horizontal Scaling
Run multiple workers with Gunicorn:
```bash
gunicorn --workers 8 ipi.web_interface:app
```

### Load Balancing
Use Nginx or HAProxy to distribute traffic across multiple instances.

### Resource Limits
Adjust in `docker-compose.yml`:
```yaml
services:
  imageguard:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

---

## Troubleshooting

### Port already in use
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill the process
kill -9 <PID>
```

### Permission errors
```bash
# Ensure upload/result directories are writable
chmod 777 /tmp/ipi_uploads /tmp/ipi_results
```

### ImageMagick not found
```bash
# Install ImageMagick
sudo apt-get install imagemagick

# Or on macOS
brew install imagemagick
```

---

## Backup & Maintenance

### Backup uploaded files (if needed)
```bash
tar -czf backup-$(date +%Y%m%d).tar.gz uploads/ results/
```

### Update the application
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

---

## Support

For issues and questions:
- GitHub Issues: <repository-url>/issues
- Documentation: See README.md

---

## License

This project is for educational and security research purposes only.
