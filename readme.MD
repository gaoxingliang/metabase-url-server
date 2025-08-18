# Metabase URL Server

A Bottle-based backend server that generates Metabase embedding URLs with JWT tokens.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set required environment variables:
```bash
export METABASE_SITE_URL="http://your-metabase-server:port"
export METABASE_SECRET_KEY="your-metabase-secret-key"
```

3. Run the server:
```bash
python app.py
```

The server will start on `http://localhost:7070`

**Note**: The server logs all requests and responses to both console and log files for debugging and monitoring purposes.

## Logging Features

The server includes comprehensive logging with automatic rotation:

- **Console Logging**: Real-time logs to stdout
- **Size-based Rotation**: Logs rotate when they reach 10MB (keeps 5 backup files)
- **Daily Rotation**: Logs rotate daily at midnight (keeps 30 days of logs)
- **Log Location**: All logs are stored in the `logs/` directory

## API Endpoints

### POST /api/metabase/urls

Generates a Metabase embedding URL with JWT token.

**Request Body:**
```json
{
  "resource": "dashboard",
  "id": "2"
}
```

**Response:**
```json
{
  "url": "http://metabase-server/embed/dashboard/jwt-token#bordered=true&titled=true",
  "expires_in_minutes": 30
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "metabase-url-server"
}
```

## Example Usage

```bash
curl -X POST http://localhost:7070/api/metabase/urls \
  -H "Content-Type: application/json" \
  -d '{"resource": "dashboard", "id": "2"}'
```

## Environment Variables

- `METABASE_SITE_URL`: Your Metabase server URL (**required**)
- `METABASE_SECRET_KEY`: Your Metabase secret key for JWT signing (**required**)
- `TOKEN_EXPIRATION_MINUTES`: Token expiration time in minutes (default: 30)

## Docker Deployment

### Using Docker Compose (Recommended)

1. Create a `.env` file with your configuration:
```bash
METABASE_SITE_URL=http://your-metabase-server:port
METABASE_SECRET_KEY=your-metabase-secret-key
TOKEN_EXPIRATION_MINUTES=30
```

2. Build and run with Docker Compose:
```bash
docker-compose up -d
```

### Using Docker directly

1. Build the image:
```bash
docker build -t edwardg/metabase-url-server .
```

2. Run the container:
```bash
docker run -d \
  --name metabase-url-server \
  -p 7070:7070 \
  -e METABASE_SITE_URL=http://your-metabase-server:port \
  -e METABASE_SECRET_KEY=your-metabase-secret-key \
  -e TOKEN_EXPIRATION_MINUTES=30 \
  -v $(pwd)/logs:/app/logs \
  edwardg/metabase-url-server
```

### Accessing the Container

To access the container with all tools:
```bash
# Get container ID
docker ps

# Access container shell
docker exec -it <container_id> /bin/bash

# Example: Check network connections
docker exec -it <container_id> netstat -tulpn

# Example: Monitor system resources
docker exec -it <container_id> top
```
