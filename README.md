# Upturtle

A lightweight, self-hosted uptime monitoring solution written in Go. Monitor your services with HTTP, ICMP (ping), and Docker container health checks, receive notifications via multiple channels, and view status through a web interface.

## Features

- **ICMP**, **HTTP/S**, **Docker** monitoring
- **Master/Dependency Monitoring**: Suppress notifications when a master service is down
- **Status Pages**: Create public status pages with selected monitors
- **Flexible Grouping**: Organize monitors into custom groups
- **Multi-channel Notifications**: Integration with Discord, Slack, Telegram, and more via [Shoutrrr](https://containrrr.dev/shoutrrr/)
- **User Management**: Multi-user support with role-based access control (admin, write, readonly)
- **API Access**: RESTful API with API key authentication


## Quick Start

### Using Docker Compose

1. Create a `docker-compose.yml` file:

```yaml
services:
  upturtle:
    image: ghcr.io/z3nto/upturtle:main
    container_name: upturtle
    ports:
      - "8080:8080"
    user: 1001:10001 # only if you use bind mounts
    environment:
      LISTEN_ADDR: ":8080"
      UPTURTLE_CONFIG_PATH: "/conf/config.json"
    volumes:
      - upturtle_conf:/conf
      - upturtle_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro # only if you want to monitor docker containers
    restart: unless-stopped

volumes:
  upturtle_conf:
  upturtle_data:
```

2. Start the service:

```bash
docker-compose up -d
```

3. Access the web interface at `http://localhost:8080`

4. Complete the installation wizard to set up your admin credentials

> **Note on Bind Mounts**: If you use bind mounts instead of named volumes (e.g., `-v /path/on/host:/conf`), you must create the directories beforehand and set the correct permissions. The application runs as user `1001`, so ensure this user has read/write access:
> ```bash
> mkdir -p /path/to/conf /path/to/data
> chown -R 1001:1001 /path/to/conf /path/to/data
> ```

### Using Docker

```bash
docker run -d \
  --name upturtle \
  -p 8080:8080 \
  -v upturtle_conf:/conf \
  -v upturtle_data:/data \
  -e LISTEN_ADDR=":8080" \
  -e UPTURTLE_CONFIG_PATH="/conf/config.json" \
  ghcr.io/z3nto/upturtle:main
```

### Building from Source

Requirements:
- Go 1.24.3 or later
- GCC (for SQLite support)

```bash
# Clone the repository
git clone https://github.com/Z3nto/upturtle.git
cd upturtle

# Build the binary
CGO_ENABLED=1 go build -o upturtle ./cmd/upturtle

# Run the application
./upturtle
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | HTTP server listen address |
| `UPTURTLE_CONFIG_PATH` | `/conf/config.json` | Path to configuration file |
### Configuration File

The configuration file (`config.json`) stores different data depending on the mode:

#### In-Memory Mode (without database)
- Admin credentials (bcrypt hashed password)
- Monitor definitions
- Groups and their ordering
- Notification targets
- Status page definitions
- Debug flags

#### SQLite Mode (with database configured)
- Database configuration

When database is enabled, the following are loaded from the database instead of the config file:
- Monitor definitions
- Groups and their ordering
- Notification targets
- Status page definitions
- User accounts

Example configuration:

```json
{
  "admin_user": "admin",
  "admin_password_hash": "$2a$10$...",
  "database": {
    "type": "sqlite",
    "path": "/data/upturtle.db"
  },
  "groups": [
    {
      "id": 1,
      "name": "Web Services",
      "type": "default",
      "order": 1
    }
  ],
  "notifications": [
    {
      "id": 1,
      "name": "Discord Alerts",
      "url": "discord://token@id"
    }
  ],
  "monitors": [
    {
      "id": "1",
      "name": "Example Website",
      "type": "http",
      "target": "https://example.com",
      "interval_seconds": 60,
      "timeout_seconds": 10,
      "notification_id": 1,
      "enabled": true,
      "group_id": 1,
      "fail_threshold": 3,
      "cert_validation": "full"
    }
  ],
  "status_pages": [
    {
      "id": 1,
      "name": "Public Status",
      "slug": "status",
      "active": true,
      "monitors": [
        {
          "monitor_id": "1",
          "group_id": 1,
          "order": 1
        }
      ]
    }
  ]
}
```

## Monitor Types

### HTTP/HTTPS Monitor

```json
{
  "type": "http",
  "target": "https://example.com",
  "timeout_seconds": 10,
  "cert_validation": "full"
}
```

Certificate validation modes:
- `full`: Complete certificate validation (default)
- `expiry`: Only check certificate expiration
- `ignore`: Skip all certificate validation

### ICMP Monitor

```json
{
  "type": "icmp",
  "target": "8.8.8.8",
  "timeout_seconds": 5
}
```

### Docker Monitor

```json
{
  "type": "docker",
  "target": "container_name_or_id",
  "timeout_seconds": 5
}
```

Note: Docker monitoring requires access to the Docker socket. Mount `/var/run/docker.sock` when running in Docker.

## Notifications

Upturtle uses [Shoutrrr](https://containrrr.dev/shoutrrr/) for notifications, supporting:

- Discord
- Slack
- Telegram
- Email (SMTP)
- Gotify
- Pushover
- And many more...

### Example Notification URLs

**Discord:**
```
discord://token@id
```

**Slack:**
```
slack://token@channel
```

**Telegram:**
```
telegram://token@telegram?chats=@chat_id
```

See the [Shoutrrr documentation](https://containrrr.dev/shoutrrr/v0.8/services/overview/) for all supported services.

## User Management

When database is configured, Upturtle supports multi-user access with three roles:

- **Admin**: Full access including user management
- **Write**: Can manage monitors, notifications, and status pages
- **Readonly**: Can only view the main status page

Users can be managed through the admin interface at `/admin/users`.

## API Access

### Authentication

API endpoints require authentication via:
1. Session cookie (for web interface)
2. API key in `X-API-Key` header

### Creating API Keys

1. Log in to the admin interface
2. Navigate to Settings → API Keys
3. Create a new API key
4. Use the key in the `X-API-Key` header

### Example API Requests

**List all monitors:**
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/monitors
```

**Get monitor details:**
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/monitors/1
```

**Create a monitor:**
```bash
curl -X POST -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Monitor",
    "type": "http",
    "target": "https://example.com",
    "interval_seconds": 60,
    "timeout_seconds": 10,
    "enabled": true
  }' \
  http://localhost:8080/api/monitors
```



## License

See [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Acknowledgments

- [Shoutrrr](https://containrrr.dev/shoutrrr/) for notification delivery
- [Docker SDK](https://github.com/docker/docker) for container monitoring
- Go community for excellent tooling and libraries
