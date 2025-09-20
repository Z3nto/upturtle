# 🐢 Upturtle

A lightweight, self-hosted monitoring solution written in Go that keeps track of your services and infrastructure with real-time status updates and flexible notification options.

## ✨ Features

- **Multi-Protocol Monitoring**: HTTP/HTTPS and ICMP (ping) monitoring
- **Real-time Dashboard**: Clean web interface with automatic status updates
- **Flexible Notifications**: Integration with 70+ notification services via [Shoutrrr](https://github.com/containrrr/shoutrrr)
- **Grouping & Organization**: Organize monitors into logical groups with custom ordering
- **Master-Slave Dependencies**: Configure monitor dependencies to avoid alert storms
- **Configurable Thresholds**: Set custom failure thresholds before notifications are sent
- **Docker Ready**: Containerized deployment with Docker Compose
- **Secure by Design**: Session-based authentication with bcrypt password hashing
- **Persistent Configuration**: JSON-based configuration with atomic updates
- **Graceful Shutdown**: Proper signal handling for clean shutdowns

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/z3nto/upturtle.git
cd upturtle
```

2. Start the application:
```bash
docker-compose up -d
```

3. Open your browser and navigate to `http://localhost:8080`

4. Complete the initial setup by creating an admin account

### Manual Installation

#### Prerequisites
- Go 1.24.3 or later
- `ping` command available (for ICMP monitoring)

#### Build and Run
```bash
# Clone the repository
git clone https://github.com/z3nto/upturtle.git
cd upturtle

# Build the application
go build -o upturtle ./cmd/upturtle

# Run the application
./upturtle
```

## 📖 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | Address and port to listen on |
| `UPTURTLE_CONFIG_PATH` | `/conf/config.json` | Path to the configuration file |

### Monitor Types

#### HTTP/HTTPS Monitoring
- Monitors web services and APIs
- Supports custom timeouts and intervals
- Validates response codes and measures latency

#### ICMP (Ping) Monitoring  
- Tests network connectivity to hosts
- Measures round-trip time
- Validates against command injection attacks

### Notification Services

Upturtle supports 70+ notification services through Shoutrrr, including:

- **Chat**: Discord, Slack, Microsoft Teams, Telegram, Matrix
- **Email**: SMTP, Gmail, Outlook
- **Push**: Pushover, Pushbullet, Gotify
- **Webhooks**: Generic HTTP webhooks
- **And many more...**

Example notification URLs:
```
discord://token@channel
slack://token:token@channel
telegram://token@chatid
smtp://user:password@host:port/?to=recipient@example.com
```

## 🏗️ Architecture

```
upturtle/
├── cmd/upturtle/          # Application entry point
├── internal/
│   ├── config/           # Configuration management
│   ├── monitor/          # Monitoring logic and types
│   ├── notifier/         # Notification handling
│   └── server/           # Web server and API
│       ├── static/       # Static web assets
│       └── templates/    # HTML templates
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile           # Container build instructions
└── go.mod              # Go module definition
```

## 🔧 API Endpoints

### Public Endpoints
- `GET /` - Main dashboard
- `GET /status` - Status page (JSON)

### Admin Endpoints (Authentication Required)
- `GET /admin` - Admin dashboard
- `POST /admin/monitors` - Create/update monitors
- `DELETE /admin/monitors/{id}` - Delete monitor
- `POST /admin/groups` - Manage monitor groups
- `POST /admin/notifications` - Manage notification targets
- `POST /admin/settings` - Update application settings

## 🔒 Security Considerations

Upturtle implements several security measures:

- **Session-based Authentication**: Secure session management with bcrypt password hashing
- **Input Validation**: Strict validation for ICMP targets to prevent command injection
- **Non-root Container**: Docker container runs as non-privileged user (UID 10001)
- **Atomic Configuration Updates**: Configuration changes are written atomically
- **Timeout Protection**: All network operations have configurable timeouts

### Security Notes
- Ensure you're running the latest version
- Use strong admin passwords
- Consider running behind a reverse proxy with HTTPS
- Regularly review your notification configurations
- Monitor the application logs for suspicious activity

## 🐳 Docker Configuration

The included `docker-compose.yml` provides a complete setup:

```yaml
services:
  upturtle:
    build: .
    container_name: upturtle
    ports:
      - "8080:8080"
    environment:
      LISTEN_ADDR: ":8080"
      STATUS_REFRESH_SECONDS: "30"
      HISTORY_LIMIT: "200"
      UPTURTLE_CONFIG_PATH: "/conf/config.json"
    volumes:
      - upturtle_conf:/conf
    restart: unless-stopped
```

## 📊 Monitoring Best Practices

1. **Group Related Services**: Use groups to organize monitors logically
2. **Set Appropriate Intervals**: Balance between responsiveness and resource usage
3. **Configure Failure Thresholds**: Avoid false alarms with reasonable thresholds (default: 3)
4. **Use Master-Slave Dependencies**: Prevent notification storms during network outages
5. **Test Notifications**: Verify your notification channels are working
6. **Monitor the Monitor**: Keep an eye on Upturtle's own resource usage

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Z3nto/upturtle.git
cd upturtle

# Install dependencies
go mod download

# Run tests
go test ./...

# Run the application in development mode
go run ./cmd/upturtle
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Shoutrrr](https://github.com/containrrr/shoutrrr) for the excellent notification library
- [Logrus](https://github.com/sirupsen/logrus) for structured logging
- The Go community for the amazing ecosystem

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/z3nto/upturtle/issues) page
2. Create a new issue with detailed information about your problem
3. Include logs, configuration (sanitized), and steps to reproduce

---

**Made with ❤️ and Go**
