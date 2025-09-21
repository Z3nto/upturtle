
<div align="center" width="100%">
    <img src="./static/logo.png" width="128" alt="" />
</div>

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
- **Database Storage**: Optional SQLite/MySQL support for persistent measurement data
- **Automatic Cleanup**: Intelligent data retention with configurable cleanup schedules
- **Health Monitoring**: Built-in database connectivity monitoring and error reporting
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
docker compose up -d
```

3. Open your browser and navigate to `http://localhost:8080`


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

### Database Configuration

Upturtle supports two storage modes:

#### In-Memory Storage (Default)
By default, Upturtle stores measurement data in memory. This is suitable for basic monitoring setups.

#### Database Storage
For persistent storage and larger deployments, you can configure a database backend. Currently supported:

- **SQLite** - Lightweight, file-based database (recommended for most users)
- **MySQL** - Full-featured database server (planned for future release)

You can choose the deployment type at the installation page.


#### Database Features

When database storage is enabled:

- **Persistent Data**: Measurement data survives application restarts
- **Per-Day Tables**: Data is organized in daily tables for efficient cleanup
- **Automatic Cleanup**: Old measurement data is automatically removed (default: 1 day retention)
- **Live Queries**: Data is read directly from the database (no in-memory cache for less oberhead)
- **Health Monitoring**: Database connectivity is monitored and displayed in the web interface
- **Configuration Storage**: Admin credentials and settings are stored in the database

#### Data Retention

- **Default**: 1 day 
- **Cleanup Schedule**: Daily at 00:01 AM
- **Method**: Old daily tables are dropped entirely for efficient cleanup

#### When to Use Database Storage

**Use In-Memory Storage when:**
- Running a small number of monitors (< 20)
- Short-term monitoring needs
- Minimal disk usage is priority
- Simple deployment requirements

**Use Database Storage when:**
- Need persistent historical data
- Running many monitors or high-frequency checks
- Require data analysis or reporting
- Planning for horizontal scaling
- Want to survive application restarts without data loss

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
      UPTURTLE_CONFIG_PATH: "/conf/config.json"
    volumes:
      - upturtle_conf:/conf
      - upturtle_data:/data  # For SQLite database storage
    restart: unless-stopped

volumes:
  upturtle_conf:
  upturtle_data:  # Persistent storage for database
```

## 📊 Monitoring Best Practices

1. **Group Related Services**: Use groups to organize monitors logically
2. **Set Appropriate Intervals**: Balance between responsiveness and resource usage
3. **Configure Failure Thresholds**: Avoid false alarms with reasonable thresholds (default: 3)
4. **Use Master-Slave Dependencies**: Prevent notification storms during network outages
5. **Test Notifications**: Verify your notification channels are working
6. **Monitor the Monitor**: Keep an eye on Upturtle's own resource usage


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
