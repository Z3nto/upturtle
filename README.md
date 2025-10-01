
<div align="center" width="100%">
    <img src="./internal/server/static/logo.png" width="200" alt="" />
</div>

# 🐢 Upturtle

A lightweight, easy-to-use self-hosted monitoring solution written in Go that keeps track of your services and infrastructure with real-time status updates and flexible notification options.

## ✨ Features

### Core Monitoring
- **Multi-Protocol Monitoring**: HTTP/HTTPS and ICMP (ping) monitoring
- **Real-time Dashboard**: Clean web interface with automatic status updates
- **Flexible Certificate Validation**: Choose between full validation or expiry-only checks for HTTPS monitors
- **Master-Slave Dependencies**: Configure monitor dependencies to avoid alert storms
- **Configurable Thresholds**: Set custom failure thresholds before notifications are sent
- **Drag & Drop Reordering**: Easily reorder monitors within groups via drag-and-drop

### Public Status Pages
- **Custom Status Pages**: Create multiple public status pages for different audiences
- **Slug-based URLs**: Clean, shareable URLs like `/status/your-service`
- **Monitor Selection**: Choose which monitors to display on each status page
- **Custom Grouping**: Organize monitors into custom groups per status page
- **Active/Inactive Control**: Enable or disable status pages without deleting them
- **Auto-refresh**: Public pages refresh every 30 seconds automatically
- **No Authentication Required**: Public pages are accessible without login

### Notifications
- **70+ Notification Services**: Integration via [Shoutrrr](https://github.com/containrrr/shoutrrr)
- **Visual URL Builder**: Easy-to-use form-based notification configuration
- **Service Templates**: Pre-configured templates for popular services (Discord, Slack, Telegram, etc.)

### Data & Storage
- **Normalized Database Schema**: Efficient SQLite storage with proper relational tables
- **Flexible Installation**: Choose between In-Memory Storage and Database Storage
- **Automatic Cleanup**: Intelligent data retention with configurable cleanup schedules


### Administration
- **Grouping & Organization**: Organize monitors into logical groups with custom ordering
- **Configurable Debug Logging**: Toggle authentication debug logs via settings page
- **Secure by Design**: Session-based authentication with bcrypt password hashing
- **Docker Ready**: Containerized deployment with Docker Compose
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
- **Live Queries**: Data is read directly from the database (no in-memory cache for less overhead)
- **Health Monitoring**: Database connectivity is monitored and displayed in the web interface
- **Configuration Storage**: Admin credentials and settings are stored in the database

#### Database Schema

Upturtle uses a normalized relational database schema for efficient storage:

**Tables:**
- `monitors` - Monitor configurations with foreign keys to groups and notifications
- `groups` - Group definitions with support for default and status page groups
- `notifications` - Notification channel configurations
- `settings` - Key-value store for application settings
- `status_pages` - Public status page configurations
- `status_page_monitors` - Many-to-many relationship between status pages and monitors
- `history_YYYYMMDD` - Daily tables for time-series data (auto-created and cleaned up)

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
- **Certificate Validation Modes**:
  - **Full Validation** (default): Validates certificate chain, hostname, expiry, and trust
  - **Expiry Only**: Skips certificate validation but warns if certificate expires within 30 days

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

#### Easy Configuration with Visual Builder

Instead of manually crafting Shoutrrr URLs, Upturtle provides a user-friendly form-based interface:

1. Select your notification service from the dropdown
2. Fill in the required fields (tokens, channels, recipients, etc.)
3. The URL is automatically generated in the correct format
4. Test your notification before saving

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
│   ├── database/         # Database interface and SQLite implementation
│   ├── monitor/          # Monitoring logic and types
│   ├── notifier/         # Notification handling
│   └── server/           # Web server and API
│       ├── static/       # Static web assets
│       └── templates/    # HTML templates
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile           # Container build instructions
└── go.mod              # Go module definition
```

## 🔌 API Endpoints

Upturtle provides a RESTful API for programmatic access:

### Monitors
- `GET /api/monitors` - List all monitors
- `GET /api/monitors/{id}` - Get monitor details
- `POST /api/monitors` - Create new monitor
- `PUT /api/monitors/{id}` - Update monitor
- `DELETE /api/monitors/{id}` - Delete monitor
- `POST /api/monitors/reorder` - Reorder monitors via drag-and-drop

### Groups
- `GET /api/groups` - List all groups
- `POST /api/groups` - Create new group
- `PUT /api/groups/{id}` - Update group
- `DELETE /api/groups/{id}` - Delete group

### Notifications
- `GET /api/notifications` - List all notification channels
- `GET /api/notifications/{id}` - Get notification details
- `POST /api/notifications` - Create notification channel
- `PUT /api/notifications/{id}` - Update notification channel
- `DELETE /api/notifications/{id}` - Delete notification channel

### Status Pages
- `GET /api/statuspages` - List all status pages
- `GET /api/statuspages/{id}` - Get status page details
- `POST /api/statuspages` - Create status page
- `PUT /api/statuspages/{id}` - Update status page
- `DELETE /api/statuspages/{id}` - Delete status page

### Settings
- `GET /api/settings` - Get application settings
- `POST /api/settings` - Update settings

All API endpoints require authentication via session cookies and include CSRF protection.


## ⚙️ Administration Features

### Settings Management

Access settings via **Admin → Settings**:

- **Data Retention**: Configure how long measurement data is kept (default: 1 day)
- **Authentication Debug**: Toggle detailed authentication logging for troubleshooting login issues
- **Database Health**: View database connectivity status and error information

### Monitor Management

- **Drag & Drop Reordering**: Click and drag monitors to reorder them within groups

### Group Management

- **Default Groups**: Standard groups for organizing monitors in the admin interface
- **Status Page Groups**: Separate groups specific to each public status page
- **Custom Ordering**: Control the display order of groups and monitors

## 🔒 Security Considerations

Upturtle implements several security measures:

- **Session-based Authentication**: Secure session management with bcrypt password hashing
- **CSRF Protection**: Cross-site request forgery tokens on all state-changing operations
- **Input Validation**: Strict validation for ICMP targets to prevent command injection
- **Non-root Container**: Docker container runs as non-privileged user (UID 10001)
- **Atomic Configuration Updates**: Configuration changes are written atomically
- **Timeout Protection**: All network operations have configurable timeouts
- **Configurable Debug Logging**: Authentication debug logs can be disabled in production

### Security Notes
- Ensure you're running the latest version
- Use strong admin passwords
- Consider running behind a reverse proxy with HTTPS
- Regularly review your notification configurations
- Monitor the application logs for suspicious activity
- Disable authentication debug logging in production environments

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
7. **Use Public Status Pages**: Create dedicated status pages for customers or teams
8. **Certificate Validation**: Use "expiry_only" mode for self-signed certificates while still tracking expiry dates

## 🌐 Public Status Pages

Upturtle allows you to create multiple public status pages that can be shared with customers, teams, or stakeholders without requiring authentication.

c


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
