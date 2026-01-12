<div align="center" width="100%">
    <img src="./internal/server/static/logo.png" width="200" alt="" />
</div>

# 🐢 Upturtle

A lightweight, easy-to-use self-hosted monitoring solution written in Go that keeps track of your services and infrastructure with real-time status updates and flexible notification options.

_Vibe coded with Claude._

> **⚠️ Note**: This project is still under active development. Features and APIs may change.

<img src="https://raw.githubusercontent.com/z3nto/upturtle/master/.github/images/screenshot1.png" width="700" alt="Upturtle Status Page" />

## Features

- **ICMP**, **HTTP/S**, **Docker** monitoring
- **Charts**: Charts for monitor history
- **Master/Dependency**: Suppress notifications when a master service is down
- **Status Pages**: Create public status pages with selected monitors
- **Flexible Grouping**: Organize monitors into custom groups
- **Multi-channel Notifications**: Integration with Discord, Slack, Telegram, and more via [Shoutrrr](https://containrrr.dev/shoutrrr/)
- **User Management**: Multi-user support with role-based access control (admin, write, readonly)
- **API Access**: RESTful API with API key authentication

<img src="https://raw.githubusercontent.com/z3nto/upturtle/master/.github/images/screenshot2.png" width="700" alt="Upturtle Charts" />

## Quick Start

### Using Docker Compose

1. Create a `docker-compose.yml` file:

```yaml
services:
  upturtle:
    image: ghcr.io/z3nto/upturtle:master
    container_name: upturtle
    ports:
      - "8080:8080"
    volumes:
      - /opt/data/upturtle:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro # only if you want to monitor docker containers
    restart: unless-stopped
```

2. Start the service:

```bash
docker-compose up -d
```

3. Access the web interface at `http://localhost:8080`

4. Complete the installation wizard to set up your admin credentials

### Using Docker

```bash
docker run -d \
  --name upturtle \
  -p 8080:8080 \
  -v /opt/data/upturtle:/conf \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \  # only if you want to monitor docker containers 
  ghcr.io/z3nto/upturtle:master
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
| `UPTURTLE_CONFIG_PATH` | `/data/conf/config.json` | Path to configuration file |

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

## License

See [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Acknowledgments

Upturtle is built with the following open source projects:

### Backend
- [Shoutrrr](https://github.com/containrrr/shoutrrr) - Notification delivery system (MIT)
- [Docker SDK](https://github.com/docker/docker) - Docker container monitoring (Apache 2.0)
- [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite database driver (MIT)
- [Logrus](https://github.com/sirupsen/logrus) - Structured logging (MIT)
- [Go Crypto](https://golang.org/x/crypto) - Password hashing with bcrypt (BSD-3-Clause)
- [Go Time](https://golang.org/x/time) - Rate limiting (BSD-3-Clause)

### Frontend
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework (MIT)
- [Chart.js](https://www.chartjs.org/) - JavaScript charting library (MIT)
- [Inter Font](https://fonts.google.com/specimen/Inter) - Typography (OFL)

Special thanks to the Go community for excellent tooling and libraries.
