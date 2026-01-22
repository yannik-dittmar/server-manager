# Server Control

A Go application that automatically starts and stops Docker containers based on network traffic. Designed for game servers (Minecraft, etc.) that should only run when players want to connect, saving resources when idle.

## Features

- **Automatic start**: Starts the container when network traffic is detected on monitored ports
- **Automatic stop**: Stops the container after a configurable period of inactivity
- **IP filtering**: 
  - Whitelist specific subnets (e.g., your local network)
  - Optional GeoIP filtering to only allow connections from specific countries
  - Automatic blacklisting of denied IPs to reduce GeoIP API calls
- **Efficient packet capture**: Uses libpcap (via gopacket) instead of spawning tcpdump
- **Graceful shutdown**: Properly handles SIGINT/SIGTERM signals

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CONTAINER_NAME` | Yes | - | Name of the Docker container to control |
| `TCP_PORTS` | No* | - | Comma-separated list of TCP ports to monitor |
| `UDP_PORTS` | No* | - | Comma-separated list of UDP ports to monitor |
| `INACTIVITY_TIMEOUT` | No | `30` | Minutes of inactivity before stopping the container |
| `NETWORK_INTERFACE` | No | `eth0` | Network interface to capture packets on |
| `ALLOWED_SUBNETS` | No | - | Comma-separated CIDR subnets that are always allowed |
| `GEOIP_ENABLED` | No | `false` | Enable GeoIP-based filtering |
| `ALLOWED_COUNTRIES` | No | `DE` | Comma-separated country codes (only when GEOIP_ENABLED=true) |

*At least one of `TCP_PORTS` or `UDP_PORTS` must be specified.

## How It Works

1. The server-control container captures network packets on the specified ports
2. When a packet arrives from an allowed IP (based on subnets or GeoIP), it:
   - Updates the "last activity" timestamp
   - Starts the target container if it's not running
3. Every 10 seconds, it checks if the inactivity timeout has been exceeded
4. If inactive for too long, it stops the target container

## Network Architecture

The controlled container uses `network_mode: service:server-control`, meaning:
- All network traffic to the game server goes through the server-control container
- Server-control can see and filter all incoming connections
- Ports are exposed on the server-control container, not the game server

```
Internet → server-control:25565 → game server (via shared network)
                    ↓
           packet capture + 
           container control
```

## Building

```bash
# Build the Docker image
docker build -t server-control .

# Or with docker-compose
docker-compose build
```

## Usage

```bash
# Start the stack
docker-compose up -d

# View logs
docker-compose logs -f server-control

# Stop everything
docker-compose down
```

## Requirements

- Docker with API access (via socket mount)
- `NET_RAW` and `NET_ADMIN` capabilities for packet capture
- The controlled container must use `network_mode: service:server-control`

## Improvements over the Python Version

1. **Native packet capture**: Uses gopacket/libpcap instead of spawning tcpdump subprocess
2. **Better concurrency**: Proper Go routines with context cancellation
3. **Thread-safe**: Mutex-protected shared state
4. **Graceful shutdown**: Handles signals properly
5. **Configurable GeoIP**: Can be disabled entirely, and supports multiple countries
6. **Better error handling**: Proper error propagation and logging
7. **Smaller image**: Multi-stage build produces a minimal Alpine-based image
8. **Type safety**: Go's type system catches errors at compile time

## Troubleshooting

### Container doesn't start on connection

1. Check that the server-control container has the `NET_RAW` capability
2. Verify the correct network interface is being monitored
3. Check the logs for "Blocked traffic from" messages (IP filtering)
4. Ensure the controlled container name matches `CONTAINER_NAME`

### GeoIP not working

The free GeoIP service (geolocation-db.com) has rate limits. Consider:
- Disabling GeoIP (`GEOIP_ENABLED=false`)
- Using `ALLOWED_SUBNETS` for your network instead
- IP caching reduces repeated lookups for the same IP

### High CPU usage

If you're seeing high CPU, the BPF filter might not be working correctly. Check:
- The ports are correctly specified
- The network interface exists and is correct
