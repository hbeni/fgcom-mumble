# WebRTC Gateway Port Configuration

## Default Configuration

The WebRTC gateway is configured to run on **port 8081** by default to avoid conflicts with common services.

## Port Options

### Port 8081 (Default - Recommended)
- **Advantages**: No conflicts with common services
- **Use Case**: Most users, especially those with other web services
- **Configuration**: Already set as default

### Port 8080 (Standard Web Port)
- **Advantages**: Standard web port, easy to remember
- **Disadvantages**: May conflict with other web services (torrent clients, etc.)
- **Use Case**: Users who prefer standard web ports

### Port 3000 (Development Port)
- **Advantages**: Common development port
- **Use Case**: Development environments

### Other Ports
- **9000**: Alternative web port
- **5000**: Flask default port range
- **Custom**: Any available port

## How to Change Port

### Method 1: Edit Configuration File
1. Edit `config/gateway.json`:
```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0"
  }
}
```

2. Restart the gateway:
```bash
./start-gateway.sh restart
```

### Method 2: Environment Variable
1. Set environment variable:
```bash
export PORT=8080
```

2. Start the gateway:
```bash
./start-gateway.sh start
```

### Method 3: Command Line Override
```bash
PORT=8080 ./start-gateway.sh start
```

## Port Conflict Resolution

### If Port 8080 is Already in Use
1. **Check what's using the port**:
```bash
sudo netstat -tulpn | grep :8080
# or
sudo lsof -i :8080
```

2. **Choose an alternative port**:
   - 8081 (recommended)
   - 8082
   - 9000
   - 5000

3. **Update configuration** and restart

### Common Port Conflicts
- **Port 8080**: Web torrent clients, Jenkins, other web services
- **Port 3000**: Node.js development servers, React dev servers
- **Port 9000**: Various web services, monitoring tools

## Verification

After changing the port, verify the configuration:

1. **Check if the service is running**:
```bash
./start-gateway.sh status
```

2. **Test the connection**:
```bash
curl http://localhost:YOUR_PORT/health
```

3. **Access the WebRTC client**:
```
http://localhost:YOUR_PORT/webrtc
```

## Firewall Configuration

If you're running behind a firewall, ensure the port is open:

```bash
# UFW (Ubuntu)
sudo ufw allow YOUR_PORT

# iptables
sudo iptables -A INPUT -p tcp --dport YOUR_PORT -j ACCEPT
```

## Production Deployment

For production deployments, consider:

1. **Use a reverse proxy** (nginx, Apache) to handle SSL termination
2. **Configure proper firewall rules**
3. **Use environment variables** for port configuration
4. **Monitor port usage** to avoid conflicts

## Troubleshooting

### Port Already in Use
```bash
# Find process using the port
sudo lsof -i :YOUR_PORT

# Kill the process (if safe to do so)
sudo kill -9 PID
```

### Permission Denied
```bash
# Run with sudo (not recommended for production)
sudo ./start-gateway.sh start

# Or change port to a higher number (>1024)
```

### Connection Refused
1. Check if the service is running
2. Verify firewall settings
3. Check if the port is correctly configured
4. Ensure the host binding is correct (0.0.0.0 for all interfaces)
