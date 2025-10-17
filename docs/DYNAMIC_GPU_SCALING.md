# Dynamic GPU Scaling Documentation

**Intelligent GPU resource management for high user loads (up to 200 concurrent users)**

## Overview

FGCom-mumble's Dynamic GPU Scaling system provides intelligent GPU resource management that automatically adjusts GPU allocation based on connected user count. This system ensures optimal performance while minimizing resource waste.

## Configuration Examples

### Basic Dynamic GPU Scaling Setup

```bash
# Dynamic GPU scaling (recommended)
enable_dynamic_gpu_scaling = true
max_local_gpus = 4
max_network_gpus = 8
scaling_thresholds = [20, 50, 100, 150, 200]

# Network GPU pool with health monitoring
network_gpu_servers = [
    "192.168.1.10:gpu1",
    "192.168.1.11:gpu2", 
    "192.168.1.12:gpu3",
    "192.168.1.13:gpu4"
]

# Network limits for intelligent scaling
max_network_bandwidth_mbps = 1000
max_network_latency_ms = 100
network_gpu_health_check_interval = 30

# Legacy static configuration (deprecated)
# shared_gpu = true
# gpu_count = 4
# gpu_distribution = "workload"
```

## Automatic Scaling Strategy

The system automatically adjusts GPU allocation based on connected user count:

- **1-20 users**: 1 GPU (local only)
- **21-50 users**: 2 GPUs (local only)  
- **51-100 users**: 3 GPUs (2 local + 1 network)
- **101-150 users**: 5 GPUs (3 local + 2 network)
- **151-200 users**: 8 GPUs (4 local + 4 network)

## Network Limits Consideration

- **Bandwidth monitoring**: 1 Gbps network limit
- **Latency monitoring**: 100ms threshold
- **Network GPU health checking**: Automatic failover
- **Load balancing**: Intelligent distribution across network GPUs
- **Cooldown periods**: Prevents scaling thrashing

## Configuration Parameters

### Core Settings

| Parameter | Description | Default | Example |
|----------|-------------|---------|---------|
| `enable_dynamic_gpu_scaling` | Enable/disable dynamic scaling | `false` | `true` |
| `max_local_gpus` | Maximum local GPUs to use | `4` | `4` |
| `max_network_gpus` | Maximum network GPUs to use | `8` | `8` |
| `scaling_thresholds` | User count thresholds for scaling | `[20, 50, 100, 150, 200]` | `[20, 50, 100, 150, 200]` |

### Network Configuration

| Parameter | Description | Default | Example |
|----------|-------------|---------|---------|
| `network_gpu_servers` | List of network GPU servers | `[]` | `["192.168.1.10:gpu1", "192.168.1.11:gpu2"]` |
| `max_network_bandwidth_mbps` | Maximum network bandwidth | `1000` | `1000` |
| `max_network_latency_ms` | Maximum acceptable latency | `100` | `100` |
| `network_gpu_health_check_interval` | Health check interval (seconds) | `30` | `30` |

## Performance Benefits

- **Intelligent resource allocation** based on actual demand
- **Network-aware scaling** that respects bandwidth and latency limits
- **Automatic failover** for network GPU failures
- **Optimal performance** for any user count from 1 to 200+
- **Reduced resource waste** compared to static GPU allocation

## Advanced Configuration

### Custom Scaling Thresholds

```bash
# Custom scaling for different deployment sizes
scaling_thresholds = [10, 25, 50, 75, 100]  # Smaller deployment
scaling_thresholds = [50, 100, 200, 300, 400]  # Larger deployment
```

### Network GPU Pool Management

```bash
# Multiple data centers
network_gpu_servers = [
    "datacenter1.example.com:gpu1",
    "datacenter1.example.com:gpu2",
    "datacenter2.example.com:gpu1",
    "datacenter2.example.com:gpu2"
]

# Load balancing across regions
network_gpu_servers = [
    "us-east.example.com:gpu1",
    "us-west.example.com:gpu1",
    "eu-central.example.com:gpu1"
]
```

### Health Monitoring

```bash
# Aggressive health checking for critical deployments
network_gpu_health_check_interval = 10

# Conservative health checking for stable networks
network_gpu_health_check_interval = 60
```

## Troubleshooting

### Common Issues

1. **Scaling Thrashing**: If the system constantly scales up and down, increase cooldown periods
2. **Network Timeouts**: Check network latency and bandwidth limits
3. **GPU Failures**: Monitor health check intervals and server availability

### Monitoring Commands

```bash
# Check current GPU allocation
./scripts/gpu_status.sh

# Monitor scaling events
tail -f /var/log/fgcom-mumble/gpu_scaling.log

# Test network GPU connectivity
./scripts/test_network_gpus.sh
```

## Migration from Static Configuration

If you're currently using static GPU configuration, here's how to migrate:

### Before (Static)
```bash
shared_gpu = true
gpu_count = 4
gpu_distribution = "workload"
```

### After (Dynamic)
```bash
enable_dynamic_gpu_scaling = true
max_local_gpus = 4
max_network_gpus = 0  # Start with local only
scaling_thresholds = [20, 50, 100, 150, 200]
```

## Best Practices

1. **Start Conservative**: Begin with local GPUs only, then add network GPUs
2. **Monitor Performance**: Use the monitoring tools to track scaling effectiveness
3. **Test Failover**: Regularly test network GPU failover scenarios
4. **Tune Thresholds**: Adjust scaling thresholds based on your specific usage patterns
5. **Network Planning**: Ensure adequate bandwidth and low latency for network GPUs

## Related Documentation

- [GPU Acceleration Guide](GPU_ACCELERATION_GUIDE.md)
- [Performance Optimization](PERFORMANCE_OPTIMIZATION.md)
- [Network Configuration](NETWORK_CONFIGURATION.md)
- [Monitoring and Logging](MONITORING_AND_LOGGING.md)





