# Feature Toggle API Control Documentation

## Overview

The FGCom-mumble system includes comprehensive feature toggles that allow administrators to control API endpoint access and data source behavior. This system enables fine-grained control over which API endpoints are available and whether external data sources are used.

## Feature Toggle Categories

### API Endpoint Control

The system provides separate toggles for read and write operations on all major API endpoints:

#### Solar Data API Controls
- `enable_solar_data_get_current` - Enable/disable GET /api/v1/solar-data/current
- `enable_solar_data_get_history` - Enable/disable GET /api/v1/solar-data/history  
- `enable_solar_data_get_forecast` - Enable/disable GET /api/v1/solar-data/forecast
- `enable_solar_data_post_submit` - Enable/disable POST /api/v1/solar-data/submit
- `enable_solar_data_post_batch_submit` - Enable/disable POST /api/v1/solar-data/batch-submit
- `enable_solar_data_put_update` - Enable/disable PUT /api/v1/solar-data/update

#### Weather Data API Controls
- `enable_weather_data_get_current` - Enable/disable GET /api/v1/weather-data/current
- `enable_weather_data_get_history` - Enable/disable GET /api/v1/weather-data/history
- `enable_weather_data_get_forecast` - Enable/disable GET /api/v1/weather-data/forecast
- `enable_weather_data_post_submit` - Enable/disable POST /api/v1/weather-data/submit
- `enable_weather_data_post_batch_submit` - Enable/disable POST /api/v1/weather-data/batch-submit
- `enable_weather_data_put_update` - Enable/disable PUT /api/v1/weather-data/update

### External Data Source Controls

#### Solar Data Sources
- `enable_external_solar_data_sources` - Master toggle for all external solar data sources
- `enable_noaa_solar_data` - Enable/disable NOAA solar data fetching
- `enable_solar_data_external_fetch` - Enable/disable external solar data fetching
- `enable_solar_data_game_submission` - Enable/disable game solar data submission

#### Weather Data Sources
- `enable_external_weather_data_sources` - Master toggle for all external weather data sources
- `enable_noaa_weather_data` - Enable/disable NOAA weather data fetching
- `enable_openweather_api` - Enable/disable OpenWeather API
- `enable_weather_gov_api` - Enable/disable Weather.gov API
- `enable_weather_data_external_fetch` - Enable/disable external weather data fetching
- `enable_weather_data_game_submission` - Enable/disable game weather data submission

## Configuration Examples

### Read-Only API Mode
To make all APIs read-only (disable all write operations):

```ini
[api_endpoint_features]
# Solar Data API Controls - Read Only
enable_solar_data_get_current = true
enable_solar_data_get_history = true
enable_solar_data_get_forecast = true
enable_solar_data_post_submit = false
enable_solar_data_post_batch_submit = false
enable_solar_data_put_update = false

# Weather Data API Controls - Read Only
enable_weather_data_get_current = true
enable_weather_data_get_history = true
enable_weather_data_get_forecast = true
enable_weather_data_post_submit = false
enable_weather_data_post_batch_submit = false
enable_weather_data_put_update = false
```

### Game Submission Mode
To enable game data submission and disable external sources:

```ini
[data_source_features]
# Enable game submission
enable_solar_data_game_submission = true
enable_weather_data_game_submission = true

# Disable external fetching when games are submitting data
enable_solar_data_external_fetch = false
enable_weather_data_external_fetch = false

[api_endpoint_features]
# Enable write operations for game submission
enable_solar_data_post_submit = true
enable_solar_data_post_batch_submit = true
enable_solar_data_put_update = true
enable_weather_data_post_submit = true
enable_weather_data_post_batch_submit = true
enable_weather_data_put_update = true
```

### External Data Only Mode
To use only external data sources and disable game submission:

```ini
[data_source_features]
# Disable game submission
enable_solar_data_game_submission = false
enable_weather_data_game_submission = false

# Enable external fetching
enable_solar_data_external_fetch = true
enable_weather_data_external_fetch = true

[api_endpoint_features]
# Disable write operations
enable_solar_data_post_submit = false
enable_solar_data_post_batch_submit = false
enable_solar_data_put_update = false
enable_weather_data_post_submit = false
enable_weather_data_post_batch_submit = false
enable_weather_data_put_update = false
```

### Hybrid Mode
To allow both external data and game submission:

```ini
[data_source_features]
# Enable both external fetching and game submission
enable_solar_data_external_fetch = true
enable_weather_data_external_fetch = true
enable_solar_data_game_submission = true
enable_weather_data_game_submission = true

[api_endpoint_features]
# Enable all operations
enable_solar_data_get_current = true
enable_solar_data_get_history = true
enable_solar_data_get_forecast = true
enable_solar_data_post_submit = true
enable_solar_data_post_batch_submit = true
enable_solar_data_put_update = true
enable_weather_data_get_current = true
enable_weather_data_get_history = true
enable_weather_data_get_forecast = true
enable_weather_data_post_submit = true
enable_weather_data_post_batch_submit = true
enable_weather_data_put_update = true
```

## API Response Behavior

### When Read Operations are Disabled
- GET endpoints return HTTP 403 Forbidden
- Response includes error message: "Solar data access is disabled by feature toggle"

### When Write Operations are Disabled
- POST/PUT endpoints return HTTP 403 Forbidden
- Response includes error message: "Solar data submission is disabled by feature toggle"

### When External Sources are Disabled
- External data fetching is skipped
- System falls back to cached data or default values
- Game-submitted data takes precedence

## Implementation Details

### Feature Toggle Checking
All API endpoints check feature toggles before processing requests:

```cpp
// Check if solar data write operations are enabled
if (!isFeatureEnabled("enable_solar_data_post_submit")) {
    res.status = 403;
    res.set_content(createErrorResponse("Solar data submission is disabled by feature toggle"), "application/json");
    return;
}
```

### External Source Control
External data sources check toggles before fetching:

```cpp
// Check if external data sources are enabled
if (!isFeatureEnabled("enable_external_solar_data_sources")) {
    return false;
}

// Check if game submission mode is enabled - if so, disable external fetching
if (isFeatureEnabled("enable_solar_data_game_submission") && 
    !isFeatureEnabled("enable_solar_data_external_fetch")) {
    return false;
}
```

## Security Considerations

### API Access Control
- Feature toggles provide a security layer for API access
- Disabled endpoints return 403 Forbidden instead of processing requests
- Prevents unauthorized data modification when write operations are disabled

### Data Source Integrity
- When game submission is enabled, external sources can be disabled to prevent conflicts
- Ensures data consistency by using a single source of truth
- Prevents external data from overwriting game-submitted data

## Monitoring and Logging

### Feature Toggle Status
The system logs when feature toggles block operations:
- API endpoint access denials are logged
- External source fetch attempts are logged when disabled
- Feature toggle changes are logged for audit purposes

### Performance Impact
- Disabled features have zero performance impact
- External source disabling reduces network traffic
- Read-only mode reduces server processing load

## Best Practices

### Production Environments
- Use read-only mode for public APIs
- Enable write operations only for authenticated game clients
- Disable external sources when using game-submitted data

### Development Environments
- Enable all features for testing
- Use hybrid mode for integration testing
- Monitor feature toggle usage for optimization

### Game Integration
- Check feature toggle status before attempting API calls
- Implement fallback behavior when write operations are disabled
- Use appropriate error handling for 403 responses

## Troubleshooting

### Common Issues

#### API Endpoints Return 403
- Check feature toggle configuration
- Verify the specific endpoint toggle is enabled
- Review logs for toggle status

#### External Data Not Updating
- Check external source toggles
- Verify game submission mode settings
- Review data source priority configuration

#### Game Submission Fails
- Verify write operation toggles are enabled
- Check API endpoint availability
- Review authentication requirements

### Configuration Validation
The system validates feature toggle configurations on startup:
- Invalid toggle values are logged
- Missing toggles use default values
- Conflicting toggles are resolved with priority rules

## Future Enhancements

### Planned Features
- Runtime toggle modification via API
- Toggle-based rate limiting
- Advanced conflict resolution
- Toggle-based caching strategies

### Integration Improvements
- WebSocket notifications for toggle changes
- REST API for toggle management
- Configuration validation tools
- Performance impact analysis
