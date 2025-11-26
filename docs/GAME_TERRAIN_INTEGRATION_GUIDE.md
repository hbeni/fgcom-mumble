# Game Terrain Integration Guide

## Overview

This guide provides comprehensive instructions for game developers on how to integrate terrain and environmental data with FGCom-mumble for realistic radio propagation simulation.

## Critical Data Requirements

### 1. Line of Sight (LOS) - ABSOLUTELY ESSENTIAL

**Why it's critical**: Radio signals cannot penetrate terrain, concrete buildings with rebar, or metal solid metal objects like metal sheets. Without accurate LOS data, radio communication will be completely unrealistic.

**What games must provide**:
- **Terrain obstruction detection**: Can the signal path reach the receiver?
- **Obstruction distance**: How far along the path is the first obstruction?
- **Obstruction height**: How high is the terrain/object  blocking the signal?

**Implementation priority**: **HIGHEST** - This is the most critical data for realistic radio simulation.

### 2. Terrain Altitude - ESSENTIAL

**Why it's critical**: Antenna height above terrain directly affects radio propagation range and quality.

**What games must provide**:
- **Ground altitude**: Height of the terrain at the user's position
- **User altitude**: Height of the user above the ground
- **Effective antenna height**: Combined height for propagation calculations

**Implementation priority**: **HIGH** - Required for accurate propagation modeling.

### 3. Environmental Conditions - IMPORTANT

**Why it's important**: Weather affects radio propagation and atmospheric noise.

**What games must provide**:
- **Temperature**: Affects atmospheric noise and propagation
- **Precipitation**: Rain/snow significantly impacts radio signals
- **Humidity**: Affects atmospheric absorption
- **Atmospheric pressure**: Influences propagation characteristics

**Implementation priority**: **MEDIUM** - Enhances realism but not critical for basic functionality.

### 4. Noise Floor Data - IMPORTANT

**Why it's important**: Determines the minimum signal strength needed for communication.

**What games must provide**:
- **Ambient noise level**: Base environmental noise
- **Atmospheric noise**: Weather-related noise
- **Man-made noise**: Human activity noise (higher in urban areas)
- **Environment type**: Urban, rural, desert, etc.

**Implementation priority**: **MEDIUM** - Improves realism but not essential for basic operation.

## Implementation Guide

### Step 1: Terrain Data Integration

#### Basic Terrain Height Query
```csharp
// Unity C# Example
public float GetTerrainHeight(Vector3 worldPosition)
{
    // Use your game's terrain system
    return Terrain.activeTerrain.SampleHeight(worldPosition);
}

public float GetGroundAltitude(Vector3 worldPosition)
{
    // Get terrain height + any base altitude
    float terrainHeight = GetTerrainHeight(worldPosition);
    float baseAltitude = GetBaseAltitude(worldPosition); // Sea level, etc.
    return terrainHeight + baseAltitude;
}
```

#### Line of Sight Ray Casting
```csharp
public bool CheckLineOfSight(Vector3 from, Vector3 to)
{
    Vector3 direction = (to - from).normalized;
    float distance = Vector3.Distance(from, to);
    
    // Cast ray from transmitter to receiver
    RaycastHit hit;
    if (Physics.Raycast(from, direction, out hit, distance))
    {
        // Check if hit is terrain (not another object)
        if (hit.collider.CompareTag("Terrain"))
        {
            return false; // LOS blocked by terrain
        }
    }
    
    return true; // Clear line of sight
}
```

### Step 2: Environmental Data Integration

#### Weather System Integration
```csharp
public class WeatherDataProvider
{
    public WeatherConditions GetWeatherConditions(Vector3 position)
    {
        return new WeatherConditions
        {
            Temperature = WeatherSystem.GetTemperature(position),
            Humidity = WeatherSystem.GetHumidity(position),
            Precipitation = WeatherSystem.GetPrecipitation(position),
            WindSpeed = WeatherSystem.GetWindSpeed(position),
            WindDirection = WeatherSystem.GetWindDirection(position)
        };
    }
}
```

#### Noise Floor Calculation
```csharp
public float CalculateNoiseFloor(Vector3 position, float frequency)
{
    float ambientNoise = GetAmbientNoise(position);
    float atmosphericNoise = GetAtmosphericNoise(position, frequency);
    float manMadeNoise = GetManMadeNoise(position);
    
    // Combine noise sources (in dBm)
    return 10 * Mathf.Log10(
        Mathf.Pow(10, ambientNoise / 10) +
        Mathf.Pow(10, atmosphericNoise / 10) +
        Mathf.Pow(10, manMadeNoise / 10)
    );
}
```

### Step 3: API Integration

#### Sending Data to FGCom-mumble
```csharp
public class FGComTerrainProvider
{
    private string fgcomApiUrl = "http://localhost:8080/api/v1/terrain/";
    
    public async Task SendTerrainData(Vector3 position, Vector3 targetPosition)
    {
        var terrainData = new
        {
            transmitter = new
            {
                latitude = GetLatitude(position),
                longitude = GetLongitude(position),
                altitude = GetAltitude(position)
            },
            receiver = new
            {
                latitude = GetLatitude(targetPosition),
                longitude = GetLongitude(targetPosition),
                altitude = GetAltitude(targetPosition)
            }
        };
        
        // Send LOS check request
        var response = await PostAsync($"{fgcomApiUrl}los-check", terrainData);
        return response;
    }
}
```

## Game Engine Specific Implementation

### Unity 3D

#### Terrain System Integration
```csharp
using UnityEngine;

public class UnityTerrainProvider : MonoBehaviour
{
    [SerializeField] private Terrain terrain;
    [SerializeField] private LayerMask terrainLayerMask = 1;
    
    public TerrainData GetTerrainData(Vector3 worldPosition)
    {
        float terrainHeight = terrain.SampleHeight(worldPosition);
        float groundAltitude = GetGroundAltitude(worldPosition);
        
        return new TerrainData
        {
            GroundAltitude = groundAltitude,
            UserAltitude = worldPosition.y - terrainHeight,
            Temperature = GetTemperature(worldPosition),
            Humidity = GetHumidity(worldPosition)
        };
    }
    
    public bool CheckLineOfSight(Vector3 from, Vector3 to)
    {
        Vector3 direction = (to - from).normalized;
        float distance = Vector3.Distance(from, to);
        
        return !Physics.Raycast(from, direction, distance, terrainLayerMask);
    }
}
```

### Unreal Engine

#### C++ Implementation
```cpp
// Header file
class FRadioTerrainProvider
{
public:
    struct FTerrainData
    {
        float GroundAltitude;
        float UserAltitude;
        float Temperature;
        float Humidity;
        bool LineOfSightBlocked;
    };
    
    FTerrainData GetTerrainData(const FVector& Position);
    bool CheckLineOfSight(const FVector& From, const FVector& To);
    
private:
    UWorld* World;
    AWeatherSystem* WeatherSystem;
};

// Implementation
FTerrainData FRadioTerrainProvider::GetTerrainData(const FVector& Position)
{
    FTerrainData Data;
    
    // Get terrain height
    float TerrainHeight = GetTerrainHeight(Position);
    Data.GroundAltitude = GetGroundAltitude(Position);
    Data.UserAltitude = Position.Z - TerrainHeight;
    
    // Get environmental data
    Data.Temperature = WeatherSystem->GetTemperature(Position);
    Data.Humidity = WeatherSystem->GetHumidity(Position);
    
    return Data;
}
```

### Godot Engine

#### GDScript Implementation
```gdscript
extends Node

class_name TerrainProvider

func get_terrain_data(position: Vector3) -> Dictionary:
    var terrain_height = get_terrain_height(position)
    var ground_altitude = get_ground_altitude(position)
    
    return {
        "ground_altitude": ground_altitude,
        "user_altitude": position.y - terrain_height,
        "temperature": get_temperature(position),
        "humidity": get_humidity(position)
    }

func check_line_of_sight(from: Vector3, to: Vector3) -> bool:
    var space_state = get_world().direct_space_state
    var result = space_state.intersect_ray(from, to, [], 1) # Layer 1 = terrain
    
    return result.is_empty()
```

## Performance Optimization

### Caching Strategies

#### Terrain Data Caching
```csharp
public class TerrainDataCache
{
    private Dictionary<Vector2Int, float> terrainCache = new Dictionary<Vector2Int, float>();
    private const float CACHE_RESOLUTION = 100f; // Cache every 100 meters
    
    public float GetCachedTerrainHeight(Vector3 position)
    {
        Vector2Int cacheKey = GetCacheKey(position);
        
        if (!terrainCache.ContainsKey(cacheKey))
        {
            terrainCache[cacheKey] = GetTerrainHeight(position);
        }
        
        return terrainCache[cacheKey];
    }
    
    private Vector2Int GetCacheKey(Vector3 position)
    {
        return new Vector2Int(
            Mathf.FloorToInt(position.x / CACHE_RESOLUTION),
            Mathf.FloorToInt(position.z / CACHE_RESOLUTION)
        );
    }
}
```

#### LOS Calculation Optimization
```csharp
public class LOSOptimizer
{
    private Dictionary<string, bool> losCache = new Dictionary<string, bool>();
    private const float CACHE_DISTANCE_THRESHOLD = 50f; // Update cache every 50m movement
    
    public bool GetCachedLOS(Vector3 from, Vector3 to)
    {
        string cacheKey = GetCacheKey(from, to);
        
        if (!losCache.ContainsKey(cacheKey))
        {
            losCache[cacheKey] = CheckLineOfSight(from, to);
        }
        
        return losCache[cacheKey];
    }
}
```

## Testing and Validation

### Unit Tests
```csharp
[Test]
public void TestTerrainHeightCalculation()
{
    var provider = new TerrainDataProvider();
    var position = new Vector3(100, 0, 100);
    
    var terrainData = provider.GetTerrainData(position);
    
    Assert.Greater(terrainData.GroundAltitude, 0);
    Assert.Greater(terrainData.UserAltitude, 0);
}

[Test]
public void TestLineOfSightBlocked()
{
    var provider = new TerrainDataProvider();
    var from = new Vector3(0, 10, 0);
    var to = new Vector3(100, 10, 0);
    
    // Place terrain obstruction between points
    CreateTerrainObstruction(50, 15, 0);
    
    bool losBlocked = !provider.CheckLineOfSight(from, to);
    Assert.IsTrue(losBlocked);
}
```

### Integration Tests
```csharp
[Test]
public void TestFGComIntegration()
{
    var provider = new FGComTerrainProvider();
    var position = new Vector3(100, 50, 100);
    var targetPosition = new Vector3(200, 50, 200);
    
    var result = await provider.SendTerrainData(position, targetPosition);
    
    Assert.IsNotNull(result);
    Assert.Contains("line_of_sight_blocked", result);
}
```

## Common Issues and Solutions

### Issue 1: Inaccurate LOS Calculations
**Problem**: LOS calculations are too slow or inaccurate.
**Solution**: 
- Use efficient ray casting algorithms
- Implement proper terrain LOD systems
- Cache LOS results for nearby positions

### Issue 2: Performance Problems
**Problem**: Terrain queries are causing frame rate drops.
**Solution**:
- Implement asynchronous terrain queries
- Use background threads for heavy calculations
- Cache frequently accessed data

### Issue 3: Environmental Data Inconsistency
**Problem**: Weather data doesn't match game's weather system.
**Solution**:
- Integrate with game's existing weather system
- Use consistent coordinate systems
- Validate data before sending to FGCom-mumble

## Integration Checklist

### Phase 1: Basic Integration
- [ ] Implement terrain height queries
- [ ] Add basic line-of-sight checking
- [ ] Create simple API communication
- [ ] Test with basic terrain scenarios

### Phase 2: Environmental Data
- [ ] Integrate weather system
- [ ] Add temperature and humidity data
- [ ] Implement precipitation detection
- [ ] Add noise floor calculations

### Phase 3: Optimization
- [ ] Implement data caching
- [ ] Optimize LOS calculations
- [ ] Add performance monitoring
- [ ] Test with large-scale scenarios

### Phase 4: Advanced Features
- [ ] Add atmospheric effects
- [ ] Implement seasonal variations
- [ ] Add day/night cycle effects
- [ ] Create debug visualization tools

## Support and Resources

### Documentation
- [Terrain API Reference](TERRAIN_ENVIRONMENTAL_DATA_API.md)
- [Game Developer Integration Guide](GAME_DEVELOPER_INTEGRATION_GUIDE.md)
- [Technical Documentation](TECHNICAL_DOCUMENTATION.md)

### Community Support
- GitHub Issues: Report bugs and request features
- Discord: Real-time community support
- Forum: Technical discussions and examples

### Example Projects
- Unity integration example
- Unreal Engine integration example
- Godot integration example
- Standalone C++ implementation
