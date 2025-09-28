# Server Configuration Updates

This document outlines the updates to server configuration files to support the new international band plan data and 4m band allocations.

## Overview

The server configuration has been updated to support the expanded band plan data, including new bands (4m, 2200m, 630m) and international frequency allocations with proper power limits and license class mappings.

## Configuration Files Updated

### Band Plan Configuration
```ini
# Updated band plan configuration
[band_plan]
# Enable new bands
enable_4m_band = true
enable_2200m_band = true
enable_630m_band = true

# International allocations
enable_international_allocations = true
enable_itu_region_1 = true
enable_itu_region_2 = true
enable_itu_region_3 = true

# 4m band specific settings
4m_band_frequency_start = 69.9
4m_band_frequency_end = 70.5
4m_band_power_limit_normal = 100
4m_band_power_limit_eme = 1000
4m_band_power_limit_ms = 1000

# 2200m band specific settings
2200m_band_frequency_start = 135.7
2200m_band_frequency_end = 137.8
2200m_band_power_limit_max = 1500

# 630m band specific settings
630m_band_frequency_start = 472
630m_band_frequency_end = 479
630m_band_power_limit_max = 1500
```

### License Class Configuration
```ini
# Updated license class configuration
[license_classes]
# European license classes
uk_full_power_limit = 400
uk_intermediate_power_limit = 50
uk_foundation_power_limit = 10

# Norwegian license classes
norway_special_power_limit = 100
norway_special_eme_power_limit = 1000
norway_special_ms_power_limit = 1000

# German license classes
germany_class_a_power_limit = 750
germany_class_e_power_limit = 75

# US license classes
usa_extra_power_limit = 1500
usa_advanced_power_limit = 1500
usa_general_power_limit = 1500
usa_technician_power_limit = 200
```

### International Configuration
```ini
# International configuration
[international]
# ITU Region 1 (Europe, Africa, Middle East)
itu_region_1_enabled = true
itu_region_1_countries = UK,Ireland,Netherlands,Belgium,Luxembourg,Denmark,Sweden,Finland,Estonia,Latvia,Lithuania,Poland,Czech Republic,Slovakia,Slovenia,Croatia,Norway,Germany,France,Italy,Spain

# ITU Region 2 (Americas)
itu_region_2_enabled = true
itu_region_2_countries = USA,Canada,Mexico,Brazil,Argentina

# ITU Region 3 (Asia-Pacific)
itu_region_3_enabled = true
itu_region_3_countries = Japan,China,India,Australia,New Zealand,South Korea

# 4m band allocations
4m_band_countries = UK,Ireland,Netherlands,Belgium,Luxembourg,Denmark,Sweden,Finland,Estonia,Latvia,Lithuania,Poland,Czech Republic,Slovakia,Slovenia,Croatia,Norway,South Africa

# 2200m band allocations
2200m_band_countries = UK,Germany,USA,Canada,Australia,Norway

# 630m band allocations
630m_band_countries = UK,Germany,USA,Canada,Australia,Norway,New Zealand
```

### Power Limit Configuration
```ini
# Power limit configuration
[power_limits]
# 4m band power limits by country
4m_uk_full = 400
4m_uk_intermediate = 50
4m_uk_foundation = 10
4m_norway_special = 100
4m_norway_special_eme = 1000
4m_norway_special_ms = 1000
4m_netherlands_full = 400
4m_netherlands_intermediate = 100
4m_netherlands_foundation = 25

# 2200m band power limits
2200m_uk_full = 1500
2200m_uk_intermediate = 400
2200m_germany_class_a = 750
2200m_germany_class_e = 75
2200m_usa_extra = 1500
2200m_usa_advanced = 1500
2200m_usa_general = 1500

# 630m band power limits
630m_uk_full = 1500
630m_uk_intermediate = 400
630m_germany_class_a = 750
630m_germany_class_e = 75
630m_usa_extra = 500
630m_usa_advanced = 500
630m_usa_general = 500
```

### Frequency Range Configuration
```ini
# Frequency range configuration
[frequency_ranges]
# 4m band frequency ranges
4m_uk_start = 70.0
4m_uk_end = 70.5
4m_norway_start = 69.9
4m_norway_end = 70.5
4m_netherlands_start = 70.0
4m_netherlands_end = 70.5

# 2200m band frequency ranges
2200m_start = 135.7
2200m_end = 137.8

# 630m band frequency ranges
630m_start = 472
630m_end = 479
```

## Server Implementation

### Band Plan Loader
```cpp
// Updated band plan loader
class BandPlanLoader {
public:
    bool loadBandSegments(const std::string& csv_path);
    bool loadInternationalAllocations();
    bool load4mBandAllocations();
    bool load2200mBandAllocations();
    bool load630mBandAllocations();
    
    // Country-specific loading
    bool loadUKBandPlan();
    bool loadNorwegianBandPlan();
    bool loadGermanBandPlan();
    bool loadUSBandPlan();
    bool loadCanadianBandPlan();
    bool loadAustralianBandPlan();
    
    // Validation
    bool validateBandPlan();
    bool validateInternationalAllocations();
    bool validatePowerLimits();
    bool validateFrequencyRanges();
};
```

### Configuration Manager
```cpp
// Updated configuration manager
class ConfigurationManager {
public:
    // Band plan configuration
    void setBandPlanEnabled(const std::string& band, bool enabled);
    void setInternationalAllocationsEnabled(bool enabled);
    void setITURegionEnabled(int region, bool enabled);
    
    // Power limit configuration
    void setPowerLimit(const std::string& country, const std::string& license_class, 
                      const std::string& band, float power_limit);
    void setEMEPowerLimit(const std::string& country, const std::string& license_class, 
                         const std::string& band, float power_limit);
    void setMSPowerLimit(const std::string& country, const std::string& license_class, 
                        const std::string& band, float power_limit);
    
    // Frequency range configuration
    void setFrequencyRange(const std::string& country, const std::string& band, 
                          float start_freq, float end_freq);
    
    // Validation
    bool validateConfiguration();
    bool validatePowerLimits();
    bool validateFrequencyRanges();
    bool validateInternationalCompliance();
};
```

### Server API Updates
```cpp
// Updated server API
class ServerAPI {
public:
    // Band plan API
    std::string getBandPlan(const std::string& country, const std::string& license_class);
    std::string getInternationalAllocations();
    std::string get4mBandAllocations();
    std::string get2200mBandAllocations();
    std::string get630mBandAllocations();
    
    // Power limit API
    float getPowerLimit(const std::string& country, const std::string& license_class, 
                       const std::string& band, bool eme_ms_operation = false);
    std::string getPowerLimitsByCountry(const std::string& country);
    std::string getPowerLimitsByBand(const std::string& band);
    
    // Frequency range API
    std::string getFrequencyRange(const std::string& country, const std::string& band);
    std::string getFrequencyRangesByCountry(const std::string& country);
    std::string getFrequencyRangesByBand(const std::string& band);
    
    // Validation API
    bool validateFrequency(float frequency, const std::string& country, 
                          const std::string& license_class, const std::string& band);
    bool validatePowerLimit(float power, const std::string& country, 
                           const std::string& license_class, const std::string& band);
    bool validateLicenseClass(const std::string& license_class, const std::string& country);
};
```

## Database Updates

### Schema Updates
```sql
-- Updated database schema
CREATE TABLE IF NOT EXISTS band_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country VARCHAR(50) NOT NULL,
    band VARCHAR(20) NOT NULL,
    license_class VARCHAR(30) NOT NULL,
    frequency_start REAL NOT NULL,
    frequency_end REAL NOT NULL,
    power_limit REAL NOT NULL,
    eme_ms_allowed BOOLEAN DEFAULT FALSE,
    eme_ms_power_limit REAL DEFAULT 0,
    itu_region INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_band_allocations_country ON band_allocations(country);
CREATE INDEX idx_band_allocations_band ON band_allocations(band);
CREATE INDEX idx_band_allocations_license_class ON band_allocations(license_class);
CREATE INDEX idx_band_allocations_itu_region ON band_allocations(itu_region);

-- 4m band specific table
CREATE TABLE IF NOT EXISTS band_4m_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country VARCHAR(50) NOT NULL,
    license_class VARCHAR(30) NOT NULL,
    frequency_start REAL NOT NULL,
    frequency_end REAL NOT NULL,
    power_limit_normal REAL NOT NULL,
    power_limit_eme REAL DEFAULT 0,
    power_limit_ms REAL DEFAULT 0,
    eme_allowed BOOLEAN DEFAULT FALSE,
    ms_allowed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2200m band specific table
CREATE TABLE IF NOT EXISTS band_2200m_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country VARCHAR(50) NOT NULL,
    license_class VARCHAR(30) NOT NULL,
    frequency_start REAL NOT NULL,
    frequency_end REAL NOT NULL,
    power_limit REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 630m band specific table
CREATE TABLE IF NOT EXISTS band_630m_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country VARCHAR(50) NOT NULL,
    license_class VARCHAR(30) NOT NULL,
    frequency_start REAL NOT NULL,
    frequency_end REAL NOT NULL,
    power_limit REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Data Migration
```sql
-- Migration script for existing installations
INSERT INTO band_allocations (country, band, license_class, frequency_start, frequency_end, power_limit, eme_ms_allowed, eme_ms_power_limit, itu_region)
SELECT 
    'UK' as country,
    '4m' as band,
    'Full' as license_class,
    70.0 as frequency_start,
    70.5 as frequency_end,
    400.0 as power_limit,
    FALSE as eme_ms_allowed,
    0.0 as eme_ms_power_limit,
    1 as itu_region
UNION ALL
SELECT 
    'Norway' as country,
    '4m' as band,
    'Special' as license_class,
    69.9 as frequency_start,
    70.5 as frequency_end,
    100.0 as power_limit,
    TRUE as eme_ms_allowed,
    1000.0 as eme_ms_power_limit,
    1 as itu_region;
```

## API Endpoints

### REST API Endpoints
```cpp
// Updated REST API endpoints
class RESTAPI {
public:
    // Band plan endpoints
    void getBandPlan(const HttpRequest& request, HttpResponse& response);
    void getInternationalAllocations(const HttpRequest& request, HttpResponse& response);
    void get4mBandAllocations(const HttpRequest& request, HttpResponse& response);
    void get2200mBandAllocations(const HttpRequest& request, HttpResponse& response);
    void get630mBandAllocations(const HttpRequest& request, HttpResponse& response);
    
    // Power limit endpoints
    void getPowerLimit(const HttpRequest& request, HttpResponse& response);
    void getPowerLimitsByCountry(const HttpRequest& request, HttpResponse& response);
    void getPowerLimitsByBand(const HttpRequest& request, HttpResponse& response);
    
    // Frequency range endpoints
    void getFrequencyRange(const HttpRequest& request, HttpResponse& response);
    void getFrequencyRangesByCountry(const HttpRequest& request, HttpResponse& response);
    void getFrequencyRangesByBand(const HttpRequest& request, HttpResponse& response);
    
    // Validation endpoints
    void validateFrequency(const HttpRequest& request, HttpResponse& response);
    void validatePowerLimit(const HttpRequest& request, HttpResponse& response);
    void validateLicenseClass(const HttpRequest& request, HttpResponse& response);
};
```

### WebSocket API Updates
```cpp
// Updated WebSocket API
class WebSocketAPI {
public:
    // Band plan updates
    void broadcastBandPlanUpdate(const std::string& country, const std::string& band);
    void broadcastInternationalAllocationUpdate();
    void broadcast4mBandUpdate();
    void broadcast2200mBandUpdate();
    void broadcast630mBandUpdate();
    
    // Power limit updates
    void broadcastPowerLimitUpdate(const std::string& country, const std::string& band);
    void broadcastEMEPowerLimitUpdate(const std::string& country, const std::string& band);
    void broadcastMSPowerLimitUpdate(const std::string& country, const std::string& band);
    
    // Frequency range updates
    void broadcastFrequencyRangeUpdate(const std::string& country, const std::string& band);
};
```

## Performance Optimization

### Caching
```cpp
// Updated caching system
class BandPlanCache {
public:
    // Cache management
    void cacheBandPlan(const std::string& country, const std::string& band, const std::string& data);
    void cacheInternationalAllocations(const std::string& data);
    void cache4mBandAllocations(const std::string& data);
    void cache2200mBandAllocations(const std::string& data);
    void cache630mBandAllocations(const std::string& data);
    
    // Cache retrieval
    std::string getCachedBandPlan(const std::string& country, const std::string& band);
    std::string getCachedInternationalAllocations();
    std::string getCached4mBandAllocations();
    std::string getCached2200mBandAllocations();
    std::string getCached630mBandAllocations();
    
    // Cache invalidation
    void invalidateBandPlanCache(const std::string& country, const std::string& band);
    void invalidateInternationalAllocationsCache();
    void invalidate4mBandCache();
    void invalidate2200mBandCache();
    void invalidate630mBandCache();
};
```

### Database Optimization
```sql
-- Database optimization
CREATE INDEX idx_band_allocations_country_band ON band_allocations(country, band);
CREATE INDEX idx_band_allocations_country_license ON band_allocations(country, license_class);
CREATE INDEX idx_band_allocations_band_license ON band_allocations(band, license_class);

-- Query optimization
EXPLAIN QUERY PLAN SELECT * FROM band_allocations 
WHERE country = 'UK' AND band = '4m' AND license_class = 'Full';

-- Performance monitoring
CREATE VIEW band_plan_performance AS
SELECT 
    country,
    band,
    COUNT(*) as allocation_count,
    AVG(power_limit) as avg_power_limit,
    MIN(frequency_start) as min_frequency,
    MAX(frequency_end) as max_frequency
FROM band_allocations
GROUP BY country, band;
```

## Security Updates

### Access Control
```cpp
// Updated access control
class AccessControl {
public:
    // Band plan access control
    bool canAccessBandPlan(const std::string& user_id, const std::string& country, const std::string& band);
    bool canAccessInternationalAllocations(const std::string& user_id);
    bool canAccess4mBandAllocations(const std::string& user_id);
    bool canAccess2200mBandAllocations(const std::string& user_id);
    bool canAccess630mBandAllocations(const std::string& user_id);
    
    // Power limit access control
    bool canAccessPowerLimits(const std::string& user_id, const std::string& country);
    bool canAccessEMEPowerLimits(const std::string& user_id, const std::string& country);
    bool canAccessMSPowerLimits(const std::string& user_id, const std::string& country);
    
    // Frequency range access control
    bool canAccessFrequencyRanges(const std::string& user_id, const std::string& country);
};
```

### Data Validation
```cpp
// Updated data validation
class DataValidation {
public:
    // Band plan validation
    bool validateBandPlanData(const std::string& data);
    bool validateInternationalAllocations(const std::string& data);
    bool validate4mBandAllocations(const std::string& data);
    bool validate2200mBandAllocations(const std::string& data);
    bool validate630mBandAllocations(const std::string& data);
    
    // Power limit validation
    bool validatePowerLimit(float power, const std::string& country, const std::string& license_class);
    bool validateEMEPowerLimit(float power, const std::string& country, const std::string& license_class);
    bool validateMSPowerLimit(float power, const std::string& country, const std::string& license_class);
    
    // Frequency range validation
    bool validateFrequencyRange(float start_freq, float end_freq, const std::string& country, const std::string& band);
    bool validateFrequency(float frequency, const std::string& country, const std::string& band);
};
```

## Monitoring and Logging

### Monitoring
```cpp
// Updated monitoring system
class MonitoringSystem {
public:
    // Band plan monitoring
    void monitorBandPlanUsage(const std::string& country, const std::string& band);
    void monitorInternationalAllocationUsage();
    void monitor4mBandUsage();
    void monitor2200mBandUsage();
    void monitor630mBandUsage();
    
    // Performance monitoring
    void monitorBandPlanPerformance();
    void monitorDatabasePerformance();
    void monitorAPIPerformance();
    
    // Error monitoring
    void monitorBandPlanErrors();
    void monitorValidationErrors();
    void monitorDatabaseErrors();
};
```

### Logging
```cpp
// Updated logging system
class LoggingSystem {
public:
    // Band plan logging
    void logBandPlanAccess(const std::string& user_id, const std::string& country, const std::string& band);
    void logInternationalAllocationAccess(const std::string& user_id);
    void log4mBandAccess(const std::string& user_id);
    void log2200mBandAccess(const std::string& user_id);
    void log630mBandAccess(const std::string& user_id);
    
    // Power limit logging
    void logPowerLimitAccess(const std::string& user_id, const std::string& country, const std::string& band);
    void logEMEPowerLimitAccess(const std::string& user_id, const std::string& country, const std::string& band);
    void logMSPowerLimitAccess(const std::string& user_id, const std::string& country, const std::string& band);
    
    // Frequency range logging
    void logFrequencyRangeAccess(const std::string& user_id, const std::string& country, const std::string& band);
    void logFrequencyValidation(const std::string& user_id, float frequency, const std::string& country, const std::string& band);
};
```

## Testing

### Unit Tests
```cpp
// Updated unit tests
TEST_CASE("Server Configuration Updates", "[server_config]") {
    SECTION("Band plan loading") {
        BandPlanLoader loader;
        REQUIRE(loader.loadBandSegments("band_segments.csv") == true);
        REQUIRE(loader.loadInternationalAllocations() == true);
        REQUIRE(loader.load4mBandAllocations() == true);
        REQUIRE(loader.load2200mBandAllocations() == true);
        REQUIRE(loader.load630mBandAllocations() == true);
    }
    
    SECTION("Configuration management") {
        ConfigurationManager config;
        config.setBandPlanEnabled("4m", true);
        config.setInternationalAllocationsEnabled(true);
        config.setITURegionEnabled(1, true);
        
        REQUIRE(config.validateConfiguration() == true);
        REQUIRE(config.validatePowerLimits() == true);
        REQUIRE(config.validateFrequencyRanges() == true);
        REQUIRE(config.validateInternationalCompliance() == true);
    }
    
    SECTION("Server API") {
        ServerAPI api;
        REQUIRE(api.getBandPlan("UK", "Full") != "");
        REQUIRE(api.getInternationalAllocations() != "");
        REQUIRE(api.get4mBandAllocations() != "");
        REQUIRE(api.get2200mBandAllocations() != "");
        REQUIRE(api.get630mBandAllocations() != "");
    }
}
```

### Integration Tests
```cpp
// Updated integration tests
TEST_CASE("Server Integration", "[server_integration]") {
    SECTION("Band plan integration") {
        BandPlanLoader loader;
        ConfigurationManager config;
        ServerAPI api;
        
        REQUIRE(loader.loadBandSegments("band_segments.csv") == true);
        REQUIRE(config.validateConfiguration() == true);
        REQUIRE(api.getBandPlan("UK", "Full") != "");
    }
    
    SECTION("Database integration") {
        DatabaseManager db;
        REQUIRE(db.createBandAllocationsTable() == true);
        REQUIRE(db.insertBandAllocations() == true);
        REQUIRE(db.validateBandAllocations() == true);
    }
    
    SECTION("API integration") {
        RESTAPI rest_api;
        WebSocketAPI ws_api;
        
        REQUIRE(rest_api.getBandPlan(HttpRequest(), HttpResponse()) == true);
        REQUIRE(ws_api.broadcastBandPlanUpdate("UK", "4m") == true);
    }
}
```

## Documentation

### User Documentation
- **Server Configuration Guide**: User guide for server configuration
- **Band Plan Configuration**: Guide for configuring band plans
- **International Allocations**: Guide for international allocations
- **Power Limit Configuration**: Guide for power limit configuration

### Developer Documentation
- **API Reference**: Complete API reference for server configuration
- **Database Schema**: Database schema documentation
- **Configuration Management**: Configuration management guide
- **Testing Guide**: Testing guide for server configuration

## Maintenance

### Regular Updates
- **Configuration Updates**: Regular updates to server configuration
- **Database Updates**: Regular updates to database schema
- **API Updates**: Regular updates to API endpoints
- **Performance Updates**: Regular performance optimizations

### Update Process
1. **Review Changes**: Review server configuration changes
2. **Update Configuration**: Update server configuration files
3. **Update Database**: Update database schema and data
4. **Test Changes**: Test server configuration changes
5. **Deploy Updates**: Deploy server configuration updates

## References

- Server configuration standards
- Database design principles
- API design best practices
- International radio regulations
- Band plan specifications
