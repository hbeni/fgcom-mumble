# Database Schema Updates

This document outlines the database schema updates to support the new international band plan data and 4m band allocations.

## Overview

The database schema has been updated to support the expanded band plan data, including new bands (4m, 2200m, 630m) and international frequency allocations with proper power limits and license class mappings.

## Schema Updates

### New Tables

#### 4m Band Allocations Table
```sql
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
```

#### 2200m Band Allocations Table
```sql
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
```

#### 630m Band Allocations Table
```sql
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

### Indexes
```sql
-- 4m band indexes
CREATE INDEX IF NOT EXISTS idx_band_4m_allocations_country ON band_4m_allocations(country);
CREATE INDEX IF NOT EXISTS idx_band_4m_allocations_license_class ON band_4m_allocations(license_class);
CREATE INDEX IF NOT EXISTS idx_band_4m_allocations_frequency ON band_4m_allocations(frequency_start, frequency_end);

-- 2200m band indexes
CREATE INDEX IF NOT EXISTS idx_band_2200m_allocations_country ON band_2200m_allocations(country);
CREATE INDEX IF NOT EXISTS idx_band_2200m_allocations_license_class ON band_2200m_allocations(license_class);
CREATE INDEX IF NOT EXISTS idx_band_2200m_allocations_frequency ON band_2200m_allocations(frequency_start, frequency_end);

-- 630m band indexes
CREATE INDEX IF NOT EXISTS idx_band_630m_allocations_country ON band_630m_allocations(country);
CREATE INDEX IF NOT EXISTS idx_band_630m_allocations_license_class ON band_630m_allocations(license_class);
CREATE INDEX IF NOT EXISTS idx_band_630m_allocations_frequency ON band_630m_allocations(frequency_start, frequency_end);
```

## Data Migration

### 4m Band Data
```sql
INSERT INTO band_4m_allocations (country, license_class, frequency_start, frequency_end, power_limit_normal, power_limit_eme, power_limit_ms, eme_allowed, ms_allowed)
VALUES 
    ('UK', 'Full', 70.0, 70.5, 400.0, 0.0, 0.0, FALSE, FALSE),
    ('UK', 'Intermediate', 70.0, 70.5, 50.0, 0.0, 0.0, FALSE, FALSE),
    ('UK', 'Foundation', 70.0, 70.5, 10.0, 0.0, 0.0, FALSE, FALSE),
    ('Norway', 'Special', 69.9, 70.5, 100.0, 1000.0, 1000.0, TRUE, TRUE),
    ('Netherlands', 'Full', 70.0, 70.5, 400.0, 0.0, 0.0, FALSE, FALSE),
    ('Netherlands', 'Intermediate', 70.0, 70.5, 100.0, 0.0, 0.0, FALSE, FALSE),
    ('Netherlands', 'Foundation', 70.0, 70.5, 25.0, 0.0, 0.0, FALSE, FALSE);
```

### 2200m Band Data
```sql
INSERT INTO band_2200m_allocations (country, license_class, frequency_start, frequency_end, power_limit)
VALUES 
    ('UK', 'Full', 135.7, 137.8, 1500.0),
    ('UK', 'Intermediate', 135.7, 137.8, 400.0),
    ('Germany', 'Class A', 135.7, 137.8, 750.0),
    ('Germany', 'Class E', 135.7, 137.8, 75.0),
    ('USA', 'Extra', 135.7, 137.8, 1500.0),
    ('USA', 'Advanced', 135.7, 137.8, 1500.0),
    ('USA', 'General', 135.7, 137.8, 1500.0);
```

### 630m Band Data
```sql
INSERT INTO band_630m_allocations (country, license_class, frequency_start, frequency_end, power_limit)
VALUES 
    ('UK', 'Full', 472.0, 479.0, 1500.0),
    ('UK', 'Intermediate', 472.0, 479.0, 400.0),
    ('Germany', 'Class A', 472.0, 479.0, 750.0),
    ('Germany', 'Class E', 472.0, 479.0, 75.0),
    ('USA', 'Extra', 472.0, 479.0, 500.0),
    ('USA', 'Advanced', 472.0, 479.0, 500.0),
    ('USA', 'General', 472.0, 479.0, 500.0);
```

## Performance Optimization

### Query Optimization
```sql
-- Optimized queries for band plan data
EXPLAIN QUERY PLAN SELECT * FROM band_4m_allocations 
WHERE country = 'UK' AND license_class = 'Full';

EXPLAIN QUERY PLAN SELECT * FROM band_2200m_allocations 
WHERE country = 'USA' AND license_class = 'Extra';

EXPLAIN QUERY PLAN SELECT * FROM band_630m_allocations 
WHERE country = 'Germany' AND license_class = 'Class A';
```

### Performance Monitoring
```sql
-- Performance monitoring views
CREATE VIEW band_plan_performance AS
SELECT 
    '4m' as band,
    country,
    COUNT(*) as allocation_count,
    AVG(power_limit_normal) as avg_power_limit,
    MIN(frequency_start) as min_frequency,
    MAX(frequency_end) as max_frequency
FROM band_4m_allocations
GROUP BY country
UNION ALL
SELECT 
    '2200m' as band,
    country,
    COUNT(*) as allocation_count,
    AVG(power_limit) as avg_power_limit,
    MIN(frequency_start) as min_frequency,
    MAX(frequency_end) as max_frequency
FROM band_2200m_allocations
GROUP BY country
UNION ALL
SELECT 
    '630m' as band,
    country,
    COUNT(*) as allocation_count,
    AVG(power_limit) as avg_power_limit,
    MIN(frequency_start) as min_frequency,
    MAX(frequency_end) as max_frequency
FROM band_630m_allocations
GROUP BY country;
```

## Security

### Access Control
```sql
-- Access control for band plan data
CREATE VIEW band_plan_access_control AS
SELECT 
    country,
    license_class,
    band,
    frequency_start,
    frequency_end,
    power_limit,
    CASE 
        WHEN country = 'UK' AND license_class = 'Full' THEN 'admin'
        WHEN country = 'UK' AND license_class = 'Intermediate' THEN 'user'
        WHEN country = 'UK' AND license_class = 'Foundation' THEN 'user'
        ELSE 'guest'
    END as access_level
FROM (
    SELECT country, license_class, '4m' as band, frequency_start, frequency_end, power_limit_normal as power_limit
    FROM band_4m_allocations
    UNION ALL
    SELECT country, license_class, '2200m' as band, frequency_start, frequency_end, power_limit
    FROM band_2200m_allocations
    UNION ALL
    SELECT country, license_class, '630m' as band, frequency_start, frequency_end, power_limit
    FROM band_630m_allocations
);
```

## Backup and Recovery

### Backup Procedures
```sql
-- Backup procedures for band plan data
CREATE TABLE band_4m_allocations_backup AS SELECT * FROM band_4m_allocations;
CREATE TABLE band_2200m_allocations_backup AS SELECT * FROM band_2200m_allocations;
CREATE TABLE band_630m_allocations_backup AS SELECT * FROM band_630m_allocations;
```

### Recovery Procedures
```sql
-- Recovery procedures for band plan data
INSERT INTO band_4m_allocations SELECT * FROM band_4m_allocations_backup;
INSERT INTO band_2200m_allocations SELECT * FROM band_2200m_allocations_backup;
INSERT INTO band_630m_allocations SELECT * FROM band_630m_allocations_backup;
```

## Testing

### Data Validation
```sql
-- Data validation queries
SELECT COUNT(*) as total_4m_allocations FROM band_4m_allocations;
SELECT COUNT(*) as total_2200m_allocations FROM band_2200m_allocations;
SELECT COUNT(*) as total_630m_allocations FROM band_630m_allocations;

-- Validate data integrity
SELECT country, license_class, COUNT(*) as count
FROM band_4m_allocations
GROUP BY country, license_class
HAVING COUNT(*) > 1;

-- Validate frequency ranges
SELECT country, MIN(frequency_start) as min_freq, MAX(frequency_end) as max_freq
FROM band_4m_allocations
GROUP BY country;
```

## Documentation

### Schema Documentation
- **Table Documentation**: Complete documentation for all tables
- **Index Documentation**: Documentation for all indexes
- **Query Documentation**: Documentation for common queries
- **Performance Documentation**: Performance optimization guide

### User Documentation
- **Database Guide**: User guide for database operations
- **Query Guide**: Guide for database queries
- **Backup Guide**: Backup and recovery guide
- **Security Guide**: Security guide for database operations

## Maintenance

### Regular Updates
- **Schema Updates**: Regular updates to database schema
- **Data Updates**: Regular updates to band plan data
- **Performance Updates**: Regular performance optimizations
- **Security Updates**: Regular security updates

### Update Process
1. **Review Changes**: Review database schema changes
2. **Update Schema**: Update database schema
3. **Migrate Data**: Migrate existing data
4. **Test Changes**: Test database changes
5. **Deploy Updates**: Deploy database updates

## References

- Database design principles
- SQL optimization techniques
- Security best practices
- Performance monitoring guidelines
- International radio regulations
