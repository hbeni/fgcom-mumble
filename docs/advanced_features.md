# Advanced Features

See [Advanced Features Documentation](docs/ADVANCED_FEATURES.md) for a comprehensive overview of all advanced features and capabilities organized by version and update cycle.

**Detailed Documentation**: See [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) for comprehensive technical details.

**Noise Analysis**: See [EV Charging Station Noise Analysis](docs/EV_CHARGING_STATION_NOISE_ANALYSIS.md) for comprehensive noise modeling including electric vehicle charging station noise analysis.

**Electrical Infrastructure**: See [Substation and Power Station Noise Analysis](docs/SUBSTATION_POWER_STATION_NOISE_ANALYSIS.md) for comprehensive noise modeling including electrical substations and power stations with 2MW+ capacity threshold, fencing effects, and multipolygon geometry support.

**Real-time Infrastructure Data**: See [Open Infrastructure Map Integration](docs/OPEN_INFRASTRUCTURE_MAP_INTEGRATION.md) for comprehensive integration with Open Infrastructure Map data source, providing real-time electrical infrastructure data from OpenStreetMap via Overpass API for enhanced noise floor calculations.

**Amateur Radio Band Segments**: See [Radio Amateur Band Segments CSV Format](docs/RADIO_AMATEUR_BAND_SEGMENTS_CSV_FORMAT.md) for comprehensive documentation of the amateur radio frequency allocation system, including country-specific regulations, license class requirements, and power limits.

## Amateur Radio Integration

FGCom-Mumble includes comprehensive amateur radio band segment support with:

- **Global Frequency Allocations**: Support for all ITU regions (1, 2, 3)
- **Country-Specific Regulations**: Detailed allocations for UK, USA, Germany, Canada, Australia, and more
- **License Class Validation**: Automatic checking of license class requirements
- **Power Limit Enforcement**: Real-time power limit validation
- **Mode-Specific Allocations**: CW, SSB, Digital, EME, and Meteor Scatter support
- **Regional Compliance**: Automatic ITU region detection and validation

The system reads from `configs/radio_amateur_band_segments.csv` which contains over 280 frequency allocations covering all major amateur radio bands from 2200m to 70cm, with detailed power limits and licensing requirements for different countries and license classes.
