# Radio Propagation Mathematics - Complete Formula Reference

This document contains all mathematical formulas used for radio propagation calculations in FGCom-mumble. All formulas are organized by category with ITU-R standard references where applicable.

## Table of Contents

1. [Free Space Path Loss](#free-space-path-loss)
2. [Line of Sight Distance](#line-of-sight-distance)
3. [Fresnel Zone Calculations](#fresnel-zone-calculations)
4. [Atmospheric Effects](#atmospheric-effects)
5. [Rain Attenuation](#rain-attenuation)
6. [Diffraction Loss](#diffraction-loss)
7. [Ground Reflection](#ground-reflection)
8. [Antenna Gain and ERP](#antenna-gain-and-erp)
9. [Signal-to-Noise Ratio](#signal-to-noise-ratio)
10. [Noise Floor Calculations](#noise-floor-calculations)
11. [Ionospheric Propagation](#ionospheric-propagation)
12. [Solar Activity Effects](#solar-activity-effects)
13. [Terrain Effects](#terrain-effects)
14. [Wavelength and Frequency](#wavelength-and-frequency)

---

## Free Space Path Loss

### ITU-R P.525-2: Standard Free Space Path Loss

The fundamental equation for radio signal attenuation in free space:

```
L_fs = 20 * log10(4π * d / λ)
```

Where:
- `L_fs` = Free space path loss (dB)
- `d` = Distance (meters)
- `λ` = Wavelength (meters)
- `π` = 3.14159...

### Alternative Form (Distance in km, Frequency in MHz)

```
L_fs = 20 * log10(d) + 20 * log10(f) + 32.45
```

Where:
- `d` = Distance (km)
- `f` = Frequency (MHz)

### Wavelength Calculation

```
λ = c / f = 300 / f_mhz
```

Where:
- `λ` = Wavelength (meters)
- `c` = Speed of light (300,000,000 m/s)
- `f_mhz` = Frequency (MHz)

### Example Calculation

For a 150 MHz signal over 10 km:
```
λ = 300 / 150 = 2.0 meters
L_fs = 20 * log10(4π * 10000 / 2.0)
L_fs = 20 * log10(62831.85)
L_fs = 20 * 4.798
L_fs = 95.96 dB
```

Or using the simplified formula:
```
L_fs = 20 * log10(10) + 20 * log10(150) + 32.45
L_fs = 20 * 1 + 20 * 2.176 + 32.45
L_fs = 20 + 43.52 + 32.45
L_fs = 95.97 dB
```

---

## Line of Sight Distance

### ITU-R P.526-14: Line of Sight Distance with Earth Curvature

The maximum line of sight distance between two antennas accounting for Earth's curvature:

```
d_los = sqrt(2 * k * R_e * h1) + sqrt(2 * k * R_e * h2)
```

Where:
- `d_los` = Maximum line of sight distance (meters)
- `k` = Effective Earth radius factor (typically 4/3 for standard atmosphere)
- `R_e` = Earth radius (6,371,000 meters)
- `h1` = Height of first antenna (meters)
- `h2` = Height of second antenna (meters)

### Simplified Form (Standard Atmosphere)

```
d_max = 3.57 * sqrt(h1 + h2)
```

Where:
- `d_max` = Maximum line of sight distance (km)
- `h1`, `h2` = Antenna heights (meters)

### Effective Earth Radius Factor

```
k = 1 / (1 + (dn/dh) * 10^-6)
```

Where:
- `k` = Effective Earth radius factor
- `dn/dh` = Refractivity gradient (N-units/km)
- Standard atmosphere: `dn/dh = -40 N-units/km`, giving `k = 4/3`

### Example Calculation

For antennas at 10m and 50m height:
```
d_max = 3.57 * sqrt(10 + 50)
d_max = 3.57 * sqrt(60)
d_max = 3.57 * 7.746
d_max = 27.65 km
```

---

## Fresnel Zone Calculations

### First Fresnel Zone Radius

The radius of the first Fresnel zone at a given point along the path:

```
r = sqrt(λ * d1 * d2 / (d1 + d2))
```

Where:
- `r` = Fresnel zone radius (meters)
- `λ` = Wavelength (meters)
- `d1` = Distance from transmitter to point (meters)
- `d2` = Distance from point to receiver (meters)

### Simplified Form (Midpoint)

At the midpoint of the path (d1 = d2 = d/2):

```
r = sqrt(λ * d / 4)
```

Or in practical units:
```
r = 17.3 * sqrt(d / (4 * f))
```

Where:
- `r` = Fresnel zone radius (meters)
- `d` = Total distance (km)
- `f` = Frequency (MHz)

### Fresnel Zone Clearance Loss

Loss due to insufficient Fresnel zone clearance:

```
L_fresnel = 20 * log10(0.6 / clearance_ratio)  if clearance_ratio < 0.6
L_fresnel = 0  if clearance_ratio >= 0.6
```

Where:
- `clearance_ratio` = Actual clearance / Fresnel radius

### Example Calculation

For a 150 MHz signal, obstacle at 5 km from transmitter, total distance 20 km:
```
λ = 300 / 150 = 2.0 meters
d1 = 5000 meters, d2 = 15000 meters
r = sqrt(2.0 * 5000 * 15000 / 20000)
r = sqrt(7,500,000 / 20,000)
r = sqrt(375)
r = 19.36 meters
```

Or using simplified formula:
```
r = 17.3 * sqrt(20 / (4 * 150))
r = 17.3 * sqrt(20 / 600)
r = 17.3 * sqrt(0.0333)
r = 17.3 * 0.183
r = 3.17 meters
```

---

## Atmospheric Effects

### ITU-R P.676-11: Atmospheric Absorption

Atmospheric absorption due to oxygen and water vapor:

#### Oxygen Absorption

For frequencies 50-70 GHz:
```
α_oxygen = 0.5 * exp(-((f_ghz - 60.0) / 10.0)^2) * distance_km
```

Where:
- `α_oxygen` = Oxygen absorption (dB)
- `f_ghz` = Frequency (GHz)
- `distance_km` = Path distance (km)

#### Water Vapor Absorption

For frequencies 20-30 GHz:
```
α_water = 0.1 * exp(-((f_ghz - 22.0) / 3.0)^2) * distance_km
```

Where:
- `α_water` = Water vapor absorption (dB)
- `f_ghz` = Frequency (GHz)

#### Altitude-Dependent Atmospheric Density

```
altitude_factor = exp(-avg_altitude_m / 8000.0)
absorption_db *= altitude_factor
```

Where:
- `avg_altitude_m` = Average altitude along path (meters)
- Scale height ≈ 8 km

#### VHF Atmospheric Loss (Simplified)

For VHF frequencies:
```
atmospheric_loss = 0.001 * distance_km  (if f >= 50 MHz, oxygen)
atmospheric_loss += 0.0005 * distance_km  (if f >= 20 MHz, water vapor)
```

### Example Calculation

For 60 GHz at sea level over 1 km:
```
α_oxygen = 0.5 * exp(-((60 - 60) / 10)^2) * 1
α_oxygen = 0.5 * exp(0) * 1
α_oxygen = 0.5 dB
```

---

## Rain Attenuation

### ITU-R P.838-3: Rain Attenuation

Rain attenuation coefficient:

```
γ_r = k * R^α
α_rain = γ_r * distance_km
```

Where:
- `γ_r` = Rain attenuation coefficient (dB/km)
- `R` = Rain rate (mm/h)
- `k`, `α` = Frequency-dependent coefficients
- `α_rain` = Total rain attenuation (dB)

### Frequency-Dependent Coefficients

#### Microwave Frequencies (1-10 GHz)
```
k = 0.0001 * f_ghz^1.5
α = 1.0
```

#### UHF Frequencies (100-1000 MHz)
```
k = 0.00001 * (f_mhz / 100)^0.5
α = 0.8
```

#### VHF and Lower Frequencies (< 100 MHz)
```
k = 0.000001
α = 0.5
```

### Example Calculation

For 10 GHz frequency with 10 mm/h rain over 5 km:
```
k = 0.0001 * 10^1.5 = 0.0001 * 31.62 = 0.003162
γ_r = 0.003162 * 10^1.0 = 0.03162 dB/km
α_rain = 0.03162 * 5 = 0.158 dB
```

---

## Diffraction Loss

### ITU-R P.526-14: Knife-Edge Diffraction

The diffraction loss for knife-edge obstacles:

```
L_d = 6.9 + 20 * log10(sqrt((v - 0.1)^2 + 1) + v - 0.1)
```

Where:
- `L_d` = Diffraction loss (dB)
- `v` = Fresnel parameter (dimensionless)

### Fresnel Parameter Calculation

```
v = h * sqrt(2 * (d1 + d2) / (λ * d1 * d2))
```

Where:
- `h` = Obstacle height above line of sight (meters)
- `d1` = Distance from transmitter to obstacle (meters)
- `d2` = Distance from obstacle to receiver (meters)
- `λ` = Wavelength (meters)

### Simplified Form

For obstacle at midpoint:
```
v = h / r_fresnel
```

Where `r_fresnel` is the Fresnel zone radius at the obstacle.

### Example Calculation

For v = 2.0:
```
L_d = 6.9 + 20 * log10(sqrt((2.0 - 0.1)^2 + 1) + 2.0 - 0.1)
L_d = 6.9 + 20 * log10(sqrt(3.61 + 1) + 1.9)
L_d = 6.9 + 20 * log10(sqrt(4.61) + 1.9)
L_d = 6.9 + 20 * log10(2.15 + 1.9)
L_d = 6.9 + 20 * log10(4.05)
L_d = 6.9 + 20 * 0.607
L_d = 6.9 + 12.14
L_d = 19.04 dB
```

---

## Ground Reflection

### ITU-R P.1546-5: Ground Reflection Loss

The reflection coefficient for ground reflection:

```
R = (sin(θ) - sqrt(ε - cos²(θ))) / (sin(θ) + sqrt(ε - cos²(θ)))
```

Where:
- `R` = Reflection coefficient
- `θ` = Angle of incidence (radians)
- `ε` = Relative permittivity of ground

### Grazing Angle Calculation

```
θ_grazing = atan((h1 + h2) / (d * 1000))
```

Where:
- `h1`, `h2` = Antenna heights (meters)
- `d` = Distance (km)

### Simplified Ground Reflection Loss

For low grazing angles (< 30°):
```
L_ground = 6.0 + 10 * log10(f / 100)
```

For high grazing angles (≥ 30°):
```
L_ground = 2.0
```

### Ground Permittivity Values

| Ground Type | Relative Permittivity (ε) | Conductivity (S/m) |
|-------------|---------------------------|-------------------|
| Wet ground   | 15-30                     | 0.01-0.1          |
| Dry ground   | 3-5                       | 0.001-0.01        |
| Sea water    | 80                        | 5                 |
| Fresh water  | 80                        | 0.001             |

### Example Calculation

For wet ground (ε = 25) at 30° angle:
```
θ = 30° = 0.524 radians
R = (sin(0.524) - sqrt(25 - cos²(0.524))) / (sin(0.524) + sqrt(25 - cos²(0.524)))
R = (0.5 - sqrt(25 - 0.75)) / (0.5 + sqrt(25 - 0.75))
R = (0.5 - sqrt(24.25)) / (0.5 + sqrt(24.25))
R = (0.5 - 4.92) / (0.5 + 4.92)
R = -4.42 / 5.42
R = -0.815
```

---

## Antenna Gain and ERP

### Antenna Gain

The gain of a directional antenna:

```
G = 10 * log10(4π * A_eff / λ²)
```

Where:
- `G` = Antenna gain (dBi)
- `A_eff` = Effective aperture area (m²)
- `λ` = Wavelength (m)

### Effective Radiated Power (ERP)

```
ERP = P_t + G_t - L_cable - L_connector
```

Where:
- `ERP` = Effective Radiated Power (dBm)
- `P_t` = Transmitter power (dBm)
- `G_t` = Transmitting antenna gain (dBi)
- `L_cable` = Cable loss (dB)
- `L_connector` = Connector loss (dB)

### ERP with Antenna Efficiency

```
ERP = P_t + G_t + η_antenna - L_cable - L_connector
```

Where:
- `η_antenna` = Antenna efficiency (dB, negative value)

### ERP Unit Conversions

```
ERP_W = 10^((ERP_dBm - 30) / 10)
ERP_dBW = ERP_dBm - 30
```

### Example Calculation

For P_t = 50 W (47 dBm), G_t = 6 dBi, L_cable = 2 dB, L_connector = 0.5 dB:
```
ERP = 47 + 6 - 2 - 0.5
ERP = 50.5 dBm
ERP = 112.2 W
```

---

## Signal-to-Noise Ratio

### Basic SNR Calculation

The signal-to-noise ratio at the receiver:

```
SNR = P_t + G_t + G_r - L_fs - L_other - N
```

Where:
- `SNR` = Signal-to-noise ratio (dB)
- `P_t` = Transmitter power (dBm)
- `G_t` = Transmitter antenna gain (dBi)
- `G_r` = Receiver antenna gain (dBi)
- `L_fs` = Free space path loss (dB)
- `L_other` = Other losses (dB)
- `N` = Noise floor (dBm)

### SNR with ERP

```
SNR = ERP + G_r - L_path - N_floor
```

### Received Power

```
P_received = ERP - L_path + G_r
```

### Example Calculation

For a 10 W (40 dBm) transmitter, 3 dBi antennas, 10 km distance at 150 MHz, 5 dB other losses, -100 dBm noise floor:
```
L_fs = 20 * log10(10) + 20 * log10(150) + 32.45 = 95.97 dB
SNR = 40 + 3 + 3 - 95.97 - 5 - (-100)
SNR = 40 + 3 + 3 - 95.97 - 5 + 100
SNR = 45.03 dB
```

---

## Noise Floor Calculations

### Thermal Noise Floor

The fundamental thermal noise floor:

```
N_thermal = k * T * B
```

Where:
- `N_thermal` = Thermal noise power (W)
- `k` = Boltzmann's constant (1.38 × 10^-23 J/K)
- `T` = Temperature (K)
- `B` = Bandwidth (Hz)

In dBm:
```
N_thermal_dBm = 10 * log10(k * T * B * 1000)
```

### Receiver Noise Figure

```
NF = 10 * log10(F)
```

Where:
- `NF` = Noise figure (dB)
- `F` = Noise factor (linear)

### Total System Noise Floor

```
N_total = F * N_thermal
N_total_dBm = N_thermal_dBm + NF
```

### Atmospheric Noise

```
N_atm = 10 * log10(k * T_atm * B) + A_f
```

Where:
- `T_atm` = Atmospheric noise temperature (K)
- `A_f` = Frequency-dependent atmospheric noise (dB)

### Man-Made Noise

```
N_man = 10 * log10(k * T_man * B) + A_urban
```

Where:
- `T_man` = Man-made noise temperature (K)
- `A_urban` = Urban noise factor (dB)

### Combined Noise Floor

```
N_total_dBm = 10 * log10(10^(N_thermal_dBm/10) + 10^(N_atm_dBm/10) + 10^(N_man_dBm/10))
```

### Minimum Detectable Signal

```
MDS = N_total + SNR_required
```

### Example Calculation

For room temperature (290K) and 25 kHz bandwidth:
```
N_thermal = 1.38e-23 * 290 * 25000
N_thermal = 1.001e-16 W
N_thermal_dBm = 10 * log10(1.001e-16 * 1000)
N_thermal_dBm = 10 * log10(1.001e-13)
N_thermal_dBm = -129.996 dBm
```

---

## Ionospheric Propagation

### Maximum Usable Frequency (MUF)

```
MUF = foF2 * sec(φ)
```

Where:
- `MUF` = Maximum Usable Frequency (MHz)
- `foF2` = Critical frequency of F2 layer (MHz)
- `φ` = Angle of incidence at the ionosphere

### Critical Frequency (foF2)

```
foF2 = foF2_median * (1 + 0.3 * cos(2π * (t - 12) / 24))
```

Where:
- `foF2_median` = Median critical frequency (MHz)
- `t` = Time of day (hours)

### MUF for Different Distances

```
MUF_distance = MUF_3000 * (3000 / distance_km)^0.5
```

Where:
- `MUF_3000` = MUF for 3000 km distance
- `distance_km` = Actual distance (km)

### Minimum Usable Frequency (LUF)

```
LUF = max(LUF_absorption, LUF_noise, LUF_antenna)
```

#### Absorption-Limited LUF

```
LUF_absorption = 0.885 * foE * sec(φ)
```

Where:
- `foE` = Critical frequency of E layer (MHz)

#### Noise-Limited LUF

```
LUF_noise = (P_t + G_t + G_r - L_path - SNR_required - N_floor) / 20
```

### Optimal Working Frequency (OWF)

```
OWF = 0.85 * MUF
```

### Frequency of Optimum Traffic (FOT)

```
FOT = 0.9 * MUF
```

### Example Calculation

For foF2_median = 8 MHz at 14:00 hours:
```
foF2 = 8 * (1 + 0.3 * cos(2π * (14 - 12) / 24))
foF2 = 8 * (1 + 0.3 * cos(π/6))
foF2 = 8 * (1 + 0.3 * 0.866)
foF2 = 8 * (1 + 0.26)
foF2 = 8 * 1.26
foF2 = 10.08 MHz
```

---

## Solar Activity Effects

### Solar Flux Index (SFI) Effect

```
SFI_effect = 0.1 * (SFI - 70)
```

Where:
- `SFI` = Solar Flux Index (10.7 cm)
- Normal range: 70-300

### Sunspot Number Influence

```
SSN_effect = 0.05 * (SSN - 20)
```

Where:
- `SSN` = Sunspot Number
- Normal range: 0-200

### Solar Activity Factor

```
SAF = 1 + SFI_effect + SSN_effect
```

### Ionospheric Absorption

```
A_ion = A_0 * (f / f_c)^(-2) * SAF
```

Where:
- `A_ion` = Ionospheric absorption (dB)
- `A_0` = Base absorption (dB)
- `f` = Frequency (MHz)
- `f_c` = Critical frequency (MHz)

### MUF Variation with Solar Activity

```
MUF_variation = MUF_base * (1 + 0.2 * sin(2π * t / 24))
```

Where:
- `t` = Time of day (hours)

### Example Calculation

For SFI = 150, SSN = 80:
```
SFI_effect = 0.1 * (150 - 70) = 8.0
SSN_effect = 0.05 * (80 - 20) = 3.0
SAF = 1 + 8.0 + 3.0 = 12.0
```

---

## Terrain Effects

### Terrain Profile Elevation

Terrain elevation affects line of sight and Fresnel zone clearance. The system calculates terrain profiles along the propagation path.

### Obstruction Height Calculation

```
h_obstruction = elevation_terrain - elevation_line_of_sight
```

Where:
- `elevation_line_of_sight` = Expected elevation for unobstructed path

### Terrain Loss

For terrain obstructions:
```
L_terrain = 20 * log10(h_obstruction / 10.0)
```

### Combined Terrain and Fresnel Loss

When both terrain obstruction and Fresnel zone clearance are considered:
```
L_total = L_terrain + L_fresnel
```

### Example Calculation

For obstruction height of 50 meters:
```
L_terrain = 20 * log10(50 / 10.0)
L_terrain = 20 * log10(5.0)
L_terrain = 20 * 0.699
L_terrain = 13.98 dB
```

---

## Total Propagation Loss

### Complete Propagation Loss Formula

The total propagation loss combines all effects:

```
L_total = L_fs + L_atm + L_rain + L_diff + L_ground + L_fresnel + L_terrain
```

Where:
- `L_fs` = Free space path loss
- `L_atm` = Atmospheric absorption
- `L_rain` = Rain attenuation
- `L_diff` = Diffraction loss
- `L_ground` = Ground reflection loss
- `L_fresnel` = Fresnel zone clearance loss
- `L_terrain` = Terrain obstruction loss

### Received Power Calculation

```
P_received = P_transmitted + G_t + G_r - L_total
```

### Link Budget

```
SNR = P_transmitted + G_t + G_r - L_total - N_floor
```

---

## Wavelength and Frequency

### Wavelength from Frequency

```
λ = c / f
λ_meters = 300 / f_mhz
```

### Frequency from Wavelength

```
f = c / λ
f_mhz = 300 / λ_meters
```

### Example Calculations

For 150 MHz:
```
λ = 300 / 150 = 2.0 meters
```

For wavelength of 2 meters:
```
f = 300 / 2 = 150 MHz
```

---

## Implementation Notes

### Numerical Stability

When implementing these equations in code:

1. **Logarithm calculations**: Use `log10()` for dB calculations
2. **Square root operations**: Ensure positive arguments
3. **Trigonometric functions**: Use radians for angle calculations
4. **Exponential functions**: Check for overflow in extreme cases
5. **Division by zero**: Validate all denominators before division
6. **Input validation**: Check for negative or zero distances/frequencies

### C++ Implementation Example

```cpp
double calculateFreeSpaceLoss(double distance_km, double frequency_mhz) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0) {
        return 1000.0; // Return high loss for invalid inputs
    }
    double wavelength_m = 300.0 / frequency_mhz;
    return 20.0 * log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
}

double calculateLineOfSight(double height1_m, double height2_m) {
    const double earth_radius_m = 6371000.0;
    const double k_factor = 4.0 / 3.0;
    double d_los = sqrt(2.0 * k_factor * earth_radius_m * height1_m) + 
                   sqrt(2.0 * k_factor * earth_radius_m * height2_m);
    return d_los / 1000.0; // Convert to km
}

double calculateMUF(double foF2, double angle_rad) {
    return foF2 / cos(angle_rad);
}

double calculateERP(double power_dBm, double antenna_gain_dBi, 
                   double cable_loss_dB, double connector_loss_dB) {
    return power_dBm + antenna_gain_dBi - cable_loss_dB - connector_loss_dB;
}
```

### Performance Considerations

- Cache frequently used calculations (solar data, terrain profiles)
- Use lookup tables for trigonometric functions where appropriate
- Implement fast square root algorithms
- Consider floating-point precision limits
- Update solar activity data periodically
- Use efficient ionospheric models

---

## ITU-R Standards Reference

All formulas in this document are based on or derived from ITU-R recommendations:

- **ITU-R P.525-2**: Calculation of free-space attenuation
- **ITU-R P.526-14**: Propagation by diffraction
- **ITU-R P.676-11**: Attenuation by atmospheric gases
- **ITU-R P.838-3**: Specific attenuation model for rain for use in prediction methods
- **ITU-R P.1546-5**: Method for point-to-area predictions for terrestrial services in the frequency range 30 MHz to 4000 MHz

---

## References

1. ITU-R P.525-2: "Calculation of free-space attenuation"
2. ITU-R P.526-14: "Propagation by diffraction"
3. ITU-R P.676-11: "Attenuation by atmospheric gases"
4. ITU-R P.838-3: "Specific attenuation model for rain for use in prediction methods"
5. ITU-R P.1546-5: "Method for point-to-area predictions for terrestrial services in the frequency range 30 MHz to 4000 MHz"

---

## Conclusion

These mathematical models provide the foundation for realistic radio propagation simulation in FGCom-mumble. The equations account for:

- Free space propagation
- Terrain effects
- Atmospheric conditions
- Antenna characteristics
- Multipath effects
- Ionospheric propagation
- Solar activity effects

Understanding these equations helps in implementing accurate radio simulation and troubleshooting propagation issues in the system.

