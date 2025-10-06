# Radio Propagation Mathematics

## Overview

This document explains the mathematical models used in FGcom-mumble for radio propagation simulation. These equations govern how radio signals behave in different environments and conditions.

## Free Space Path Loss

The fundamental equation for radio signal attenuation in free space:

```
L_fs = 20 * log10(d) + 20 * log10(f) + 32.45
```

Where:
- `L_fs` = Free space path loss (dB)
- `d` = Distance (km)
- `f` = Frequency (MHz)

### Example Calculation
For a 150 MHz signal over 10 km:
```
L_fs = 20 * log10(10) + 20 * log10(150) + 32.45
L_fs = 20 * 1 + 20 * 2.176 + 32.45
L_fs = 20 + 43.52 + 32.45
L_fs = 95.97 dB
```

## Line of Sight Distance

The maximum line of sight distance between two antennas:

```
d_max = 3.57 * sqrt(h1 + h2)
```

Where:
- `d_max` = Maximum line of sight distance (km)
- `h1` = Height of first antenna (m)
- `h2` = Height of second antenna (m)

### Example Calculation
For antennas at 10m and 50m height:
```
d_max = 3.57 * sqrt(10 + 50)
d_max = 3.57 * sqrt(60)
d_max = 3.57 * 7.746
d_max = 27.65 km
```

## Fresnel Zone Calculation

The radius of the first Fresnel zone at a given point:

```
r = 17.3 * sqrt((d1 * d2) / (f * d))
```

Where:
- `r` = Fresnel zone radius (m)
- `d1` = Distance from transmitter to obstacle (km)
- `d2` = Distance from obstacle to receiver (km)
- `f` = Frequency (MHz)
- `d` = Total distance (km)

### Example Calculation
For a 150 MHz signal, obstacle at 5 km from transmitter, total distance 20 km:
```
r = 17.3 * sqrt((5 * 15) / (150 * 20))
r = 17.3 * sqrt(75 / 3000)
r = 17.3 * sqrt(0.025)
r = 17.3 * 0.158
r = 2.73 m
```

## Ground Reflection

The reflection coefficient for ground reflection:

```
R = (sin(θ) - sqrt(ε - cos²(θ))) / (sin(θ) + sqrt(ε - cos²(θ)))
```

Where:
- `R` = Reflection coefficient
- `θ` = Angle of incidence (radians)
- `ε` = Relative permittivity of ground

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

## Atmospheric Refraction

The effective Earth radius factor:

```
k = 1 / (1 + (dn/dh) * 10^-6)
```

Where:
- `k` = Effective Earth radius factor
- `dn/dh` = Refractivity gradient (N-units/km)

### Example Calculation
For standard atmosphere (dn/dh = -40 N-units/km):
```
k = 1 / (1 + (-40) * 10^-6)
k = 1 / (1 - 0.00004)
k = 1 / 0.99996
k = 1.00004
```

## Rain Attenuation

Rain attenuation coefficient:

```
α = a * R^b
```

Where:
- `α` = Attenuation coefficient (dB/km)
- `R` = Rain rate (mm/h)
- `a`, `b` = Frequency-dependent coefficients

### Example Calculation
For 10 GHz frequency (a = 0.0001, b = 1.0) with 10 mm/h rain:
```
α = 0.0001 * 10^1.0
α = 0.0001 * 10
α = 0.001 dB/km
```

## Knife-Edge Diffraction

The diffraction loss for knife-edge obstacles:

```
L_d = 6.9 + 20 * log10(sqrt((v - 0.1)² + 1) + v - 0.1)
```

Where:
- `L_d` = Diffraction loss (dB)
- `v` = Fresnel parameter

### Example Calculation
For v = 2.0:
```
L_d = 6.9 + 20 * log10(sqrt((2.0 - 0.1)² + 1) + 2.0 - 0.1)
L_d = 6.9 + 20 * log10(sqrt(3.61 + 1) + 1.9)
L_d = 6.9 + 20 * log10(sqrt(4.61) + 1.9)
L_d = 6.9 + 20 * log10(2.15 + 1.9)
L_d = 6.9 + 20 * log10(4.05)
L_d = 6.9 + 20 * 0.607
L_d = 6.9 + 12.14
L_d = 19.04 dB
```

## Antenna Gain

The gain of a directional antenna:

```
G = 10 * log10(4π * A_eff / λ²)
```

Where:
- `G` = Antenna gain (dBi)
- `A_eff` = Effective aperture area (m²)
- `λ` = Wavelength (m)

### Example Calculation
For a 1 m² aperture at 150 MHz (λ = 2 m):
```
G = 10 * log10(4π * 1 / 2²)
G = 10 * log10(4π * 1 / 4)
G = 10 * log10(π)
G = 10 * 0.497
G = 4.97 dBi
```

## Signal-to-Noise Ratio

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

### Example Calculation
For a 10 W (40 dBm) transmitter, 3 dBi antennas, 10 km distance at 150 MHz, 5 dB other losses, -100 dBm noise floor:
```
L_fs = 20 * log10(10) + 20 * log10(150) + 32.45 = 95.97 dB
SNR = 40 + 3 + 3 - 95.97 - 5 - (-100)
SNR = 40 + 3 + 3 - 95.97 - 5 + 100
SNR = 45.03 dB
```

## Multipath Fading

The Rayleigh fading model for multipath environments:

```
P_r = P_t * |h|²
```

Where:
- `P_r` = Received power (W)
- `P_t` = Transmitted power (W)
- `h` = Complex channel coefficient

The magnitude of h follows a Rayleigh distribution:
```
f(r) = (r/σ²) * exp(-r²/(2σ²))
```

### Example Calculation
For σ = 1, the probability of signal strength > 0.5:
```
P(r > 0.5) = exp(-0.5²/(2*1²))
P(r > 0.5) = exp(-0.25/2)
P(r > 0.5) = exp(-0.125)
P(r > 0.5) = 0.882
```

## Doppler Shift

The Doppler frequency shift:

```
f_d = (v * f * cos(θ)) / c
```

Where:
- `f_d` = Doppler shift (Hz)
- `v` = Relative velocity (m/s)
- `f` = Carrier frequency (Hz)
- `θ` = Angle between velocity and line of sight
- `c` = Speed of light (m/s)

### Example Calculation
For a vehicle moving at 100 km/h (27.8 m/s) at 150 MHz, 45° angle:
```
f_d = (27.8 * 150e6 * cos(45°)) / 3e8
f_d = (27.8 * 150e6 * 0.707) / 3e8
f_d = 2.95e9 / 3e8
f_d = 9.83 Hz
```

## Noise Floor Calculations

The noise floor is the minimum signal level that can be detected above the background noise. It's crucial for determining the maximum communication range.

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

### Example Calculation
For room temperature (290K) and 25 kHz bandwidth:
```
N_thermal = 1.38e-23 * 290 * 25000
N_thermal = 1.001e-16 W
N_thermal_dBm = 10 * log10(1.001e-16 * 1000)
N_thermal_dBm = 10 * log10(1.001e-13)
N_thermal_dBm = 10 * (-13 + log10(1.001))
N_thermal_dBm = 10 * (-13 + 0.0004)
N_thermal_dBm = -129.996 dBm
```

### Receiver Noise Figure

The noise figure of the receiver:

```
NF = 10 * log10(F)
```

Where:
- `NF` = Noise figure (dB)
- `F` = Noise factor (linear)

### Example Calculation
For a receiver with noise factor F = 2:
```
NF = 10 * log10(2)
NF = 10 * 0.301
NF = 3.01 dB
```

### Total System Noise Floor

The total noise floor including receiver noise:

```
N_total = N_thermal + (F - 1) * N_thermal
N_total = F * N_thermal
```

In dBm:
```
N_total_dBm = N_thermal_dBm + NF
```

### Example Calculation
For the previous example with 3.01 dB noise figure:
```
N_total_dBm = -129.996 + 3.01
N_total_dBm = -126.986 dBm
```

### Atmospheric Noise

Atmospheric noise varies with frequency and location:

```
N_atm = 10 * log10(k * T_atm * B) + A_f
```

Where:
- `T_atm` = Atmospheric noise temperature (K)
- `A_f` = Frequency-dependent atmospheric noise (dB)

### Example Calculation
For 150 MHz in rural area (T_atm = 1000K, A_f = 0 dB):
```
N_atm = 10 * log10(1.38e-23 * 1000 * 25000) + 0
N_atm = 10 * log10(3.45e-16)
N_atm = 10 * (-15.46)
N_atm = -154.6 dBm
```

### Man-Made Noise

Urban man-made noise:

```
N_man = 10 * log10(k * T_man * B) + A_urban
```

Where:
- `T_man` = Man-made noise temperature (K)
- `A_urban` = Urban noise factor (dB)

### Example Calculation
For urban environment (T_man = 10000K, A_urban = 6 dB):
```
N_man = 10 * log10(1.38e-23 * 10000 * 25000) + 6
N_man = 10 * log10(3.45e-15) + 6
N_man = 10 * (-14.46) + 6
N_man = -144.6 + 6
N_man = -138.6 dBm
```

### Combined Noise Floor

The total noise floor is the sum of all noise sources:

```
N_total = N_thermal + N_atm + N_man
```

In dBm (using the rule of 10s):
```
N_total_dBm = 10 * log10(10^(N_thermal_dBm/10) + 10^(N_atm_dBm/10) + 10^(N_man_dBm/10))
```

### Example Calculation
For thermal (-130 dBm), atmospheric (-155 dBm), and man-made (-139 dBm) noise:
```
N_total_dBm = 10 * log10(10^(-130/10) + 10^(-155/10) + 10^(-139/10))
N_total_dBm = 10 * log10(10^(-13) + 10^(-15.5) + 10^(-13.9))
N_total_dBm = 10 * log10(1e-13 + 3.16e-16 + 1.26e-14)
N_total_dBm = 10 * log10(1.13e-13)
N_total_dBm = 10 * (-12.95)
N_total_dBm = -129.5 dBm
```

### Signal-to-Noise Ratio Requirements

Different modulation schemes require different SNR levels:

| Modulation | Required SNR (dB) |
|------------|-------------------|
| AM Voice   | 10-15            |
| FM Voice   | 6-12             |
| SSB Voice  | 3-6              |
| Digital    | 10-20            |

### Minimum Detectable Signal

The minimum signal level that can be detected:

```
MDS = N_total + SNR_required
```

### Example Calculation
For FM voice (SNR = 10 dB) with noise floor of -130 dBm:
```
MDS = -130 + 10
MDS = -120 dBm
```

### Link Budget with Noise

The complete link budget including noise:

```
SNR = P_t + G_t + G_r - L_fs - L_other - N_total
```

### Example Calculation
For 10 W (40 dBm) transmitter, 3 dBi antennas, 10 km distance at 150 MHz, 5 dB other losses, -130 dBm noise floor:
```
L_fs = 20 * log10(10) + 20 * log10(150) + 32.45 = 95.97 dB
SNR = 40 + 3 + 3 - 95.97 - 5 - (-130)
SNR = 40 + 3 + 3 - 95.97 - 5 + 130
SNR = 75.03 dB
```

### Noise Temperature

The equivalent noise temperature:

```
T_eq = T_0 * (F - 1)
```

Where:
- `T_eq` = Equivalent noise temperature (K)
- `T_0` = Reference temperature (290K)
- `F` = Noise factor

### Example Calculation
For noise factor F = 2:
```
T_eq = 290 * (2 - 1)
T_eq = 290 * 1
T_eq = 290K
```

### Noise Power Spectral Density

The noise power per unit bandwidth:

```
N_0 = k * T_total
```

Where:
- `N_0` = Noise power spectral density (W/Hz)
- `T_total` = Total system noise temperature (K)

### Example Calculation
For total noise temperature of 1000K:
```
N_0 = 1.38e-23 * 1000
N_0 = 1.38e-20 W/Hz
N_0_dBm = 10 * log10(1.38e-20 * 1000)
N_0_dBm = 10 * log10(1.38e-17)
N_0_dBm = -168.6 dBm/Hz
```

## Implementation Notes

### Numerical Stability
When implementing these equations in code, consider:

1. **Logarithm calculations**: Use log10() for dB calculations
2. **Square root operations**: Ensure positive arguments
3. **Trigonometric functions**: Use radians for angle calculations
4. **Exponential functions**: Check for overflow in extreme cases

### Example C++ Implementation
```cpp
double calculateFreeSpaceLoss(double distance_km, double frequency_mhz) {
    return 20.0 * log10(distance_km) + 20.0 * log10(frequency_mhz) + 32.45;
}

double calculateLineOfSight(double height1_m, double height2_m) {
    return 3.57 * sqrt(height1_m + height2_m);
}
```

### Performance Considerations
- Cache frequently used calculations
- Use lookup tables for trigonometric functions
- Implement fast square root algorithms
- Consider floating-point precision limits

## References

1. ITU-R P.526-14: "Propagation by diffraction"
2. ITU-R P.676-11: "Attenuation by atmospheric gases"
3. ITU-R P.838-3: "Specific attenuation model for rain"
4. ITU-R P.1546-5: "Method for point-to-area predictions"

## Conclusion

These mathematical models provide the foundation for realistic radio propagation simulation in FGcom-mumble. The equations account for:

- Free space propagation
- Terrain effects
- Atmospheric conditions
- Antenna characteristics
- Multipath effects
- Doppler shifts

Understanding these equations helps in implementing accurate radio simulation and troubleshooting propagation issues in the system.
