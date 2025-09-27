#!/bin/bash
# extract_pattern_advanced.sh - Advanced radiation pattern extraction from nec2c output

extract_radiation_pattern_advanced() {
    local nec2c_output="$1"
    local pattern_file="$2"
    local frequency_mhz="$3"
    local altitude_m="$4"

    # Create pattern file header
    cat > "$pattern_file" << EOF
# FGCom-mumble Far-Field Radiation Pattern
# Frequency: ${frequency_mhz} MHz
# Altitude: ${altitude_m} m
# Format: Theta Phi Gain_dBi H_Polarization V_Polarization
# Theta: Elevation angle (0-180 degrees)
# Phi: Azimuth angle (0-360 degrees)
# Gain: Antenna gain in dBi
# H_Polarization: Horizontal polarization component
# V_Polarization: Vertical polarization component
EOF

    # Try multiple extraction methods
    local pattern_found=false
    local pattern_lines=0

    # Method 1: Look for standard radiation pattern format
    if [ "$pattern_found" = false ]; then
        echo "Trying standard radiation pattern extraction..."

        # Extract RP commands and their angles from the original NEC file
        local rp_angles=()
        local nec_file="${nec2c_output%.out}.nec"
        if [ -f "$nec_file" ]; then
            echo "Extracting RP angles from NEC file..."
            while IFS= read -r line; do
                if [[ "$line" =~ ^RP[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9.]+[[:space:]]+[0-9.]+[[:space:]]+([0-9.]+)[[:space:]]+([0-9.]+) ]]; then
                    local theta="${BASH_REMATCH[1]}"
                    local phi="${BASH_REMATCH[2]}"
                    echo "Found RP angle: theta=$theta, phi=$phi"
                    rp_angles+=("$theta $phi")
                fi
            done < "$nec_file"
            echo "Total RP angles found: ${#rp_angles[@]}"
        else
            # Suppress the "NEC file not found" message that was confusing users
            : # No operation - just continue silently
        fi

        local in_pattern=false
        local header_found=false
        local pattern_count=0

        while IFS= read -r line; do
            # Check for radiation pattern section
            if [[ "$line" =~ "RADIATION PATTERN" ]] || [[ "$line" =~ "FAR FIELD" ]] || [[ "$line" =~ "RADIATION" ]]; then
                in_pattern=true
                continue
            fi

            # Look for header line with THETA/PHI
            if [ "$in_pattern" = true ] && [[ "$line" =~ "THETA" ]] && [[ "$line" =~ "PHI" ]]; then
                header_found=true
                continue
            fi

            # Extract data lines
            if [ "$in_pattern" = true ] && [ "$header_found" = true ]; then
                # Skip empty lines and separators
                if [[ -z "$line" ]] || [[ "$line" =~ "^[[:space:]]*$" ]] || [[ "$line" =~ "^-" ]] || [[ "$line" =~ "^=" ]]; then
                    continue
                fi

                # Parse pattern data (Theta Phi VERTC HORIZ TOTAL format)
                # Format: "    0.00      0.00     -9.44  -999.99    -9.44"
                if [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                    local theta="${BASH_REMATCH[1]}"
                    local phi="${BASH_REMATCH[2]}"
                    local vertc="${BASH_REMATCH[3]}"
                    local horiz="${BASH_REMATCH[4]}"
                    local gain="${BASH_REMATCH[5]}"

                    # Skip lines with -999.99 values (invalid data)
                    if [[ "$gain" == "-999.99" ]]; then
                        continue
                    fi

                    # Use the correct angles from RP commands if available
                    if [ ${#rp_angles[@]} -gt 0 ] && [ $pattern_count -lt ${#rp_angles[@]} ]; then
                        local rp_angle="${rp_angles[$pattern_count]}"
                        theta=$(echo "$rp_angle" | cut -d' ' -f1)
                        phi=$(echo "$rp_angle" | cut -d' ' -f2)
                    fi

                    # Calculate polarization components (simplified)
                    local h_pol="0.0"
                    local v_pol="0.0"

                    # Basic polarization estimation based on angle
                    if (( $(echo "$theta < 45" | bc -l) )); then
                        v_pol="1.0"  # Vertical polarization dominant at low angles
                    elif (( $(echo "$theta > 135" | bc -l) )); then
                        h_pol="1.0"  # Horizontal polarization dominant at high angles
                    else
                        # Mixed polarization at intermediate angles
                        h_pol="0.5"
                        v_pol="0.5"
                    fi

                    echo "$theta $phi $gain $h_pol $v_pol" >> "$pattern_file"
                    pattern_lines=$((pattern_lines + 1))
                    pattern_count=$((pattern_count + 1))
                fi
            fi

            # Stop if we hit another section
            if [ "$in_pattern" = true ] && [[ "$line" =~ "^[[:space:]]*[A-Z]" ]] && [[ ! "$line" =~ "THETA" ]] && [[ ! "$line" =~ "PHI" ]] && [[ ! "$line" =~ "RADIATION" ]]; then
                break
            fi
        done < "$nec2c_output"

        if [ "$pattern_lines" -gt 0 ]; then
            pattern_found=true
            echo "Standard extraction: Found $pattern_lines pattern points"
        fi
    fi

    # Method 2: Look for gain table format
    if [ "$pattern_found" = false ]; then
        echo "Trying gain table extraction..."

        local in_gain_table=false
        local pattern_lines=0

        while IFS= read -r line; do
            # Look for gain table section
            if [[ "$line" =~ "GAIN" ]] && [[ "$line" =~ "TABLE" ]]; then
                in_gain_table=true
                continue
            fi

            # Extract gain data
            if [ "$in_gain_table" = true ]; then
                # Skip empty lines and headers
                if [[ -z "$line" ]] || [[ "$line" =~ "^[[:space:]]*$" ]] || [[ "$line" =~ "THETA" ]] || [[ "$line" =~ "PHI" ]]; then
                    continue
                fi

                # Parse gain table format
                if [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                    local theta="${BASH_REMATCH[1]}"
                    local phi="${BASH_REMATCH[2]}"
                    local gain="${BASH_REMATCH[3]}"

                    # Calculate polarization components
                    local h_pol="0.0"
                    local v_pol="0.0"

                    if (( $(echo "$theta < 45" | bc -l) )); then
                        v_pol="1.0"
                    elif (( $(echo "$theta > 135" | bc -l) )); then
                        h_pol="1.0"
                    else
                        h_pol="0.5"
                        v_pol="0.5"
                    fi

                    echo "$theta $phi $gain $h_pol $v_pol" >> "$pattern_file"
                    pattern_lines=$((pattern_lines + 1))
                fi
            fi

            # Stop if we hit another section
            if [ "$in_gain_table" = true ] && [[ "$line" =~ "^[[:space:]]*[A-Z]" ]] && [[ ! "$line" =~ "GAIN" ]]; then
                break
            fi
        done < "$nec2c_output"

        if [ "$pattern_lines" -gt 0 ]; then
            pattern_found=true
            echo "Gain table extraction: Found $pattern_lines pattern points"
        fi
    fi

    # Method 3: FAIL if no real data found (NO SYNTHETIC PATTERNS!)
    if [ "$pattern_found" = false ]; then
        echo "ERROR: No real radiation pattern data found in NEC2 output!"
        echo "This indicates a problem with the antenna model or simulation."
        echo "Synthetic patterns are NOT generated as they are inaccurate."
        return 1
    fi

    # Final validation
    if [ "$pattern_lines" -eq 0 ]; then
        echo "Error: No pattern data could be extracted or generated"
        return 1
    fi

    echo "Successfully extracted/generated $pattern_lines radiation pattern points"
    return 0
}

# Export the function for use in other scripts
export -f extract_radiation_pattern_advanced

# If called directly with arguments, run the function
if [ $# -eq 4 ]; then
    extract_radiation_pattern_advanced "$1" "$2" "$3" "$4"
fi
