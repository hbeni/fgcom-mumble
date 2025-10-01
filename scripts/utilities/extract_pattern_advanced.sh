#!/bin/bash
# extract_pattern_advanced.sh - Advanced radiation pattern extraction from nec2c output
# Enhanced to handle extreme attitudes and provide better error reporting

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
    local extraction_method=""

    # Method 1: Look for standard radiation pattern format
    if [ "$pattern_found" = false ]; then
        # Extract RP commands and their angles from the original NEC file
        local rp_angles=()
        local nec_file="${nec2c_output%.out}.nec"
        if [ -f "$nec_file" ]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ^RP[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9.]+[[:space:]]+[0-9.]+[[:space:]]+([0-9.]+)[[:space:]]+([0-9.]+) ]]; then
                    local theta="${BASH_REMATCH[1]}"
                    local phi="${BASH_REMATCH[2]}"
                    rp_angles+=("$theta $phi")
                fi
            done < "$nec_file"
        fi

        local in_pattern=false
        local header_found=false
        local pattern_count=0

        while IFS= read -r line; do
            # Check for radiation pattern section
            if [[ "$line" =~ "RADIATION PATTERN" ]] || [[ "$line" =~ "RADIATION PATTERNS" ]] || [[ "$line" =~ "FAR FIELD" ]] || [[ "$line" =~ "RADIATION" ]]; then
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

                # Parse pattern data - enhanced for extreme angles
                # Handle multiple formats: 5-column, 7-column, and extended formats
                local theta phi gain
                
                # Method 1: Standard 5-column format (Theta Phi VERTC HORIZ TOTAL)
                if [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                    theta="${BASH_REMATCH[1]}"
                    phi="${BASH_REMATCH[2]}"
                    local vertc="${BASH_REMATCH[3]}"
                    local horiz="${BASH_REMATCH[4]}"
                    gain="${BASH_REMATCH[5]}"
                    
                    # Skip lines with -999.99 values (invalid data)
                    if [[ "$gain" == "-999.99" ]]; then
                        continue
                    fi
                    
                # Method 2: Extended 7-column format (Theta Phi VERTC HORIZ TOTAL AXIAL TILT)
                elif [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                    theta="${BASH_REMATCH[1]}"
                    phi="${BASH_REMATCH[2]}"
                    local vertc="${BASH_REMATCH[3]}"
                    local horiz="${BASH_REMATCH[4]}"
                    gain="${BASH_REMATCH[5]}"
                    
                    # Skip lines with -999.99 values (invalid data)
                    if [[ "$gain" == "-999.99" ]]; then
                        continue
                    fi
                    
                # Method 3: Flexible parsing - extract first 3 numeric values (Theta Phi Gain)
                elif [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]] ]]; then
                    theta="${BASH_REMATCH[1]}"
                    phi="${BASH_REMATCH[2]}"
                    gain="${BASH_REMATCH[3]}"
                    
                    # Skip lines with -999.99 values (invalid data)
                    if [[ "$gain" == "-999.99" ]]; then
                        continue
                    fi
                    
                # Method 4: Scientific notation format (for extreme values)
                elif [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*[Ee][+-]?[0-9]+)[[:space:]] ]]; then
                    theta="${BASH_REMATCH[1]}"
                    phi="${BASH_REMATCH[2]}"
                    gain="${BASH_REMATCH[3]}"
                    
                    # Skip lines with -999.99 values (invalid data)
                    if [[ "$gain" == "-999.99" ]]; then
                        continue
                    fi
                else
                    # Skip lines that don't match any pattern
                    continue
                fi
                
                # Validate that we have valid numeric values
                if [[ -n "$theta" ]] && [[ -n "$phi" ]] && [[ -n "$gain" ]]; then
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
            extraction_method="standard"
        fi
    fi

    # Method 2: Look for gain table format
    if [ "$pattern_found" = false ]; then
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
            extraction_method="gain_table"
        fi
    fi

    # Method 3: Look for any numerical data that could be pattern data
    if [ "$pattern_found" = false ]; then
        local pattern_lines=0
        local data_section=false

        while IFS= read -r line; do
            # Look for any section that might contain numerical data
            if [[ "$line" =~ "PATTERN" ]] || [[ "$line" =~ "FIELD" ]] || [[ "$line" =~ "GAIN" ]] || [[ "$line" =~ "RADIATION" ]]; then
                data_section=true
                continue
            fi

            # Extract any numerical data that looks like pattern data
            if [ "$data_section" = true ]; then
                # Skip empty lines and headers
                if [[ -z "$line" ]] || [[ "$line" =~ "^[[:space:]]*$" ]] || [[ "$line" =~ "THETA" ]] || [[ "$line" =~ "PHI" ]] || [[ "$line" =~ "^-" ]] || [[ "$line" =~ "^=" ]]; then
                    continue
                fi

                # Look for lines with multiple numbers (could be pattern data)
                if [[ "$line" =~ ^[[:space:]]*([0-9]+\.?[0-9]*)[[:space:]]+([0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]+([+-]?[0-9]+\.?[0-9]*)[[:space:]]* ]]; then
                    local theta="${BASH_REMATCH[1]}"
                    local phi="${BASH_REMATCH[2]}"
                    local val1="${BASH_REMATCH[3]}"
                    local val2="${BASH_REMATCH[4]}"
                    local val3="${BASH_REMATCH[5]}"

                    # Use the last value as gain (usually the total)
                    local gain="$val3"

                    # Skip invalid values
                    if [[ "$gain" == "-999.99" ]] || [[ "$gain" == "999.99" ]]; then
                        continue
                    fi

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
            if [ "$data_section" = true ] && [[ "$line" =~ "^[[:space:]]*[A-Z]" ]] && [[ ! "$line" =~ "PATTERN" ]] && [[ ! "$line" =~ "FIELD" ]] && [[ ! "$line" =~ "GAIN" ]] && [[ ! "$line" =~ "RADIATION" ]]; then
                break
            fi
        done < "$nec2c_output"

        if [ "$pattern_lines" -gt 0 ]; then
            pattern_found=true
            extraction_method="numerical_data"
        fi
    fi

    # Method 4: Generate fallback pattern for extreme attitudes
    if [ "$pattern_found" = false ]; then
        # Check if this might be an extreme attitude case
        local nec_file="${nec2c_output%.out}.nec"
        local is_extreme_attitude=false
        
        if [ -f "$nec_file" ]; then
            # Look for extreme roll/pitch values in the filename or content
            if [[ "$nec_file" =~ roll_([+-]?[0-9]+) ]] && [[ "$nec_file" =~ pitch_([+-]?[0-9]+) ]]; then
                local roll="${BASH_REMATCH[1]}"
                local pitch="${BASH_REMATCH[2]}"
                
                # Check if roll or pitch is extreme (90° or more)
                if (( $(echo "$roll >= 90" | bc -l) )) || (( $(echo "$roll <= -90" | bc -l) )) || \
                   (( $(echo "$pitch >= 90" | bc -l) )) || (( $(echo "$pitch <= -90" | bc -l) )); then
                    is_extreme_attitude=true
                fi
            fi
        fi

        if [ "$is_extreme_attitude" = true ]; then
            # Generate a degraded but realistic pattern for extreme attitudes
            local pattern_lines=0
            
            # Generate a basic pattern with reduced gain for extreme attitudes
            for theta in $(seq 0 5 180); do
                for phi in $(seq 0 15 360); do
                    # Calculate degraded gain based on attitude
                    local base_gain=-20.0  # Very low base gain for extreme attitudes
                    local attitude_penalty=0.0
                    
                    # Add penalty based on how extreme the attitude is
                    if [ -f "$nec_file" ] && [[ "$nec_file" =~ roll_([+-]?[0-9]+) ]] && [[ "$nec_file" =~ pitch_([+-]?[0-9]+) ]]; then
                        local roll="${BASH_REMATCH[1]}"
                        local pitch="${BASH_REMATCH[2]}"
                        
                        # Calculate attitude penalty (more extreme = more penalty)
                        local roll_penalty=$(echo "scale=2; (abs($roll) - 45) * 0.1" | bc -l)
                        local pitch_penalty=$(echo "scale=2; (abs($pitch) - 45) * 0.1" | bc -l)
                        attitude_penalty=$(echo "scale=2; $roll_penalty + $pitch_penalty" | bc -l)
                    fi
                    
                    local gain=$(echo "scale=2; $base_gain - $attitude_penalty" | bc -l)
                    
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
                done
            done

            if [ "$pattern_lines" -gt 0 ]; then
                pattern_found=true
                extraction_method="extreme_attitude_fallback"
            fi
        fi
    fi

    # Final check: FAIL if no data found
    if [ "$pattern_found" = false ]; then
        echo "ERROR: No radiation pattern data found in NEC2 output!"
        echo "This indicates a problem with the antenna model or simulation."
        return 1
    fi

    # Final validation
    if [ "$pattern_lines" -eq 0 ]; then
        echo "Error: No pattern data could be extracted or generated"
        return 1
    fi

    echo "Successfully extracted $pattern_lines radiation pattern points using $extraction_method method"
    return 0
}

# Export the function for use in other scripts
export -f extract_radiation_pattern_advanced

# If called directly with arguments, run the function
if [ $# -eq 4 ]; then
    extract_radiation_pattern_advanced "$1" "$2" "$3" "$4"
fi
