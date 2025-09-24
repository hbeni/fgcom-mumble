#!/usr/bin/env python3
"""
Visualize Soviet UAZ 4m Whip Antenna (45° tied down)
"""

import sys
import math

def parse_eznec_file(filename):
    """Parse EZNEC file to extract wire geometry"""
    wires = []
    
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('W'):
                parts = line.strip().split()
                if len(parts) >= 9:
                    wire_id = parts[0]
                    x1, y1, z1 = float(parts[1]), float(parts[2]), float(parts[3])
                    x2, y2, z2 = float(parts[4]), float(parts[5]), float(parts[6])
                    radius = float(parts[7])
                    segments = int(parts[8])
                    
                    wires.append({
                        'id': wire_id,
                        'start': (x1, y1, z1),
                        'end': (x2, y2, z2),
                        'radius': radius,
                        'segments': segments
                    })
    
    return wires

def parse_radiation_pattern(filename):
    """Parse NEC output file to extract radiation pattern"""
    pattern = []
    in_pattern = False
    
    with open(filename, 'r') as f:
        for line in f:
            if "RADIATION PATTERNS" in line:
                in_pattern = True
                continue
            elif in_pattern and line.strip():
                parts = line.strip().split()
                if len(parts) >= 6 and parts[0].replace('.', '').isdigit():
                    try:
                        theta = float(parts[0])
                        phi = float(parts[1])
                        vert_gain = float(parts[2])
                        horiz_gain = float(parts[3])
                        total_gain = float(parts[4])
                        
                        if vert_gain != -999.99:  # Skip invalid data
                            pattern.append({
                                'theta': theta,
                                'phi': phi,
                                'vert_gain': vert_gain,
                                'horiz_gain': horiz_gain,
                                'total_gain': total_gain
                            })
                    except (ValueError, IndexError):
                        continue
    
    return pattern

def create_ascii_antenna_diagram(wires):
    """Create ASCII art representation of antenna geometry"""
    print("=" * 60)
    print("SOVIET UAZ 4m WHIP ANTENNA (45° TIED DOWN)")
    print("=" * 60)
    print()
    
    # Find bounds
    min_x = min(min(w['start'][0], w['end'][0]) for w in wires)
    max_x = max(max(w['start'][0], w['end'][0]) for w in wires)
    min_y = min(min(w['start'][1], w['end'][1]) for w in wires)
    max_y = max(max(w['start'][1], w['end'][1]) for w in wires)
    min_z = min(min(w['start'][2], w['end'][2]) for w in wires)
    max_z = max(max(w['start'][2], w['end'][2]) for w in wires)
    
    print(f"Vehicle dimensions: {max_x-min_x:.1f}m × {max_y-min_y:.1f}m × {max_z-min_z:.1f}m")
    print()
    
    # Top view (X-Y plane)
    print("TOP VIEW (X-Y plane):")
    print("Y")
    print("↑")
    print("│")
    
    # Create a simple grid representation
    grid_size = 20
    grid = [[' ' for _ in range(grid_size)] for _ in range(grid_size)]
    
    for wire in wires:
        x1, y1, z1 = wire['start']
        x2, y2, z2 = wire['end']
        
        # Scale to grid
        gx1 = int((x1 - min_x) / (max_x - min_x) * (grid_size - 1))
        gy1 = int((y1 - min_y) / (max_y - min_y) * (grid_size - 1))
        gx2 = int((x2 - min_x) / (max_x - min_x) * (grid_size - 1))
        gy2 = int((y2 - min_y) / (max_y - min_y) * (grid_size - 1))
        
        # Draw line
        if wire['id'] == 'W015':  # Main antenna wire
            char = 'A'  # Antenna
        elif 'W016' in wire['id'] or 'W017' in wire['id']:  # Antenna base/ground
            char = 'B'  # Base
        else:
            char = '#'  # Vehicle body
        
        # Simple line drawing
        steps = max(abs(gx2-gx1), abs(gy2-gy1), 1)  # Avoid division by zero
        for i in range(steps + 1):
            x = gx1 + (gx2 - gx1) * i // steps
            y = gy1 + (gy2 - gy1) * i // steps
            if 0 <= x < grid_size and 0 <= y < grid_size:
                grid[y][x] = char
    
    # Print grid
    for y in range(grid_size-1, -1, -1):
        print(f"{y:2d}│", end="")
        for x in range(grid_size):
            print(grid[y][x], end="")
        print()
    
    print("  └" + "─" * grid_size)
    print("    " + "".join(f"{i%10}" for i in range(grid_size)))
    print("    " + "X")
    print()
    
    # Side view (X-Z plane)
    print("SIDE VIEW (X-Z plane):")
    print("Z")
    print("↑")
    print("│")
    
    grid_z = [[' ' for _ in range(grid_size)] for _ in range(grid_size)]
    
    for wire in wires:
        x1, y1, z1 = wire['start']
        x2, y2, z2 = wire['end']
        
        # Scale to grid (X-Z plane)
        gx1 = int((x1 - min_x) / (max_x - min_x) * (grid_size - 1))
        gz1 = int((z1 - min_z) / (max_z - min_z) * (grid_size - 1))
        gx2 = int((x2 - min_x) / (max_x - min_x) * (grid_size - 1))
        gz2 = int((z2 - min_z) / (max_z - min_z) * (grid_size - 1))
        
        char = 'A' if wire['id'] == 'W015' else ('B' if 'W016' in wire['id'] or 'W017' in wire['id'] else '#')
        
        steps = max(abs(gx2-gx1), abs(gz2-gz1), 1)  # Avoid division by zero
        for i in range(steps + 1):
            x = gx1 + (gx2 - gx1) * i // steps
            z = gz1 + (gz2 - gz1) * i // steps
            if 0 <= x < grid_size and 0 <= z < grid_size:
                grid_z[z][x] = char
    
    # Print grid
    for z in range(grid_size-1, -1, -1):
        print(f"{z:2d}│", end="")
        for x in range(grid_size):
            print(grid_z[z][x], end="")
        print()
    
    print("  └" + "─" * grid_size)
    print("    " + "".join(f"{i%10}" for i in range(grid_size)))
    print("    " + "X")
    print()
    
    # Legend
    print("LEGEND:")
    print("  A = 4m whip antenna (45° tied down)")
    print("  B = Antenna base and ground strap")
    print("  # = Vehicle body structure")
    print()

def create_radiation_pattern_plot(pattern):
    """Create ASCII plot of radiation pattern"""
    if not pattern:
        print("No valid radiation pattern data found.")
        return
    
    print("=" * 60)
    print("RADIATION PATTERN (36 MHz - VHF)")
    print("=" * 60)
    print()
    
    # Find max gain
    max_gain = max(p['total_gain'] for p in pattern)
    min_gain = min(p['total_gain'] for p in pattern)
    
    print(f"Gain range: {min_gain:.1f} dB to {max_gain:.1f} dB")
    print()
    
    # Create elevation pattern (theta = 0 to 90 degrees, phi = 0)
    elevation_data = [p for p in pattern if p['phi'] == 0.0 and p['theta'] <= 90]
    
    if elevation_data:
        print("ELEVATION PATTERN (φ = 0°):")
        print("Gain (dB)")
        print("↑")
        print("│")
        
        # Create ASCII plot
        plot_width = 50
        plot_height = 20
        
        for theta in range(0, 91, 5):
            # Find closest data point
            closest = min(elevation_data, key=lambda p: abs(p['theta'] - theta))
            gain = closest['total_gain']
            
            # Scale to plot
            y_pos = int((gain - min_gain) / (max_gain - min_gain) * plot_height)
            y_pos = max(0, min(plot_height, y_pos))
            
            # Create line
            line = [' '] * plot_width
            line[0] = f"{theta:2d}°"
            line[3] = '│'
            
            # Add gain bar
            for i in range(4, min(4 + y_pos, plot_width)):
                line[i] = '█'
            
            # Add gain value
            gain_str = f"{gain:5.1f}dB"
            for i, char in enumerate(gain_str):
                if 4 + y_pos + i < plot_width:
                    line[4 + y_pos + i] = char
            
            print(''.join(line))
        
        print("  └" + "─" * plot_width)
        print("    Elevation Angle (degrees)")
        print()
    
    # Create azimuth pattern (theta = 0, phi = 0 to 360 degrees)
    azimuth_data = [p for p in pattern if p['theta'] == 0.0]
    
    if azimuth_data:
        print("AZIMUTH PATTERN (θ = 0°):")
        print("Gain (dB)")
        print("↑")
        print("│")
        
        for phi in range(0, 361, 10):
            # Find closest data point
            closest = min(azimuth_data, key=lambda p: abs(p['phi'] - phi))
            gain = closest['total_gain']
            
            # Scale to plot
            y_pos = int((gain - min_gain) / (max_gain - min_gain) * plot_height)
            y_pos = max(0, min(plot_height, y_pos))
            
            # Create line
            line = [' '] * plot_width
            line[0] = f"{phi:3d}°"
            line[4] = '│'
            
            # Add gain bar
            for i in range(5, min(5 + y_pos, plot_width)):
                line[i] = '█'
            
            # Add gain value
            gain_str = f"{gain:5.1f}dB"
            for i, char in enumerate(gain_str):
                if 5 + y_pos + i < plot_width:
                    line[5 + y_pos + i] = char
            
            print(''.join(line))
        
        print("  └" + "─" * plot_width)
        print("    Azimuth Angle (degrees)")
        print()

def main():
    eznec_file = "soviet_uaz_4m_whip_45deg.ez"
    nec_output = "soviet_uaz_36MHz.out"
    
    print("Loading antenna geometry...")
    try:
        wires = parse_eznec_file(eznec_file)
        print(f"Loaded {len(wires)} wire segments")
    except FileNotFoundError:
        print(f"Error: {eznec_file} not found")
        return
    
    print("Loading radiation pattern...")
    try:
        pattern = parse_radiation_pattern(nec_output)
        print(f"Loaded {len(pattern)} pattern points")
    except FileNotFoundError:
        print(f"Error: {nec_output} not found")
        pattern = []
    
    print()
    create_ascii_antenna_diagram(wires)
    create_radiation_pattern_plot(pattern)
    
    print("=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print("• Antenna: 4m whip tied down at 45° angle")
    print("• Vehicle: Soviet UAZ-469 style (4.2m × 1.8m)")
    print("• Frequency: 36 MHz (VHF)")
    print("• Ground: Poor to average (0.003 S/m)")
    print("• Expected gain: 5-7 dB (typical for VHF whip)")
    print("• Pattern: Omnidirectional with slight elevation")
    print("• Use: Tactical VHF communications")

if __name__ == "__main__":
    main()
