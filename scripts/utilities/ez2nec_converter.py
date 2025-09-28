#!/usr/bin/env python3
"""
EZNEC to NEC2 Converter
Converts EZNEC format files (.ez) to NEC2 format files (.nec)
"""

import sys
import re
import os

def convert_ez_to_nec(ez_file, nec_file):
    """
    Convert EZNEC file to NEC2 format
    """
    print(f"Converting {ez_file} to {nec_file}")
    
    with open(ez_file, 'r') as f:
        lines = f.readlines()
    
    nec_lines = []
    in_geometry = False
    in_source = False
    in_ground = False
    in_loads = False
    in_frequency = False
    in_radiation = False
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith(';') or line.startswith('EZNEC'):
            continue
            
        # Handle different sections
        if line.startswith('; GEOMETRY'):
            in_geometry = True
            continue
        elif line.startswith('; SOURCE'):
            in_geometry = False
            in_source = True
            continue
        elif line.startswith('; GROUND'):
            in_source = False
            in_ground = True
            continue
        elif line.startswith('; LOADS'):
            in_ground = False
            in_loads = True
            continue
        elif line.startswith('; FREQUENCY'):
            in_loads = False
            in_frequency = True
            continue
        elif line.startswith('; RADIATION'):
            in_frequency = False
            in_radiation = True
            continue
        
        # Process geometry lines (W001, W002, etc.)
        if line.startswith('W') and len(line.split()) >= 9:
            nec_lines.append(convert_wire_line(line))
        
        # Process source lines (SY SRC)
        elif line.startswith('SY SRC'):
            nec_lines.append(convert_source_line(line))
        
        # Process ground lines (GD)
        elif line.startswith('GD'):
            nec_lines.append(convert_ground_line(line))
        
        # Process load lines (LD)
        elif line.startswith('LD'):
            nec_lines.append(convert_load_line(line))
        
        # Process frequency lines (FR)
        elif line.startswith('FR'):
            nec_lines.append(convert_frequency_line(line))
        
        # Process radiation pattern lines (RP)
        elif line.startswith('RP'):
            nec_lines.append(convert_radiation_line(line))
    
    # Write NEC file
    with open(nec_file, 'w') as f:
        f.write('CM Converted from EZNEC format\n')
        f.write('CE\n')
        for line in nec_lines:
            f.write(line + '\n')
        f.write('EN\n')
    
    print(f"Conversion complete: {nec_file}")

def convert_wire_line(line):
    """
    Convert EZNEC wire line to NEC2 format
    EZNEC: W001  -19.75 0.0   0.0   19.75 0.0   0.0   1.9   79
    NEC2:  GW 1 79 -19.75 0.0 0.0 19.75 0.0 0.0 1.9
    """
    parts = line.split()
    if len(parts) < 9:
        return line
    
    # Extract wire number from W001 format
    wire_num = parts[0][1:]  # Remove 'W' prefix
    
    # Convert to NEC2 GW format
    nec_line = f"GW {wire_num} {parts[8]} {parts[1]} {parts[2]} {parts[3]} {parts[4]} {parts[5]} {parts[6]} {parts[7]}"
    return nec_line

def convert_source_line(line):
    """
    Convert EZNEC source line to NEC2 format
    EZNEC: SY SRC  W003  1  1
    NEC2:  GE 1
    """
    parts = line.split()
    if len(parts) >= 4:
        wire_num = parts[2][1:]  # Remove 'W' prefix
        return f"GE {wire_num}"
    return "GE 1"

def convert_ground_line(line):
    """
    Convert EZNEC ground line to NEC2 format
    EZNEC: GD 0 0 0 0 0.005 0.013
    NEC2:  GN 1 0 0 0 0.005 0.013
    """
    parts = line.split()
    if len(parts) >= 7:
        return f"GN 1 {parts[1]} {parts[2]} {parts[3]} {parts[4]} {parts[5]} {parts[6]}"
    return "GN 1 0 0 0 0.005 0.013"

def convert_load_line(line):
    """
    Convert EZNEC load line to NEC2 format
    EZNEC: LD 5 1 1 0 3.7E+07 0
    NEC2:  LD 5 1 1 0 3.7E+07 0
    """
    return line

def convert_frequency_line(line):
    """
    Convert EZNEC frequency line to NEC2 format
    EZNEC: FR 0 1 0 0 8.9 0
    NEC2:  FR 0 1 0 0 8.9 0
    """
    return line

def convert_radiation_line(line):
    """
    Convert EZNEC radiation pattern line to NEC2 format
    EZNEC: RP 0 37 73 1000 0 0 5 10 0 0
    NEC2:  RP 0 37 73 1000 0 0 5 10 0 0
    """
    return line

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 ez2nec_converter.py input.ez output.nec")
        sys.exit(1)
    
    ez_file = sys.argv[1]
    nec_file = sys.argv[2]
    
    if not os.path.exists(ez_file):
        print(f"Error: Input file {ez_file} does not exist")
        sys.exit(1)
    
    convert_ez_to_nec(ez_file, nec_file)

if __name__ == "__main__":
    main()
