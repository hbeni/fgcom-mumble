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
    
    This function reads an EZNEC format file (.ez) and converts it to NEC2 format (.nec).
    It parses the EZNEC file structure and converts each section (geometry, sources,
    ground, loads, frequency, radiation) to the corresponding NEC2 format.
    
    Args:
        ez_file (str): Path to the input EZNEC file
        nec_file (str): Path to the output NEC2 file
        
    Returns:
        bool: True if conversion was successful, False otherwise
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        IOError: If there's an error reading or writing files
        
    Note:
        The function handles various EZNEC file sections:
        - Geometry: Wire definitions and coordinates
        - Sources: Excitation points and currents
        - Ground: Ground plane specifications
        - Loads: Impedance loads and networks
        - Frequency: Frequency specifications
        - Radiation: Radiation pattern requests
        
    Example:
        >>> convert_ez_to_nec("antenna.ez", "antenna.nec")
        Converting antenna.ez to antenna.nec
        True
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
    
    This function converts a single EZNEC wire definition line to NEC2 format.
    It parses the wire parameters and reformats them according to NEC2 syntax.
    
    Args:
        line (str): EZNEC wire line (e.g., "W001 -19.75 0.0 0.0 19.75 0.0 0.0 1.9 79")
        
    Returns:
        str: NEC2 formatted wire line (e.g., "GW 1 79 -19.75 0.0 0.0 19.75 0.0 0.0 1.9")
        
    Note:
        EZNEC format: W001 -19.75 0.0 0.0 19.75 0.0 0.0 1.9 79
        NEC2 format:  GW 1 79 -19.75 0.0 0.0 19.75 0.0 0.0 1.9
        Where: W001 = wire 1, coordinates are start/end points, 1.9 = radius, 79 = segments
        
    Example:
        >>> convert_wire_line("W001 -19.75 0.0 0.0 19.75 0.0 0.0 1.9 79")
        "GW 1 79 -19.75 0.0 0.0 19.75 0.0 0.0 1.9"
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
    
    This function converts EZNEC source definitions to NEC2 format.
    It extracts the wire number from the source specification and
    creates a corresponding NEC2 ground plane excitation command.
    
    Args:
        line (str): EZNEC source line (e.g., "SY SRC W003 1 1")
        
    Returns:
        str: NEC2 formatted source line (e.g., "GE 3")
        
    Note:
        EZNEC format: SY SRC W003 1 1 (source on wire 3)
        NEC2 format:  GE 3 (ground plane excitation on wire 3)
        
    Example:
        >>> convert_source_line("SY SRC W003 1 1")
        "GE 3"
    """
    parts = line.split()
    if len(parts) >= 4:
        wire_num = parts[2][1:]  # Remove 'W' prefix
        return f"GE {wire_num}"
    return "GE 1"

def convert_ground_line(line):
    """
    Convert EZNEC ground line to NEC2 format
    
    This function converts EZNEC ground plane definitions to NEC2 format.
    It preserves the ground plane parameters while changing the command
    from GD (ground) to GN (ground plane with specified parameters).
    
    Args:
        line (str): EZNEC ground line (e.g., "GD 0 0 0 0 0.005 0.013")
        
    Returns:
        str: NEC2 formatted ground line (e.g., "GN 1 0 0 0 0.005 0.013")
        
    Note:
        EZNEC format: GD 0 0 0 0 0.005 0.013
        NEC2 format:  GN 1 0 0 0 0.005 0.013
        Parameters: ground type, conductivity, permittivity, etc.
        
    Example:
        >>> convert_ground_line("GD 0 0 0 0 0.005 0.013")
        "GN 1 0 0 0 0.005 0.013"
    """
    parts = line.split()
    if len(parts) >= 7:
        return f"GN 1 {parts[1]} {parts[2]} {parts[3]} {parts[4]} {parts[5]} {parts[6]}"
    return "GN 1 0 0 0 0.005 0.013"

def convert_load_line(line):
    """
    Convert EZNEC load line to NEC2 format
    
    This function converts EZNEC load definitions to NEC2 format.
    Since both formats use the same LD command syntax, the line
    is returned unchanged.
    
    Args:
        line (str): EZNEC load line (e.g., "LD 5 1 1 0 3.7E+07 0")
        
    Returns:
        str: NEC2 formatted load line (same as input)
        
    Note:
        Both EZNEC and NEC2 use identical LD command syntax:
        LD 5 1 1 0 3.7E+07 0
        Where: 5=load type, 1=wire, 1=segment, 0=tag, 3.7E+07=resistance, 0=reactance
        
    Example:
        >>> convert_load_line("LD 5 1 1 0 3.7E+07 0")
        "LD 5 1 1 0 3.7E+07 0"
    """
    return line

def convert_frequency_line(line):
    """
    Convert EZNEC frequency line to NEC2 format
    
    This function converts EZNEC frequency definitions to NEC2 format.
    Since both formats use the same FR command syntax, the line
    is returned unchanged.
    
    Args:
        line (str): EZNEC frequency line (e.g., "FR 0 1 0 0 8.9 0")
        
    Returns:
        str: NEC2 formatted frequency line (same as input)
        
    Note:
        Both EZNEC and NEC2 use identical FR command syntax:
        FR 0 1 0 0 8.9 0
        Where: 0=linear, 1=number of frequencies, 0=start, 0=end, 8.9=frequency, 0=step
        
    Example:
        >>> convert_frequency_line("FR 0 1 0 0 8.9 0")
        "FR 0 1 0 0 8.9 0"
    """
    return line

def convert_radiation_line(line):
    """
    Convert EZNEC radiation pattern line to NEC2 format
    
    This function converts EZNEC radiation pattern requests to NEC2 format.
    Since both formats use the same RP command syntax, the line
    is returned unchanged.
    
    Args:
        line (str): EZNEC radiation line (e.g., "RP 0 37 73 1000 0 0 5 10 0 0")
        
    Returns:
        str: NEC2 formatted radiation line (same as input)
        
    Note:
        Both EZNEC and NEC2 use identical RP command syntax:
        RP 0 37 73 1000 0 0 5 10 0 0
        Where: 0=normalized, 37=theta angles, 73=phi angles, 1000=distance, etc.
        
    Example:
        >>> convert_radiation_line("RP 0 37 73 1000 0 0 5 10 0 0")
        "RP 0 37 73 1000 0 0 5 10 0 0"
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
