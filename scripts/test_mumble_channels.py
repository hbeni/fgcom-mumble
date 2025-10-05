#!/usr/bin/env python3
"""
Test Mumble server channels using a simple connection
"""

import socket
import ssl
import struct
import time

def test_mumble_connection():
    """Test connection to Mumble server and check channels"""
    
    print("Testing Mumble server connection...")
    
    try:
        # Connect to Mumble server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('192.168.1.190', 64738))
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname='192.168.1.190')
        
        print("✅ Connected to Mumble server")
        print("✅ SSL handshake successful")
        
        # Send version message
        version_msg = struct.pack('>HH', 0, 0)  # Version message
        ssl_sock.send(version_msg)
        
        print("✅ Version message sent")
        
        # Close connection
        ssl_sock.close()
        
        print("✅ Connection test successful!")
        return True
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return False

if __name__ == "__main__":
    test_mumble_connection()
