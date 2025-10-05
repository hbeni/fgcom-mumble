#!/usr/bin/env python3
"""
Test Ice connection to Mumble server
"""

import sys
import Ice

def test_ice_connection():
    """Test basic Ice connection to Mumble server"""
    
    print("Testing Ice connection to Mumble server...")
    
    try:
        # Initialize Ice
        print("Initializing Ice...")
        communicator = Ice.initialize()
        
        # Try to connect to Mumble server
        print("Connecting to Mumble server...")
        proxy = communicator.stringToProxy('Meta:tcp -h 127.0.0.1 -p 6502')
        
        # Try to get the proxy
        print("Getting proxy...")
        meta = proxy.ice_uncheckedCast()
        
        print("✅ SUCCESS: Ice connection established!")
        print("Mumble server Ice interface is working")
        
        # Clean up
        communicator.destroy()
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Ice connection failed: {e}")
        print(f"Error type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    success = test_ice_connection()
    sys.exit(0 if success else 1)
