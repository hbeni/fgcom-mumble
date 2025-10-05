#!/usr/bin/env python3
"""
Test channel lookup in Mumble server
"""

import sqlite3
import subprocess
import sys

def test_channel_lookup():
    """Test if we can find the channel in the database"""
    
    print("Testing channel lookup in Mumble database...")
    
    try:
        # Connect to database
        conn = sqlite3.connect('/var/lib/mumble-server/fgcom-mumble.sqlite')
        cursor = conn.cursor()
        
        # Check channels
        cursor.execute("SELECT channel_id, name FROM channels ORDER BY channel_id")
        channels = cursor.fetchall()
        
        print("Channels in database:")
        for channel_id, name in channels:
            print(f"  ID {channel_id}: '{name}'")
        
        # Check if fgcom-mumble channel exists
        cursor.execute("SELECT channel_id FROM channels WHERE name = ?", ("fgcom-mumble",))
        result = cursor.fetchone()
        
        if result:
            print(f"✅ Found fgcom-mumble channel with ID: {result[0]}")
        else:
            print("❌ fgcom-mumble channel not found!")
            return False
        
        # Check ACL for the channel
        cursor.execute("SELECT * FROM acl WHERE channel_id = ?", (result[0],))
        acl_entries = cursor.fetchall()
        
        print(f"ACL entries for channel {result[0]}:")
        for entry in acl_entries:
            print(f"  {entry}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_channel_lookup()
    sys.exit(0 if success else 1)
