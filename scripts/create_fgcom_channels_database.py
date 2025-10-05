#!/usr/bin/env python3
"""
FGcom-mumble Channel Creation Script - Database Method
Creates channels directly in the Mumble server SQLite database
"""

import sys
import os
import sqlite3
import subprocess

def create_fgcom_channels():
    """Create fgcom-mumble channels directly in the database"""
    
    print("FGcom-mumble Channel Creation Script (Database Method)")
    print("=" * 55)
    
    # Database path
    db_path = "/var/lib/mumble-server/fgcom-mumble.sqlite"
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"ERROR: Database not found at {db_path}")
        return False
    
    try:
        # Connect to database
        print(f"Connecting to database: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current channels
        print("Checking existing channels...")
        cursor.execute("SELECT channel_id, name FROM channels ORDER BY channel_id")
        existing_channels = cursor.fetchall()
        
        print("Current channels:")
        for channel_id, name in existing_channels:
            print(f"  {channel_id}: {name}")
        
        # Define channels to create
        channels_to_create = [
            (1, 0, "fgcom-mumble", 1),  # channel_id, parent_id, name, inheritacl
            (2, 0, "fgcom-mumble-admins", 1)  # channel_id, parent_id, name, inheritacl
        ]
        
        # Create channels
        for channel_id, parent_id, name, inheritacl in channels_to_create:
            # Check if channel already exists
            cursor.execute("SELECT channel_id FROM channels WHERE channel_id = ?", (channel_id,))
            if cursor.fetchone():
                print(f"Channel {channel_id} ({name}) already exists, skipping...")
                continue
            
            print(f"Creating channel {channel_id}: {name}")
            cursor.execute("""
                INSERT INTO channels (server_id, channel_id, parent_id, name, inheritacl)
                VALUES (1, ?, ?, ?, ?)
            """, (channel_id, parent_id, name, inheritacl))
            
            print(f"✅ Created channel {channel_id}: {name}")
        
        # Create ACL entries for the channels
        print("Setting up ACL permissions...")
        
        # ACL for fgcom-mumble channel (channel 1)
        acl_entries = [
            # Channel 1 (fgcom-mumble): all users can enter, traverse, speak, whisper, textmessage
            (1, 1, 0, None, None, 1, 1, 0, 0),  # @all: +enter, +traverse, +speak, +whisper, +textmessage
            # Channel 2 (fgcom-mumble-admins): all users can enter and traverse, admins can speak/whisper/textmessage
            (1, 2, 0, None, None, 1, 1, 0, 0),  # @all: +enter, +traverse
            (1, 2, 1, None, "admin", 1, 1, 0, 0),  # @admin: +speak, +whisper, +textmessage
        ]
        
        for server_id, channel_id, priority, user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv in acl_entries:
            cursor.execute("""
                INSERT INTO acl (server_id, channel_id, priority, user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (server_id, channel_id, priority, user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv))
        
        print("✅ ACL permissions configured")
        
        # Commit changes
        conn.commit()
        print("✅ Database changes committed")
        
        # Verify channels were created
        print("\nVerifying channels...")
        cursor.execute("SELECT channel_id, name FROM channels ORDER BY channel_id")
        final_channels = cursor.fetchall()
        
        print("Final channels:")
        for channel_id, name in final_channels:
            print(f"  {channel_id}: {name}")
        
        # Close connection
        conn.close()
        
        print("\n✅ SUCCESS: All channels created successfully!")
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Failed to create channels: {e}")
        return False

def main():
    """Main function"""
    print("Starting FGcom-mumble channel creation...")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        return 1
    
    # Check if Mumble server is running
    print("Checking if Mumble server is running...")
    try:
        result = subprocess.run(['systemctl', 'is-active', 'mumble-server'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("ERROR: Mumble server is not running!")
            print("Please start the Mumble server first:")
            print("  sudo systemctl start mumble-server")
            return 1
        else:
            print("Mumble server is running")
    except Exception as e:
        print(f"Warning: Could not check Mumble server status: {e}")
    
    # Create the channels
    success = create_fgcom_channels()
    
    if success:
        print("\n🎉 SUCCESS: FGcom-mumble channels created successfully!")
        print("The following channels are now available:")
        print("  - fgcom-mumble (ID: 1)")
        print("  - fgcom-mumble-admins (ID: 2)")
        print("\nYou can now start the FGcom-mumble bots.")
        return 0
    else:
        print("\n❌ FAILED: Could not create FGcom-mumble channels")
        print("Please check the error messages above and try again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
