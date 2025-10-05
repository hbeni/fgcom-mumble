#!/usr/bin/env python3
"""
Test bot channel lookup by creating a simple bot that tries to get the channel
"""

import subprocess
import sys
import time

def test_bot_channel():
    """Test if a simple bot can get the channel"""
    
    print("Testing bot channel lookup...")
    
    # Create a simple test bot script
    test_bot = """
dofile("fgcom-sharedFunctions.inc.lua")

local client = mumble.client()
client:connect("192.168.1.190", 64738, "testbot", "testbot.pem", "testbot.key")

client:hook("OnServerSync", function(client, event)
    print("Server sync completed")
    
    -- Try to get channel by name
    local ch = client:getChannel("fgcom-mumble")
    if ch then
        print("✅ Channel found by name: " .. ch:getName())
    else
        print("❌ Channel not found by name")
    end
    
    -- Try to get channel by ID
    local ch2 = client:getChannel(1)
    if ch2 then
        print("✅ Channel found by ID: " .. ch2:getName())
    else
        print("❌ Channel not found by ID")
    end
    
    -- List all channels
    local channels = client:getChannels()
    print("All channels:")
    for id, channel in pairs(channels) do
        print("  ID " .. id .. ": " .. channel:getName())
    end
    
    client:disconnect()
    os.exit(0)
end)

mumble.loop()
"""
    
    # Write test bot to file
    with open('/tmp/test_bot.lua', 'w') as f:
        f.write(test_bot)
    
    try:
        # Run the test bot
        result = subprocess.run(['cd /home/haaken/github-projects/fgcom-mumble/server && luajit /tmp/test_bot.lua'], 
                              shell=True, capture_output=True, text=True, timeout=10)
        
        print("Test bot output:")
        print(result.stdout)
        if result.stderr:
            print("Test bot errors:")
            print(result.stderr)
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("Test bot timed out")
        return False
    except Exception as e:
        print(f"Test bot failed: {e}")
        return False

if __name__ == "__main__":
    success = test_bot_channel()
    sys.exit(0 if success else 1)
