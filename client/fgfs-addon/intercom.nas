#
# FGCom-mumble addon intercom logic
#
# @author Benedikt Hallinger, 2023


# FGFS supports copilot operations. For that, there is a basic copilot module to be
# implemented by the aircraft.
#
# To simulate some kind of intercom, and to give the participants a channel to speak
# without transmitting on the radio, we establish an intercom channel. This is achieved
# by creating a "virtual" radio node with a unique dynamic channel name ("frequency").
#
# The channel name is built from the copilot module: "IC:<plane1ID>-<plane2ID>:<channel>",
# where <planeID> are the alphabetically sorted pilot/copilot callsign
# and <channel> something like "crew" or "pax", depending on the planes settings.
#
# Things like channel isolation and multi channel operations can then be
# controlled by the plane by creating more IC devices and adjust channel names.

var IntercomDevice = {
    channel_prefix: "PHONE:IC",
    fgcomPacketStr: nil,
    is_used:        0,
    
    # Parameter: root: the intercom property root tree, as a property node.
    new: func(root) {
        var r = { parents: [IntercomDevice], root: root, };
        r.init();
        r.name = "IC" ~ (root.getIndex() + 1);
        return r;
    },
    
    init: func() {
        print("Addon FGCom-mumble   created new intercom device subnode (" ~ me.root.getPath() ~ ")");
        me.root.setValue("channel", me.root.getIndex() + 1);
        me.root.setValue("volume",           1.0);
        me.root.setBoolValue("operable",     1);
        me.root.setBoolValue("ptt",          0);
        me.root.setBoolValue("is-used",      0);
        me.root.setValue("connected-callsigns",   "");
                
        # Hash containing all listeners / timers / aliases, for the destructor.
        me.listeners = {};
        me.timers    = {};
        me.aliases   = {};
        
        # Register a common output root node, so the normal radio code will pickup the changes
        # (for this to work, the radio code already has to bee initialized)
        me.fgcomPacketStr = FGComMumble_radios.GenericRadio.outputRootNode.addChild("COM", 1);
        me.fgcomPacketStr.setValue("");
        
        # Register some listeners to trigger the UPD field update for this intercom
        me.listeners.freq = setlistener(me.root.getPath()~"/channel",             func { me.updatePacketString(); }, 0, 0);
        me.listeners.oper = setlistener(me.root.getPath()~"/operable",            func { me.updatePacketString(); }, 0, 0);
        me.listeners.vol  = setlistener(me.root.getPath()~"/volume",              func { me.updatePacketString(); }, 0, 0);
        me.listeners.ptt  = setlistener(me.root.getPath()~"/ptt",                 func { me.updatePacketString(); }, 0, 0);
        me.listeners.conn = setlistener(me.root.getPath()~"/connected-callsigns", func { me.updatePacketString(); }, 0, 0);
        
    },
    
    del: func {
        foreach (var l; keys(me.listeners)) removelistener(me.listeners[l]);
        foreach (var t; keys(me.timers)) me.timers[t].stop();
        foreach (var a; keys(me.aliases)) me.aliases[a].unalias();
        me.listeners = {};
        me.timers    = {};
        me.aliases   = {};
        fgcomPacketStr.setValue("");
    },
    
    # Establish intercom connection.
    # param is sorted vector of pilot and copilot callsigns: ["TEST1", "TEST2"]
    isConnected: 0,
    connect: func(connection) {
        me.root.setBoolValue("is-used", 1);
        me.is_used = 1;
        me.isConnected = 1;
        me.root.setValue("connected-callsigns", string.join("-", connection));
        print("Addon FGCom-mumble     connected "~me.name~" to "~me.getFQChannelName());
    },
    
    # Remove connection for Intercom
    disconnect: func() {
        print("Addon FGCom-mumble     disconnected "~me.name~" from "~me.getFQChannelName());
        me.root.setValue("connected-callsigns", "");
        me.root.setBoolValue("is-used", 0);
        me.is_used = 0;
        me.isConnected = 0;
    },
    
    # Generate the fully qualified fgcom channel name
    getFQChannelName: func() {
        var cs = me.root.getValue("connected-callsigns");
        
        if (cs) {
            return me.channel_prefix ~ ":"
                ~ me.root.getValue("connected-callsigns") ~ ":"
                ~ me.root.getValue("channel");
        } else {
            return "<del>";  # deregister radio if unused
        }
    },
    
    updatePacketString: func {
        # Generates the FGCom-mumble udp packet string for this radio
        if (me.fgcomPacketStr == nil) return;
        
        var fields = [];
        var comidx = me.fgcomPacketStr.getIndex();
        if (me.root.getValue("is-used") and me.isConnected) {
#            print("Addon FGCom-mumble      processing IC "~me.root.getPath());
            
            append(fields, "COM" ~ comidx ~ "_FRQ="~me.getFQChannelName());
            append(fields, "COM" ~ comidx ~ "_PTT="~me.root.getValue("ptt"));
            append(fields, "COM" ~ comidx ~ "_VOL="~me.root.getValue("volume"));
            append(fields, "COM" ~ comidx ~ "_PBT="~me.root.getValue("operable"));
            
        } else {
#            print("Addon FGCom-mumble      skipping IC "~me.root.getPath());
        }
        
        me.fgcomPacketStr.setValue(string.join(",", fields));
    }
};


var IntercomSystem = {
    copilotWatchdog_checkIntervall: 5,  # how often should we check for a new connection? (in secs)
    
    # Parameter: root: the intercom system property root tree, as a property node.
    new: func(root) {
        var r = { parents: [IntercomSystem], root: root, };
        r.init();
        return r;
    },
    
    init: func() {
        # Hash containing all listeners / timers / aliases, for the destructor.
        me.listeners = {};
        me.timers    = {};
        me.aliases   = {};
        
        me.add_intercom_device();  # add default intercom device
        
        # Add a watchdog that periodically checks if we are connected in the copilot module.
        # If so, establish the channel and COM device settings
        me.timers.copilotWatchdog = maketimer(me.copilotWatchdog_checkIntervall, me, me.copilotWatchdog);
        me.timers.copilotWatchdog.start();
    },
    
    del: func {
        foreach (var l; keys(me.listeners)) removelistener(me.listeners[l]);
        foreach (var t; keys(me.timers)) me.timers[t].stop();
        foreach (var a; keys(me.aliases)) me.aliases[a].unalias();
        me.listeners = {};
        me.timers    = {};
        me.aliases   = {};
    },
    
    
    devices: [],
    add_intercom_device: func() {
        var new_device = IntercomDevice.new(me.root.getChild("IC", size(me.devices), 1));
        append(me.devices, new_device);
        return new_device;
    },
    
    # Loop function to check if we are connected to a pilot/copilot connection.
    # If so, activate the intercom handling/channel
    connection_established: 0,
    copilotWatchdog: func() {
#        print("Addon FGCom-mumble   copilot module watchdog checking connection state");
        var connection = me.getPilotCopilotConnection();
        
        if (connection and !me.connection_established) {
            # New connection detected
            print("Addon FGCom-mumble     copilot module watchdog detected new connection");
            me.connection_established = 1;
            me.devices[0].connect(connection);
            
            me.updateCombar();
        }
        
        if (!connection and me.connection_established) {
            # Established connection broke down
            print("Addon FGCom-mumble     copilot module watchdog detected disconnect");
            me.connection_established = 0;
            me.devices[0].disconnect();
            
            me.updateCombar();
        }
    },
    
    # Check connection state.
    # returns nil if not connected,
    # otherwise sorted vector of pilot and copilot callsigns
    getPilotCopilotConnection: func() {
        var remote_callsign = sprintf("%s", getprop("/sim/remote/pilot-callsign"));
        var local_callsign  = sprintf("%s", getprop("/sim/multiplay/callsign"));
        if (local_callsign and remote_callsign) {
            return sort([local_callsign,remote_callsign], func(a,b) cmp(a,b));
        } else {
            return nil;
        }
    },
    
    # If combar is currently open, close and reopen it, so the dialog updates the buttons
    updateCombar: func() {
        if (FGComMumble_combar.combar.dialogOpened) {
            FGComMumble_combar.combar.dlgWindow.del();
            FGComMumble_combar.combar.show();
        }
    },
};


# Global instance, initialized by addon-main.nas
var intercom_system = nil;
