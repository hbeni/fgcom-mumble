#
# FGCom-mumble addon radios logic
#
# @author Benedikt Hallinger, 2021
# @author Colin Geniet, 2021


# FGCom-mumble nasal radios objects task is to make some minor checks and changes
# to the properties transmitted to the FGCom-mumble plugin.
# Notably, they make sure that no value is transmitted for unused radios.
# ADF radio objects also handle the RDF logic.

var GenericRadio = {
    # Parameter: root: the radio property root (e.g. /instrumentation/comm[i]), as a property node.
    new: func(root) {
        var r = { parents: [GenericRadio], root: root, };
        r.init();
        r.name = "XXX" ~ (root.getIndex() + 1);
        return r;
    },

    # initialized by addon-main.nas after load to grant access to the global settings
    globalSettings: nil,
    setGlobalSettings: func(p) {
        GenericRadio.globalSettings = p;
        GenericRadio.outputRootNode = props.globals.getNode(p.settingsRootPath ~ "/output", 1);
    },

    # Node base where the output should go (initialized by setGlobalSettings() via addon-main.nas)
    outputRootNode: nil,


    fgcomPacketStr: nil, # node for udp output
    fields2props: {},    # map packet field names to properties

    init: func {
        # Radio frequencies are initialized by C++ code even for aircrafts which do not use the radio.
        # To avoid transmitting the frequency for an unused radio (which would make it functional
        # in the fgcom-mumble plugin), test if the 'operable' property exist.
        # It is created by the C++ instrument code, if the radio is used.
        me.operable = me.root.getNode("operable");
        me.is_used = (me.operable != nil);
        print("Addon FGCom-mumble   radio "~(me.is_used?"using:   ":"skipped: ")~me.root.getPath());

        # Property subtree for fgcom-mumble properties.
        me.fgcom_root        = me.root.getNode("fgcom-mumble", 1);
        me.fgcom_freq_mhz    = me.fgcom_root.getNode("selected-mhz", 1);
        me.fgcom_vol         = me.fgcom_root.getNode("volume", 1);
        me.fgcom_pbt         = me.fgcom_root.getNode("operable", 1); me.fgcom_pbt.setBoolValue(1);
        me.fgcom_root.setValue("is-used", me.is_used);

        # Hash containing all listeners / timers / aliases, for the destructor.
        me.listeners = {};
        me.timers = {};
        me.aliases = {};


        # "operable" is a tied property, so we need a polling mechanism updating it
        me.timers.operable_poller = maketimer(1.0, me, 
            func{
#                print("Addon FGCom-mumble   polling operable: "~me.root.getPath()~"/operable");
                me.fgcom_pbt.setBoolValue(getprop(me.root.getPath()~"/operable"));
            }
        );
        me.timers.operable_poller.start();

        # Update the udp string once a prop changes;
        # for this register a new distinct output subnode
        if (me.is_used) {
            me.fgcomPacketStr = me.outputRootNode.addChild("COM", 1);
            print("Addon FGCom-mumble     registered output node as "~me.fgcomPacketStr.getPath());
            me.fields2props = {
                # Map the fgcom-mumble protocol fields to properties
                FRQ:     me.fgcom_root.getPath() ~ "/selected-mhz",
                CWKHZ:   me.root.getPath()       ~ "/frequencies/selected-channel-width-khz",
                PBT:     me.fgcom_root.getPath() ~ "/operable",
                PTT:     me.root.getPath()       ~ "/ptt",
                VOL:     me.fgcom_root.getPath() ~ "/volume",
                PWR:     me.root.getPath()       ~ "/tx-power",
                SQC:     me.root.getPath()       ~ "/cutoff-signal-quality",
                RDF:     me.fgcom_root.getPath() ~ "/rdf-enabled",
                PUBLISH: me.fgcom_root.getPath() ~ "/publish",
            };
            foreach (var f; keys(me.fields2props)) {
#                print("Addon FGCom-mumble     add listener for " ~ f ~ " ("~me.fields2props[f]~")");
                me.listeners["upd_udp_field:"~f] = setlistener(me.fields2props[f], func { me.updatePacketString(); }, 0, 0);
            }
            me.listeners["forceEchoTest"] = setlistener(GenericRadio.globalSettings.forceEchoTestNode, func { me.updatePacketString(); }, 0, 0);
            me.updatePacketString();
        }
    },

    del: func {
        foreach (var l; keys(me.listeners)) removelistener(me.listeners[l]);
        foreach (var t; keys(me.timers)) me.timers[t].stop();
        foreach (var a; keys(me.aliases)) me.aliases[a].unalias();
        me.listeners = {};
        me.timers = {};
        me.aliases = {};
        fgcomPacketStr.setValue("");
    },

    updatePacketString: func {
        # Generates the FGCom-mumble udp packet string for this radio
        if (me.fgcomPacketStr == nil) return;

        # stringify the props, fields are only added if the prop exists
        var fields = [];
        foreach (var f; keys(me.fields2props)) {
            var propval = getprop(me.fields2props[f]);

            # If the global ECHOTEST mode was requested, force radios FRQ field output to the echotest frequency
            if (f == "FRQ" and GenericRadio.globalSettings.forceEchoTestNode.getBoolValue()) propval = "910.00";
            if (f == "PBT" and GenericRadio.globalSettings.forceEchoTestNode.getBoolValue()) propval = "1";

            # because of float type characteristics, sometimes values are returned like "127.549999999", and rounding fixes that
            if (substr(sprintf("%s",propval), -3) == "999") {
                propval = sprintf("%.4f", propval);
            }

#            print("Addon FGCom-mumble     generate udp packet field: "~f~ " ("~(propval != nil? propval:"<nil>")~")");
            if (propval != nil) append(fields, "COM" ~ me.fgcomPacketStr.getIndex() ~ "_" ~ f ~ "=" ~ propval);
        }

        me.fgcomPacketStr.setValue(string.join(",", fields));
    },
};

var COM = {
    new: func(root) {
        var r = { parents: [COM, GenericRadio.new(root)], };
        r.name = "COM" ~ (root.getIndex() + 1);
        r.init();
        return r;
    },

    init: func {
        me.vol       = me.root.getNode("volume", 1);
        me.freq_mhz  = me.root.getNode("frequencies/selected-mhz", 1);

        # Only initialize properties if the radio is used.
        if (me.is_used) {
            me.listeners.frq = setlistener(me.freq_mhz.getPath(), func { me.recalcFrequency(); }, 1, 0);
            me.listeners.vol = setlistener(me.vol.getPath(), func { me.recalcVolume(); }, 1, 0);
        }
    },

    recalcVolume: func {
        me.fgcom_vol.setValue(me.vol.getValue());
    },

    recalcFrequency: func {
        var f = me.freq_mhz.getValue();
        me.fgcom_freq_mhz.setValue(f);
    },
};


#
# FGCom-mumble ADF logic
#
var ADF = {
    # Minimum RDF signal quality to activate ADF.
    rdf_quality_threshold: 0.2,
    # Update period for RDF, seconds
    rdf_update_period: 1,

    new: func(root) {
        var r = { parents: [ADF, GenericRadio.new(root)], };
        r.name = "ADF" ~ (root.getIndex() + 1);
        r.init();
        return r;
    },

    init: func {
        # FG ADF properties
        me.vol               = me.root.getNode("volume-norm", 1);
        me.ident_aud         = me.root.getNode("ident-audible", 1);
        me.mode              = me.root.getNode("mode", 1);
        me.freq_khz          = me.root.getNode("frequencies/selected-khz", 1);
        me.indicated_bearing = me.root.getNode("indicated-bearing-deg", 1);

        # Properties for plugin RDF signals
        # Input
        me.fgcom_rdf_bearing = me.fgcom_root.getNode("direction-deg", 1);
        me.fgcom_rdf_quality = me.fgcom_root.getNode("quality", 1);

        # Output
        me.fgcom_rdf_enabled = me.fgcom_root.getNode("rdf-enabled", 1);
        me.fgcom_publish     = me.fgcom_root.getNode("publish", 1);

        # Only initialize properties / listeners / timers if the radio is used.
        if (me.is_used) {
            me.fgcom_rdf_enabled.setValue(1);
            me.fgcom_publish.setValue(0);

            # Volume update
            me.listeners.vol =        setlistener(me.vol, func { me.recalcVolume(); }, 1, 0);
            me.listeners.indent_aud = setlistener(me.ident_aud, func { me.recalcVolume(); }, 0, 0);
            # Frequency update
            me.listeners.freq =       setlistener(me.freq_khz, func { me.recalcFrequency(); }, 1, 0);

            # RDF update loop
            if (me.fgcom_rdf_enabled.getBoolValue()) {
                me.has_rdf_signal = 0;
                me.timers.rdf_timer = maketimer(me.rdf_update_period, me, me.rdf_loop);
                me.timers.rdf_timer.start();
            }
        }
    },

    recalcVolume: func {
        # Reception depends on ident-audible and the volume knob
        # ident-audible is supposed to be set from the audio panel.
        if (me.ident_aud.getBoolValue()) {
            me.fgcom_vol.setValue(me.vol.getValue() or 0);
        } else {
            me.fgcom_vol.setValue(0);
        }
    },

    recalcFrequency: func {
        var freq = me.freq_khz.getValue();
        if (freq == nil) {
            me.fgcom_freq_mhz.clearValue();
            return
        }

        var freq_num = num(freq);
        if (freq_num == nil) {
            # Frequency can not be converted to a number.
            # Do not attempt KHz -> MHz conversion
            me.fgcom_freq_mhz.setValue(freq);
        } else {
            me.fgcom_freq_mhz.setValue(freq_num / 1000.0);
        }
    },

    # Receive RDF data from plugin output.
    #
    # This function is designed to be called often (for each packet).
    # It simply memorises the data, which is read by the RDF logic runs at a lower rate.
    set_rdf_data: func(direction, quality) {
#        debug.dump(["DBG ADF set_rdf_data", [direction, quality]]);
        me.fgcom_rdf_bearing.setValue(direction);
        me.fgcom_rdf_quality.setValue(quality);
    },

    clear_rdf_data: func {
        me.fgcom_rdf_bearing.clearValue();
        me.fgcom_rdf_quality.clearValue()
    },

    rdf_loop: func {
        if (me.operable.getBoolValue()) {
            var direction = me.fgcom_rdf_bearing.getValue();
            var quality = me.fgcom_rdf_quality.getValue();
#            debug.dump(["DBG ADF loop", [direction, quality], me.mode.getValue()]);
            if (direction != nil and quality != nil and quality > me.rdf_quality_threshold and me.mode.getValue() == "adf") {
                # Has signal, and is in the correct mode: animate the needle
                me.has_rdf_signal = 1;
                interpolate(me.indicated_bearing, direction, 1);
            } else {
                if (me.has_rdf_signal) {
                    # signal lost, reset needle
                    me.has_rdf_signal = 0;
                    interpolate(me.indicated_bearing, 90, 1);
                }
            }
        }

        # Clear input fields to denote we have fully processed this dataset.
        # If no update from FGCom-mumble occurs, the input remains empty, so we can detect lost signals
        me.clear_rdf_data();
    },
};


# Radios objects, indexed by their index in protocol fgcom-mumble.xml (X for COMX).
var COM_radios = {};
var ADF_radios = {};

var create_radios = func {
    # Walk all com entries and create instances
    var i = 1;
    foreach (r; props.globals.getNode("/instrumentation/").getChildren("comm") ) {
        COM_radios[i] = COM.new(r);
        if (COM_radios[i].is_used) i = i + 1;
    }

    # Walk all ADF entries and create isntances
    foreach (r; props.globals.getNode("/instrumentation/").getChildren("adf") ) {
        ADF_radios[i] = ADF.new(r);
        if (ADF_radios[i].is_used) i = i + 1;
    }
}

var update_radios = func {
    foreach (var i; keys(COM_radios)) COM_radios[i].updatePacketString();
    foreach (var i; keys(ADF_radios)) ADF_radios[i].updatePacketString();
}


var destroy_radios = func {
    foreach (var i; keys(COM_radios)) COM_radios[i].del();
    foreach (var i; keys(ADF_radios)) ADF_radios[i].del();
    COM_radios = {};
    ADF_radios = {};
}

var get_radios = func {
    var r = [];
    foreach (var i; keys(COM_radios)) append(r, COM_radios[i]);
    foreach (var i; keys(ADF_radios)) append(r, ADF_radios[i]);
    return r;
}


#
# Function to read RDF data sent by the plugin.
#
# All RDF data is sent through the same properties.
# This function simply parses it, and redistributes it to the correct ADF.

# Input properties (initialized in start_rdf)
var fgcom_rdf_input_node      = nil;
var fgcom_rdf_input_radio     = nil;
var fgcom_rdf_input_callsign  = nil;
var fgcom_rdf_input_direction = nil;
var fgcom_rdf_input_quality   = nil;

var rdf_data_callback = func {
    var radio     = fgcom_rdf_input_radio.getValue();
    var direction = fgcom_rdf_input_direction.getValue();
    var quality   = fgcom_rdf_input_quality.getValue();
#    debug.dump(["DBG ADF rdf_data_callback", [radio, direction, quality]]);

    if (radio == "" or direction == "" or quality == "") return; # No data

    # Read input data
    # Format is this: "RDF:CS_TX=NDB:TEST,FRQ=0.342,DIR=11.567468,VRT=2.299456,QLY=0.999998,ID_RX=3"
    # (ID_RX is the radio index in the mumble plugin)
    var radio     = num(split("=", radio)[1]);
    var direction = split("=", direction)[1];
    var quality   = split("=", quality)[1];

    # Send to corresponding ADF
#    debug.dump(["DBG ADF rdf_data_callback", [radio, ADF_radios]]);
#    debug.dump(["DBG ADF rdf_data_callback", [radio, ["used", ADF_radios[radio].is_used]]]);
    if (radio != nil and contains(ADF_radios, radio) and ADF_radios[radio].is_used) {
        # Found corresponding ADF radio, send the signal to it.
        ADF_radios[radio].set_rdf_data(direction, quality);
    }
}

# Listener to receive RDF data.
# The listener is placed on the property corresponding to the last field of the protocol.
# So when this property gets updated, it means a full RDF signal info has just been received.

var rdf_data_listener = nil;

var start_rdf = func(rdfInputNode) {
    if (rdf_data_listener != nil) return;

    # Init RDF input nodes
    print("Addon FGCom-mumble start RDF input handling using "~rdfInputNode.getPath());
    fgcom_rdf_input_radio     = rdfInputNode.initNode("radio", "");
    fgcom_rdf_input_callsign  = rdfInputNode.initNode("callsign", "");
    fgcom_rdf_input_direction = rdfInputNode.initNode("direction", "");
    fgcom_rdf_input_quality   = rdfInputNode.initNode("quality", "");
    
    rdf_data_listener = setlistener(fgcom_rdf_input_radio, func {
        # call() to set the local namespace.
        call(rdf_data_callback, [], nil, FGComMumble_radios);
    });
}

var stop_rdf = func {
    if (rdf_data_listener == nil) return;
    removelistener(rdf_data_listener);
    rdf_data_listener = nil;
}
