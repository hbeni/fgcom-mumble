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
        return r;
    },

    init: func {
        # Radio frequencies are initialized by C++ code even for aircrafts which do not use the radio.
        # To avoid transmitting the frequency for an unused radio (which would make it functional
        # in the fgcom-mumble plugin), test if the 'operable' property exist.
        # It is created by the C++ instrument code, if the radio is used.
        me.operable = me.root.getNode("operable");
        me.is_used = (me.operable != nil);
        print("Addon FGCom-mumble   radio "~(me.is_used?"using  ":"skipped")~": "~me.root.getPath());

        # Property subtree for fgcom-mumble properties.
        me.fgcom_root        = me.root.getNode("fgcom-mumble", 1);
        me.fgcom_freq_mhz    = me.fgcom_root.getNode("selected-mhz", 1);
        me.fgcom_vol         = me.fgcom_root.getNode("volume", 1);
        me.fgcom_root.setValue("is-used", me.is_used);

        # Hash containing all listeners / timers / aliases, for the destructor.
        me.listeners = {};
        me.timers = {};
        me.aliases = {};
    },

    del: func {
        foreach (var l; keys(me.listeners)) removelistener(me.listeners[l]);
        foreach (var t; keys(me.timers)) me.timers[t].stop();
        foreach (var a; keys(me.aliases)) me.aliases[a].unalias();
        me.listeners = {};
        me.timers = {};
        me.aliases = {};
    },
};

var COM = {
    new: func(root) {
        var r = { parents: [COM, GenericRadio.new(root)], };
        r.init();
        return r;
    },

    init: func {
        me.vol       = me.root.getNode("volume", 1);
        me.freq_mhz  = me.root.getNode("frequencies/selected-mhz", 1);
        me.ptt       = me.root.getNode("ptt", 1);
        me.fgcom_ptt = me.fgcom_root.getNode("ptt", 1);

        # Only initialize properties if the radio is used.
        if (me.is_used) {
            # Volume/frequency/ptt are transmitted as is if the radio is used, so simply alias the properties.
            me.fgcom_vol.alias(me.vol);
            me.fgcom_freq_mhz.alias(me.freq_mhz);
            me.fgcom_ptt.alias(me.ptt);
            # Aliased properties are memorized for the destructor.
            me.aliases.fgcom_vol = me.fgcom_vol;
            me.aliases.fgcom_freq_mhz = me.fgcom_vol;
            me.aliases.fgcom_ptt = me.fgcom_vol;
        }
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

# Number of radios, and their offset in protocol file fgcom-mumble.xml.
var n_COM = 3;
var COM_offset = 1;
var n_ADF = 2;
var ADF_offset = 4;

var create_radios = func {
    for (var i=0; i<n_COM; i+=1) {
        if (contains(COM_radios, i+COM_offset)) continue;
        COM_radios[i+COM_offset] = COM.new(props.globals.getNode("instrumentation/comm["~i~"]", 1));
    }
    for (var i=0; i<n_ADF; i+=1) {
        if (contains(ADF_radios, i+ADF_offset)) continue;
        ADF_radios[i+ADF_offset] = ADF.new(props.globals.getNode("instrumentation/adf["~i~"]", 1));
    }
}

var destroy_radios = func {
    foreach (var i; keys(COM_radios)) COM_radios[i].del();
    foreach (var i; keys(ADF_radios)) ADF_radios[i].del();
    COM_radios = {};
    ADF_radios = {};
}


#
# Function to read RDF data sent by the plugin.
#
# All RDF data is sent through the same properties.
# This function simply parses it, and redistributes it to the correct ADF.

# Input properties
var fgcom_rdf_input_node      = props.globals.getNode("instrumentation/adf[0]/fgcom-mumble/input/", 1);
var fgcom_rdf_input_radio     = fgcom_rdf_input_node.initNode("radio", "");
var fgcom_rdf_input_callsign  = fgcom_rdf_input_node.initNode("callsign", "");
var fgcom_rdf_input_direction = fgcom_rdf_input_node.initNode("direction", "");
var fgcom_rdf_input_quality   = fgcom_rdf_input_node.initNode("quality", "");

var rdf_data_callback = func {
    var radio = fgcom_rdf_input_radio.getValue();
    var direction = fgcom_rdf_input_direction.getValue();
    var quality = fgcom_rdf_input_quality.getValue();

    if (radio == "" or direction == "" or quality == "") return; # No data

    # Read input data
    # Format is this: "RDF:CS_TX=Test,FRQ=123.45,DIR=180.5,VRT=12.5,QLY=0.98,ID_RX=1"
    var radio     = num(split("=", radio)[1]);
    var direction = split("=", direction)[1];
    var quality   = split("=", quality)[1];

    # Send to corresponding ADF
    if (radio != nil and contains(ADF_radios, radio) and ADF_radios[radio].is_used) {
        # Found corresponding ADF radio, send the signal to it.
        ADF_radios[radio].set_rdf_data(direction, quality);
    }
}

# Listener to receive RDF data.
# The listener is placed on the property corresponding to the last field of the protocol.
# So when this property gets updated, it means a full RDF signal info has just been received.

var rdf_data_listener = nil;

var start_rdf = func {
    if (rdf_data_listener != nil) return;
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
