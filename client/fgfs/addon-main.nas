#
# Protocol FGCom-mumble addon main nasal hook
#
# based on the KML addon by Slawek Mikula
#
# @author Benedikt Hallinger, 2021



#
# Function to overwrite ADF needle for RDF data
#
var rdfResetCheck_interval = 1;
var rdfResetCheck = maketimer(rdfResetCheck_interval, func() {
    #print("FGCom-mumble: rdfResetCheck()");

    # Read current ADF instrument settings
    var adf_node = props.globals.getNode("/instrumentation/adf[0]");
    
    var lastRDFBearing = adf_node.getNode("fgcom-mumble/direction-deg");
    
    # Read most recent input data
    # Format is this: "RDF:CS_TX=Test,FRQ=123.45,DIR=180.5,VRT=12.5,QLY=0.98"
    var fgcom_rdf_input_node      = adf_node.getNode("fgcom-mumble/input/");
    var fgcom_rdf_input_callsign  = fgcom_rdf_input_node.getNode("callsign");
    var fgcom_rdf_input_direction = fgcom_rdf_input_node.getNode("direction");
    var fgcom_rdf_input_quality   = fgcom_rdf_input_node.getNode("quality");
    
    
    # Process the input, if it is valid
    if (fgcom_rdf_input_direction.getValue() != "") {
        # There is new data: handle it
        #print("FGCom-mumble: rdfResetCheck() New data received");
        var fgcom_rdf_direction_field = split("=", fgcom_rdf_input_direction.getValue());
        var fgcom_rdf_quality_field   = split("=", fgcom_rdf_input_quality.getValue());

        if (
            adf_node.getNode("operable").getBoolValue()
            and adf_node.getNode("mode").getValue() == "adf"
            and fgcom_rdf_quality_field[1] >= 0.2
        ) {
            # Signal valid, let ADF needle respond
            lastRDFBearing.setDoubleValue(fgcom_rdf_direction_field[1]);
            interpolate(adf_node.getPath()~"/indicated-bearing-deg", fgcom_rdf_direction_field[1], rdfResetCheck_interval);
        } else {
            # Do nothing: next loop check will go into "signal lost" code, because FGCom-mumble did not provide new data
        }

    } else {
        # Signal lost!
        if (lastRDFBearing.getValue() > -1) {
            # We still got an old value, so reset now.
            # Successive checks will not do anything until we get new signal data.
            # The C++ ADF will update the ADF needle periodically if signals are received.
            #print("FGCom-mumble: rdfResetCheck() signal lost");
            lastRDFBearing.setDoubleValue(-1.0);
            interpolate(adf_node.getPath()~"/indicated-bearing-deg", 90, rdfResetCheck_interval);
        }
    }


    # Clear input fields to denote we have fully processed this dataset.
    # If no update from FGCom-mumble occurs, the input remains empty, so we can detect lost signals
    foreach(var p; fgcom_rdf_input_node.getChildren()) {
        p.setValue("");
    }
});


var main = func( addon ) {
    var root = addon.basePath;
    var myAddonId  = addon.id;
    var mySettingsRootPath = "/addons/by-id/" ~ myAddonId;
    var protocolInitialized = 0;
    
    # init props with defaults
    var enabledNode = props.globals.getNode(mySettingsRootPath ~ "/enabled", 1);
    enabledNode.setAttribute("userarchive", "y");
    if (enabledNode.getValue() == nil) {
      enabledNode.setBoolValue("1");
    }
    var refreshNode = props.globals.getNode(mySettingsRootPath ~ "/refresh-rate", 1);
    refreshNode.setAttribute("userarchive", "y");
    if (refreshNode.getValue() == nil) {
      refreshNode.setIntValue("10");
    }
    var hostNode = props.globals.getNode(mySettingsRootPath ~ "/host", 1);
    hostNode.setAttribute("userarchive", "y");
    if (hostNode.getValue() == nil) {
      hostNode.setValue("localhost");
    }
    var portNode = props.globals.getNode(mySettingsRootPath ~ "/port", 1);
    portNode.setAttribute("userarchive", "y");
    if (portNode.getValue() == nil) {
      portNode.setIntValue("16661");
    }
    
    var lastRDFBearing = props.globals.getNode("/instrumentation/adf[0]/fgcom-mumble/direction-deg", 1);
    lastRDFBearing.setDoubleValue(-1.0);
    var adfVolume = props.globals.getNode("/instrumentation/adf[0]/fgcom-mumble/volume", 1);
    adfVolume.setDoubleValue(1.0);
    var adfFrq = props.globals.getNode("/instrumentation/adf[0]/fgcom-mumble/selected-mhz", 1);
    adfFrq.setValue("0");
    
    
    # Init GUI menu entry
    var menuTgt = "/sim/menubar/default/menu[7]";  # 7=multiplayer
    var menudata = {
		label   : "FGCom-mumble",
		name    : "fgcom-mumble",
		binding : { command : "dialog-show", "dialog-name" : "fgcom-mumble-settings" }
	};
	props.globals.getNode(menuTgt).addChild("item").setValues(menudata);
	fgcommand("gui-redraw");

    var initProtocol = func() {
      if (protocolInitialized == 0) {
        print("Addon FGCom-mumble initializing");
        var enabled = getprop(mySettingsRootPath ~ "/enabled");
        var refresh = getprop(mySettingsRootPath ~ "/refresh-rate");
        var host    = getprop(mySettingsRootPath ~ "/host");
        var port    = getprop(mySettingsRootPath ~ "/port");

        if (enabled == 1) {
          var protocolstring_out = "generic,socket,out," ~ refresh ~ "," ~ host ~ "," ~ port ~",udp,fgcom-mumble";
          print("Addon FGCom-mumble activating protocol '"~protocolstring_out~"'");
          fgcommand("add-io-channel", props.Node.new({
            "config": protocolstring_out,
            "name":"fgcom-mumble"
          }));
          
          var protocolstring_in = "generic,socket,in," ~ refresh ~ ",,19991,udp,fgcom-mumble";
          print("Addon FGCom-mumble activating protocol '"~protocolstring_in~"'");
          fgcommand("add-io-channel", props.Node.new({
            "config": protocolstring_in,
            "name":"fgcom-mumble"
          }));
          
          foreach(var p; props.globals.getNode("/instrumentation/adf[0]/fgcom-mumble/input/").getChildren()) {
            p.setValue("");
          }
          rdfResetCheck.start();
          protocolInitialized = 1;
        }
      }
    }

    var shutdownProtocol = func() {
        if (protocolInitialized == 1) {
            print("Addon FGCom-mumble shutdown protocol...");
            fgcommand("remove-io-channel",
              props.Node.new({
                  "name" : "fgcom-mumble"
              })
            );
            rdfResetCheck.stop();
            protocolInitialized = 0;
        }
    }

    var reinitProtocol = func() {
        print("Addon FGCom-mumble re-initializing");
        shutdownProtocol();
        initProtocol();
    }

    var init = _setlistener(mySettingsRootPath ~ "/enabled", func() {
        if (getprop(mySettingsRootPath ~ "/enabled") == 1) {
            initProtocol();
        } else {
            shutdownProtocol();
        }
    });

    var init_fdm = setlistener("/sim/signals/fdm-initialized", func() {
        removelistener(init_fdm); # only call once
        if (getprop(mySettingsRootPath ~ "/enabled") == 1) {
            initProtocol();
        }
    });

    var reinit_listener = _setlistener("/sim/signals/reinit", func {
        removelistener(reinit_listener); # only call once
        if (getprop(mySettingsRootPath ~ "/enabled") == 1) {
            initProtocol();
        }
    });
    
    var reinit_hzChange   = setlistener(mySettingsRootPath ~ "/refresh-rate", reinitProtocol, 0, 0);
    var reinit_hostChange = setlistener(mySettingsRootPath ~ "/host", reinitProtocol, 0, 0);
    var reinit_portChange = setlistener(mySettingsRootPath ~ "/port", reinitProtocol, 0, 0);
    
    var recalcADFVolume = func() {
        # Reception depends on ident-audible and the volume knob
        # ident-audible is supposed to be set from the audio panel
        var adf_vol   = getprop("/instrumentation/adf[0]/volume-norm") or 0;
        var adf_ident = getprop("/instrumentation/adf[0]/ident-audible") or 0;
        if (adf_ident) {
            setprop("/instrumentation/adf[0]/fgcom-mumble/volume", adf_vol);
        } else {
            setprop("/instrumentation/adf[0]/fgcom-mumble/volume", 0);
        }
    }
    var rdfModeChange = setlistener("/instrumentation/adf[0]/ident-audible", recalcADFVolume, 1, 0);
    var rdfVolChange  = setlistener("/instrumentation/adf[0]/volume-norm", recalcADFVolume, 0, 0);
    
    var recalcADFFrequency = setlistener("/instrumentation/adf[0]/frequencies/selected-khz", func(p) {
        # Recalculate kHz frequency into MHz for fgcom-mumble
        var ori_frq      = p.getValue()~"";  # enforce string
        var calc_frq = 0;
        if (size(ori_frq) <= 3) {
            calc_frq = "0."~ori_frq;
        } else {
            var mhz = left(ori_frq, size(ori_frq)-3);
            var khz = right(ori_frq, 3);
            calc_frq = mhz~"."~khz;
        }
        setprop("/instrumentation/adf[0]/fgcom-mumble/selected-mhz", calc_frq);
    }, 1, 0);
}
