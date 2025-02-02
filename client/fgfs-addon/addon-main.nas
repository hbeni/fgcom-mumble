#
# Protocol FGCom-mumble addon main nasal hook
#
# based on the KML addon by Slawek Mikula
#
# @author Benedikt Hallinger, 2021


var main = func( addon ) {
    var root = addon.basePath;
    var myAddonId  = addon.id;
    var mySettingsRootPath = "/addons/by-id/" ~ myAddonId;
    var protocolInitialized = 0;
    var fgcom_timers = {};
    var fgcom_listeners = {};
    
    print("Addon FGCom-mumble loading...");
    
    # init props with defaults
    var configNodes = {};
    configNodes.settingsRootPath = mySettingsRootPath;
    configNodes.enabledNode = props.globals.getNode(mySettingsRootPath ~ "/enabled", 1);
    configNodes.enabledNode.setAttribute("userarchive", "y");
    if (configNodes.enabledNode.getValue() == nil) {
      configNodes.enabledNode.setBoolValue(1);
    }
    configNodes.refreshNode = props.globals.getNode(mySettingsRootPath ~ "/refresh-rate", 1);
    configNodes.refreshNode.setAttribute("userarchive", "y");
    if (configNodes.refreshNode.getValue() == nil) {
      configNodes.refreshNode.setIntValue("10");
    }
    configNodes.hostNode = props.globals.getNode(mySettingsRootPath ~ "/host", 1);
    configNodes.hostNode.setAttribute("userarchive", "y");
    if (configNodes.hostNode.getValue() == nil) {
      configNodes.hostNode.setValue("localhost");
    }
    configNodes.portNode = props.globals.getNode(mySettingsRootPath ~ "/port", 1);
    configNodes.portNode.setAttribute("userarchive", "y");
    if (configNodes.portNode.getValue() == nil) {
      configNodes.portNode.setIntValue("16661");
    }
    configNodes.audioEffectsEnableNode = props.globals.getNode(mySettingsRootPath ~ "/audio-effects-enabled", 1);
    configNodes.audioEffectsEnableNode.setAttribute("userarchive", "y");
    if (configNodes.audioEffectsEnableNode.getValue() == nil) {
      configNodes.audioEffectsEnableNode.setBoolValue(1);
    }
    configNodes.audioHearAllNode = props.globals.getNode(mySettingsRootPath ~ "/audio-hear-all", 1);
    configNodes.audioHearAllNode.setAttribute("userarchive", "y");
    if (configNodes.audioHearAllNode.getValue() == nil) {
      configNodes.audioHearAllNode.setBoolValue(0);
    }
    configNodes.forceEchoTestNode = props.globals.getNode(mySettingsRootPath ~ "/force-echotest-frq", 1);
    configNodes.forceEchoTestNode.setAttribute("userarchive", "n");
    configNodes.forceEchoTestNode.setBoolValue(0);

    # Init GUI menu entry
    var menuTgt = "/sim/menubar/default/menu[7]";  # 7=multiplayer
    var menudata = {
		label   : "FGCom-mumble",
		name    : "fgcom-mumble",
		binding : { command : "dialog-show", "dialog-name" : "fgcom-mumble-settings" }
	};
	props.globals.getNode(menuTgt).addChild("item").setValues(menudata);
	fgcommand("gui-redraw");

    # Start radios logic
    print("Addon FGCom-mumble initializing radios...");
    io.load_nasal(root~"/radios.nas", "FGComMumble_radios");
    var rdfinputNode = props.globals.getNode(mySettingsRootPath ~ "/rdfinput/",1);
    FGComMumble_radios.GenericRadio.setGlobalSettings(configNodes);
    FGComMumble_radios.create_radios();
    FGComMumble_radios.start_rdf(rdfinputNode);

    # Show error message, if no radios could be found
    if (size(FGComMumble_radios.get_com_radios_usable()) == 0) {
      print("Addon FGCom-mumble WARNING: no usable COM radios where found! This should be reported to the aircraft devs (They need to include a <comm-radio> node in instrumentation.xml).");
      fgcommand("dialog-show", {"dialog-name" : "fgcom-mumble-comoverride"});
    }

    
    # Start intercom logic
    print("Addon FGCom-mumble initializing intercom...");
    var intercom_root = props.globals.getNode(mySettingsRootPath ~ "/intercom/",1);
    io.load_nasal(root~"/intercom.nas", "FGComMumble_intercom");
    FGComMumble_intercom.intercom_system = FGComMumble_intercom.IntercomSystem.new(intercom_root);

    # Load the FGCom-mumble combar
    print("Addon FGCom-mumble loading combar...");
    io.load_nasal(root~"/gui/combar.nas", "FGComMumble_combar");

    # Build the final UDP output string transmitted by the protocol file out of the individual radios udp string
    # (note: the generic protocl handler can only process ~256 chars; to prevent truncation,
    #        we need to multiplex into several chunks. The plugin currently supports MAXLINE=1024 chars)
    var out_prop = [
      props.globals.getNode(mySettingsRootPath ~ "/output/udp[0]",1),
      props.globals.getNode(mySettingsRootPath ~ "/output/udp[1]",1),
      props.globals.getNode(mySettingsRootPath ~ "/output/udp[2]",1),
      props.globals.getNode(mySettingsRootPath ~ "/output/udp[3]",1)
    ];
    var update_udp_output = func() {
#      print("Addon FGCom-mumble   updating final UDP transmit field...");
      var udpout_idx   = 0;
      var udpout_chars = 0;
      var str_v = [];
      foreach (r_out; FGComMumble_radios.GenericRadio.outputRootNode.getChildren("COM")) {
#        print("Addon FGCom-mumble      processing "~r_out.getPath());
        if (udpout_chars + size(r_out.getValue()) < 256) {
          append(str_v, r_out.getValue());
          udpout_chars = udpout_chars + size(r_out.getValue());
        } else {
          # Overflow: finish current prop and store into next prop. TODO: this is rather rough but works for now, but we could optimize space usage by splitting not entire COM udp stirngs, but at the individual field level
          out_prop[udpout_idx].setValue(string.join(",", str_v));
          str_v = [];
          udpout_idx = udpout_idx + 1;
          udpout_chars = 0;
          append(str_v, r_out.getValue());
        }
      }
      out_prop[udpout_idx].setValue(string.join(",", str_v));
      
      # clean remaining unused fields in case there was old data
      for (var i=udpout_idx+1; i < 4; i = i+1)  out_prop[i].setValue("");
    }

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
          
          foreach(var p; rdfinputNode.getChildren()) {
            p.setValue("");
          }
          
          # Register a listener to each initialized radios output node
          var r_out_l_idx = 0;
          foreach (r_out; FGComMumble_radios.GenericRadio.outputRootNode.getChildren("COM")) {
#            print("Addon FGCom-mumble    add listener for radio udp_output node (" ~ r_out.getPath() ~")");
            fgcom_listeners["upd_com_out:"~r_out_l_idx] = _setlistener(r_out.getPath(), func { update_udp_output(); }, 0, 0);
            r_out_l_idx = r_out_l_idx + 1;
          }
          
          update_udp_output();
          
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
            
            foreach (var t; keys(fgcom_timers)) fgcom_timers[t].stop();
            fgcom_timers = {};
          
            foreach (var l; keys(fgcom_listeners)) removelistener(fgcom_listeners[l]);
            fgcom_listeners = {};
          
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
    
    # Check for upates at init time
    checkUpdate(mySettingsRootPath);
}


# compare two version vectors of semantic format [major, minor, patch]
# returns -1 if a is newer, 0 if both are equal and 1 if b is newer
var compareVersion = func(a, b) {
    for (var i=0; i<=2; i=i+1) {
        if (a[i] < b[i]) return 1;
        if (a[i] > b[i]) return -1;
    }
    return 0;
}

var checkUpdate = func(rp) {
    var curVer = getprop(rp ~ "/version");
    print("Addon FGCom-mumble checking for updates (local version: "~curVer~")");
    var curVer_v = split(".", curVer);

    # Fetch latest release tag from github release list
    var releaseInfo_url = "https://github.com/hbeni/fgcom-mumble/releases";
    print("Addon FGCom-mumble    using releaseInfo_url: "~releaseInfo_url);

    http.load(releaseInfo_url).done(func(r) {
        # something like: <a href="/hbeni/fgcom-mumble/releases/tag/v.0.14.0">v.0.14.0</a>
        var release_tag_idx = find("releases/tag/", r.response);
        if (release_tag_idx > 0) {
            # something like: 'releases/tag/v.0.14.0">v.0.14.0<
            #                   we want this: ^^^
            tag_name = split("/", split('"', substr(r.response, release_tag_idx, 32) )[0] )[2];
        } else {
            print("Addon FGCom-mumble   unable to get latest release tag");
            canvas.MessageBox.warning(
                "FGCom-mumble updater "~curVer,
                "There was a serious problem getting the latest release info.\n\nPlease file a bug report:\n" ~
                "https://github.com/hbeni/fgcom-mumble/issues",
                cb = nil,
                buttons = canvas.MessageBox.Ok
            );
            return;
        }
        
        # Fetch the addon version from the found tags codebase
        var params = props.Node.new( {
            "url":        "https://raw.githubusercontent.com/hbeni/fgcom-mumble/" ~ tag_name ~ "/client/fgfs-addon/addon-metadata.xml",
            "targetnode": rp ~ "/updater-httpserver-rsp-releaseinfo",
            "complete":   rp ~ "/updater-httpserver-rsp-releaseinfo-complete",
        } );
        
        # callback to process the data
        setlistener(rp ~ "/updater-httpserver-rsp-releaseinfo-complete", func() {
            var upstream_version = getprop(rp ~ "/updater-httpserver-rsp-releaseinfo/addon/version");
            upstream_version_v = split(".", upstream_version);
            var versionCompare = compareVersion(curVer_v, upstream_version_v);
            if (versionCompare  > 0) {
                print("Addon FGCom-mumble  release version "~upstream_version~ " is newer than the local version "~curVer);
                
                # Make a canvas window to show the info
                canvas.MessageBox.information(
                    "FGCom-mumble updater "~curVer,
                    "There is a new addon release "~upstream_version~" waiting for you :)\n\n" ~
                    "Please go to the download page:\nhttps://github.com/hbeni/fgcom-mumble/releases",
                    cb = nil,
                    buttons = canvas.MessageBox.Ok
                );
            } else {
                print("Addon FGCom-mumble  local version "~curVer~ " is up-to-date (upstream release: "~upstream_version~")");
            }
        });
        fgcommand("xmlhttprequest", params);
        
    });
    
    
}
