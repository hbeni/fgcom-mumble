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
    
    print("Addon FGCom-mumble loading...");
    
    # init props with defaults
    var enabledNode = props.globals.getNode(mySettingsRootPath ~ "/enabled", 1);
    enabledNode.setAttribute("userarchive", "y");
    if (enabledNode.getValue() == nil) {
      enabledNode.setBoolValue(1);
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
    var audioEffectsEnableNode = props.globals.getNode(mySettingsRootPath ~ "/audio-effects-enabled", 1);
    audioEffectsEnableNode.setAttribute("userarchive", "y");
    if (audioEffectsEnableNode.getValue() == nil) {
      audioEffectsEnableNode.setBoolValue(1);
    }
    var audioHearAllNode = props.globals.getNode(mySettingsRootPath ~ "/audio-hear-all", 1);
    audioHearAllNode.setAttribute("userarchive", "y");
    if (audioHearAllNode.getValue() == nil) {
      audioHearAllNode.setBoolValue(0);
    }

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
    print("Addon FGCom-mumble loading radios...");
    io.load_nasal(root~"/radios.nas", "FGComMumble_radios");
    var rdfinputNode = props.globals.getNode(mySettingsRootPath ~ "/rdfinput/",1);
    FGComMumble_radios.GenericRadio.setOutputRoot(props.globals.getNode(mySettingsRootPath ~ "/output", 1));
    FGComMumble_radios.create_radios();
    FGComMumble_radios.start_rdf(rdfinputNode);

    # Load the FGCom-mumble combar
    print("Addon FGCom-mumble loading combar...");
    io.load_nasal(root~"/gui/combar.nas", "FGComMumble_combar");
    
    var update_udp_output = func() {
      FGComMumble_radios.update_radios();
      var out_prop = props.globals.getNode(mySettingsRootPath ~ "/output/udp",1);
      var str_v = [];
      foreach (r_out; FGComMumble_radios.GenericRadio.outputRootNode.getChildren("COM")) {
        append(str_v, r_out.getValue());
      }
      out_prop.setValue(string.join(",", str_v));
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
          
          fgcom_timers.udploop = maketimer(1/refresh, nil, update_udp_output);
          fgcom_timers.udploop.start();
          
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
            
            foreach (var t; keys(fgcom_timers.timers)) fgcom_timers.timers[t].stop();
            fgcom_timers.timers = {};
          
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
