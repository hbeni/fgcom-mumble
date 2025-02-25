#
# Protocol FGCom-mumble addon main nasal hook
#
# based on the KML addon by Slawek Mikula
#
# @author Benedikt Hallinger, 2021

var FGComMumble = {
  addon: nil,
  rootPath: "",
  rootNode: nil,
  listeners: {},
  timers: {},
  
  # Small simple logger which allows filtering by category and severity
  # changeable at runtime by setting props
  logger: {
    level_node: nil,   # setting means: 0=none, 1=ERROR, 2=INFO; 3=FINE, 4=FINER, 5=FINEST
    dbg_node: nil,
    init: func() {
      # init nodes with defaults. Can be overridden at commandline by --prop:
      me.dbg_node = FGComMumble.rootNode.getNode("debug", 1);
      me.level_node = me.dbg_node.initNode("level", 2, "INT");
      me.dbg_node.initNode("category_core",     1, "BOOL");
      me.dbg_node.initNode("category_radio",    1, "BOOL");
      me.dbg_node.initNode("category_intercom", 1, "BOOL");
      me.dbg_node.initNode("category_combar",   1, "BOOL");
      me.dbg_node.initNode("category_udp",      1, "BOOL");
      me.dbg_node.initNode("category_rdf",      1, "BOOL");
      foreach (cfg; me.dbg_node.getChildren()) {
        FGComMumble.listeners["debug:"~cfg.getName()] = 
          setlistener(cfg.getPath(), func(node) {
            FGComMumble.logger.log("core", -1, "debug config changed: "~node.getName()~"=>"~node.getValue());
          }, 0, 0);
      }
    },
    log: func(category, level, msg) {
      var levelSelected    = (level <= me.get_level());
      var categorySelected = (me.dbg_node.getChild("category_"~category).getValue());
      if ( levelSelected and categorySelected ) {
        printf("Addon FGCom-mumble [%s]: %s", category, msg);
      }
    },
    logHash: func(category, level, msg, hash) {
      me.log(category, level, msg);
      var levelSelected    = (level <= me.get_level());
      var categorySelected = (me.dbg_node.getChild("category_"~category).getValue());
      if (levelSelected and categorySelected) debug.dump(hash);
    },
    get_level: func() {
      return me.level_node.getValue();
    }
  },
  
  # Initialize system
  init: func(addon) {
    me.addon    = addon;
    me.rootPath = "/addons/by-id/" ~ addon.id;
    me.rootNode = props.globals.getNode(me.rootPath);
    
    me.logger.init();
    
    FGComMumble.logger.log("core", -1, "Version "~me.rootNode.getChild("version").getValue() ~ " loading..." );
  },
  

  # Udpate checks
  checkUpdate: func(showOK) {
    var curVer = me.rootNode.getValue("version");
    FGComMumble.logger.log("core", 2, "checking for updates (local version: "~curVer~")");
    var curVer_v = split(".", curVer);

    # Fetch latest release tag from github release list
    var releaseInfo_url = "https://github.com/hbeni/fgcom-mumble/releases";
    FGComMumble.logger.log("core", 3, "   using releaseInfo_url: "~releaseInfo_url);

    http.load(releaseInfo_url).done(func(r) {
        # something like: <a href="/hbeni/fgcom-mumble/releases/tag/v.0.14.0">v.0.14.0</a>
        var release_tag_idx = find("releases/tag/", r.response);
        if (release_tag_idx > 0) {
            # something like: 'releases/tag/v.0.14.0">v.0.14.0<
            #                   we want this: ^^^
            tag_name = split("/", split('"', substr(r.response, release_tag_idx, 32) )[0] )[2];
        } else {
            FGComMumble.logger.log("core", 1, "  unable to get latest release tag");
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
            "targetnode": me.rootNode.getPath() ~ "/updater-httpserver-rsp-releaseinfo",
            "complete":   me.rootNode.getPath() ~ "/updater-httpserver-rsp-releaseinfo-complete",
        } );
        
        # callback to process the data
        FGComMumble.listeners["checkUpdate_response_callback"] = _setlistener(me.rootNode.getPath() ~ "/updater-httpserver-rsp-releaseinfo-complete", func() {
            var upstream_version = getprop(me.rootNode.getPath() ~ "/updater-httpserver-rsp-releaseinfo/addon/version");
            upstream_version_v = split(".", upstream_version);
            var versionCompare = FGComMumble.compareVersion(curVer_v, upstream_version_v);
            if (versionCompare  > 0) {
                FGComMumble.logger.log("core", 2, " release version "~upstream_version~ " is newer than the local version "~curVer);
                
                # Make a canvas window to show the info
                canvas.MessageBox.information(
                    "FGCom-mumble updater "~curVer,
                    "There is a new addon release "~upstream_version~" waiting for you :)\n\n" ~
                    "Please go to the download page:\nhttps://github.com/hbeni/fgcom-mumble/releases",
                    cb = nil,
                    buttons = canvas.MessageBox.Ok
                );
            } else {
                FGComMumble.logger.log("core", 2, " local version "~curVer~ " is up-to-date (upstream release: "~upstream_version~")");
                if (showOK) {
                  # Make a canvas window to show the info
                  canvas.MessageBox.information(
                      "FGCom-mumble updater "~curVer,
                      "Your version is up-to-date.\n\n" ~
                      "(upstream release: "~upstream_version~")",
                      cb = nil,
                      buttons = canvas.MessageBox.Ok
                  );
                }
            }
            removelistener(FGComMumble.listeners["checkUpdate_response_callback"]);
            delete(FGComMumble.listeners, "checkUpdate_response_callback");
        });
        fgcommand("xmlhttprequest", params);
        
    });
  },
  
  # compare two version vectors of semantic format [major, minor, patch]
  # returns -1 if a is newer, 0 if both are equal and 1 if b is newer
  compareVersion: func(a, b) {
      for (var i=0; i<=2; i=i+1) {
          if (a[i] < b[i]) return 1;
          if (a[i] > b[i]) return -1;
      }
      return 0;
  }
};

var main = func( addon ) {
    var root = addon.basePath;
    var myAddonId  = addon.id;
    var mySettingsRootPath = "/addons/by-id/" ~ myAddonId;
    var protocolInitialized = 0;
    var fgcom_timers = {};
    var fgcom_listeners = {};
    
    FGComMumble.init(addon);
    
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
    configNodes.rdfportNode = props.globals.getNode(mySettingsRootPath ~ "/rdfport", 1);
    configNodes.rdfportNode.setAttribute("userarchive", "y");
    if (configNodes.rdfportNode.getValue() == nil) {
      configNodes.rdfportNode.setIntValue("19991");
    }
    configNodes.updateCheckNode = props.globals.getNode(mySettingsRootPath ~ "/check-for-updates", 1);
    configNodes.updateCheckNode.setAttribute("userarchive", "y");
    if (configNodes.updateCheckNode.getValue() == nil) {
      configNodes.updateCheckNode.setBoolValue(1);
    }
    configNodes.audioEffectsEnableNode = props.globals.getNode(mySettingsRootPath ~ "/audio-effects-enabled", 1);
    configNodes.audioEffectsEnableNode.setAttribute("userarchive", "y");
    if (configNodes.audioEffectsEnableNode.getValue() == nil) {
      configNodes.audioEffectsEnableNode.setBoolValue(1);
    }
    configNodes.enableCOMRDF = props.globals.getNode(mySettingsRootPath ~ "/com-rdf-enabled", 1);
    configNodes.enableCOMRDF.setAttribute("userarchive", "y");
    if (configNodes.enableCOMRDF.getValue() == nil) {
      configNodes.enableCOMRDF.setBoolValue(1);
    }
    configNodes.audioHearAllNode = props.globals.getNode(mySettingsRootPath ~ "/audio-hear-all", 1);
    configNodes.audioHearAllNode.setAttribute("userarchive", "y");
    if (configNodes.audioHearAllNode.getValue() == nil) {
      configNodes.audioHearAllNode.setBoolValue(0);
    }
    configNodes.forceEchoTestNode = props.globals.getNode(mySettingsRootPath ~ "/force-echotest-frq", 1);
    configNodes.forceEchoTestNode.setAttribute("userarchive", "n");
    configNodes.forceEchoTestNode.setBoolValue(0);

    # Start radios logic
    FGComMumble.logger.log("core", 2, "initializing radios...");
    io.load_nasal(root~"/radios.nas", "FGComMumble_radios");
    FGComMumble_radios.FGComMumble = FGComMumble;
    var rdfinputNode = props.globals.getNode(mySettingsRootPath ~ "/rdfinput/",1);
    FGComMumble_radios.GenericRadio.setGlobalSettings(configNodes);
    FGComMumble_radios.create_radios();
    FGComMumble_radios.start_rdf(rdfinputNode);

    # Show error message, if no radios could be found
    if (size(FGComMumble_radios.get_com_radios_usable()) == 0) {
      FGComMumble.logger.log("core", 1, "WARNING: no usable COM radios where found! This should be reported to the aircraft devs (They need to include a <comm-radio> node in instrumentation.xml).");
      fgcommand("dialog-show", {"dialog-name" : "fgcom-mumble-comoverride"});
    }

    
    # Start intercom logic
    FGComMumble.logger.log("core", 2, "initializing intercom...");
    var intercom_root = props.globals.getNode(mySettingsRootPath ~ "/intercom/",1);
    io.load_nasal(root~"/intercom.nas", "FGComMumble_intercom");
    FGComMumble_intercom.FGComMumble = FGComMumble;
    FGComMumble_intercom.intercom_system = FGComMumble_intercom.IntercomSystem.new(intercom_root);

    # Load the FGCom-mumble combar
    FGComMumble.logger.log("core", 2, "loading combar...");
    io.load_nasal(root~"/gui/combar.nas", "FGComMumble_combar");
    FGComMumble_combar.FGComMumble = FGComMumble;

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
      FGComMumble.logger.log("udp", 3, "  updating final UDP transmit field...");
      var udpout_idx   = 0;
      var udpout_chars = 0;
      var str_v = [];
      foreach (r_out; FGComMumble_radios.GenericRadio.outputRootNode.getChildren("COM")) {
        FGComMumble.logger.log("udp", 4, "     processing "~r_out.getPath());
        if (udpout_chars + size(r_out.getValue()) < 256) {
          append(str_v, r_out.getValue());
          udpout_chars = udpout_chars + size(r_out.getValue());
        } else {
          # Overflow: finish current prop and store into next prop. TODO: this is rather rough but works for now, but we could optimize space usage by splitting not entire COM udp stirngs, but at the individual field level. We now have code for that in the debug dialog canvas!
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
        FGComMumble.logger.log("core", 2, "initializing addon");
        var enabled = getprop(mySettingsRootPath ~ "/enabled");
        var refresh = getprop(mySettingsRootPath ~ "/refresh-rate");
        var host    = getprop(mySettingsRootPath ~ "/host");
        var port    = getprop(mySettingsRootPath ~ "/port");
        var rdfport = getprop(mySettingsRootPath ~ "/rdfport");

        if (enabled == 1) {
          FGComMumble.logger.log("udp", 2, "initializing protocol");
          var protocolstring_out = "generic,socket,out," ~ refresh ~ "," ~ host ~ "," ~ port ~",udp,fgcom-mumble";
          FGComMumble.logger.log("udp", 3, "activating protocol '"~protocolstring_out~"'");
          fgcommand("add-io-channel", props.Node.new({
            "config": protocolstring_out,
            "name":"fgcom-mumble-out"
          }));
          
          var protocolstring_in = "generic,socket,in," ~ refresh ~ ",,"~rdfport~",udp,fgcom-mumble";
          FGComMumble.logger.log("udp", 3, "activating protocol '"~protocolstring_in~"'");
          fgcommand("add-io-channel", props.Node.new({
            "config": protocolstring_in,
            "name":"fgcom-mumble-in"
          }));
          
          foreach(var p; rdfinputNode.getChildren()) {
            p.setValue("");
          }
          
          # Register a listener to each initialized radios output node
          var r_out_l_idx = 0;
          foreach (r_out; FGComMumble_radios.GenericRadio.outputRootNode.getChildren("COM")) {
            FGComMumble.logger.log("udp", 3, "   add listener for radio udp_output node (" ~ r_out.getPath() ~")");
            fgcom_listeners["upd_com_out:"~r_out_l_idx] = _setlistener(r_out.getPath(), func { update_udp_output(); }, 0, 0);
            r_out_l_idx = r_out_l_idx + 1;
          }
          
          # FGCom 3.0 compatibility:
          # The old FGCom protocol seems outdated and transmit an old property.
          # To get compatibility out-of-the-box, we listen to changes and
          # translate the value to the individual comms ptt property.
          # (the code tries to do this only for existing properties, so we don't create nodes accidentally)
          var legacy_fgcom_ptt_prop = "/controls/radios/comm-ptt";
          var legacy_fgcom_ptt_oldVal = 0;
          var legacy_fgcom_ptt_set = func(id, active) {
            var selected_comm = props.globals.getNode("/instrumentation/").getChild("comm", id);
            if (selected_comm != nil) {
              var selected_comm_ptt = selected_comm.getChild("ptt");
              if (selected_comm_ptt != nil) {
                FGComMumble.logger.log("radio", 4, "     comm["~id~"] set to "~active);
                selected_comm_ptt.setBoolValue(active);
              } else {
                FGComMumble.logger.log("radio", 4, "     comm["~id~"] has no ptt node");
              }
            } else {
              FGComMumble.logger.log("radio", 4, "     comm["~id~"] not registered");
            }
          };
          FGComMumble.logger.log("radio", 3, "add listener for legacy_fgcom_ptt (" ~ legacy_fgcom_ptt_prop ~")");
          fgcom_listeners["legacy_fgcom_ptt"] = _setlistener(legacy_fgcom_ptt_prop, func {
            var fgcom_ptt_selector = getprop(legacy_fgcom_ptt_prop);
            FGComMumble.logger.log("radio", 4, "   legacy_fgcom_ptt(" ~ fgcom_ptt_selector ~")");
            if (fgcom_ptt_selector > 0) {
              # Activate PTT
              legacy_fgcom_ptt_set(fgcom_ptt_selector-1, 1);
            } else {
              # Reset PTT
              if (legacy_fgcom_ptt_oldVal > 0) {
                # reset previous com-ptt
                legacy_fgcom_ptt_set(legacy_fgcom_ptt_oldVal-1, 0);
              }
            }
            legacy_fgcom_ptt_oldVal = fgcom_ptt_selector;
          }, 0, 0);

          # FCOM 3.0 bug prevention (#204)
          # Running FGCom-mumble and legacy FGCom has resulted in legacy FGCom segfaulting.
          # So, if we activate FGCom-mumble, legacy FGCom must be turned off.
          var legacy_fgcom_enabled_prop = "/sim/fgcom/enabled";
          if (getprop(legacy_fgcom_enabled_prop)) {
            FGComMumble.logger.log("core", 2, "disabling legacy FGCom (" ~ legacy_fgcom_enabled_prop ~")");
            setprop(legacy_fgcom_enabled_prop, 0);
          }
          # Also we search the menu bar item to disable it, so nobody accidentally
          # opens the old FGCom dialoge which will reenable itself.
          # We do this by overwriting the classic menu entry, if possible.
          var menubar = props.globals.getNode("/sim/menubar/default");
          var legacy_fgcom_menuDisabled = 0;
          foreach (menu_entry; menubar.getChildren("menu")) {
            foreach (menu_item; menu_entry.getChildren("item")) {
              if (menu_item.getValue("name") == "fgcom-settings") {
                legacy_fgcom_menuDisabled = 1;
                FGComMumble.logger.log("core", 2, "overwriting legacy FGCom menu entry ("~menu_item.getPath()~")" );
                #menu_item.setBoolValue("enabled", 0);
                
                # overwrite the entry with our menu
                menu_item.setValue("label", "FGCom-mumble");
                menu_item.setValue("name", "fgcom-mumble");
                menu_item.getChild("binding").setValue("dialog-name", "fgcom-mumble-settings");
                fgcommand("gui-redraw");
                break;
              }
            }
            if (legacy_fgcom_menuDisabled) break;
          }
          
          # Init GUI menu entry, in case we could't overwrite the classic FGCom one
          if (!legacy_fgcom_menuDisabled) {
            FGComMumble.logger.log("core", 2, "adding FGCom-mumble menu entry" );
            var menuTgt = "/sim/menubar/default/menu[7]";  # 7=multiplayer
            var menudata = {
                label   : "FGCom-mumble",
                name    : "fgcom-mumble",
                binding : { command : "dialog-show", "dialog-name" : "fgcom-mumble-settings" }
            };
            props.globals.getNode(menuTgt).addChild("item").setValues(menudata);
            fgcommand("gui-redraw");
          }

          
          update_udp_output();
          
          protocolInitialized = 1;
        }
      }
    }

    var shutdownProtocol = func() {
        if (protocolInitialized == 1) {
            FGComMumble.logger.log("udp", 2, "shutdown protocol...");
            foreach (var channelName; ["fgcom-mumble-out", "fgcom-mumble-in"]) {
              FGComMumble.logger.log("udp", 3, "remove-io-channel("~channelName~")");
              fgcommand("remove-io-channel",
                props.Node.new({
                    "name" : channelName
                })
              );
            }
            
            foreach (var t; keys(fgcom_timers)) fgcom_timers[t].stop();
            fgcom_timers = {};
          
            foreach (var l; keys(fgcom_listeners)) removelistener(fgcom_listeners[l]);
            fgcom_listeners = {};
          
            protocolInitialized = 0;
        }
    }

    var reinitProtocol = func() {
        FGComMumble.logger.log("core", 2, "re-initializing");
        shutdownProtocol();

        # Delay start so the closing channel has time to finalize the socket
        var delayRestart_t = maketimer(1, FGComMumble, initProtocol);
        delayRestart_t.singleShot = 1;
        delayRestart_t.start();
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
    
    var reinit_hzChange       = setlistener(mySettingsRootPath ~ "/refresh-rate", reinitProtocol, 0, 0);
    var reinit_hostChange     = setlistener(mySettingsRootPath ~ "/host", reinitProtocol, 0, 0);
    var reinit_portChange     = setlistener(mySettingsRootPath ~ "/port", reinitProtocol, 0, 0);
    var reinit_rdfportChange  = setlistener(mySettingsRootPath ~ "/rdfport", reinitProtocol, 0, 0);
    
    # Check for upates at init time
    if (configNodes.updateCheckNode.getValue()) {
      FGComMumble.checkUpdate(0);
    } else {
      FGComMumble.logger.log("core", 2, "ATTENTION: Not checking for updates (as requested by user setting)");
    }
}
