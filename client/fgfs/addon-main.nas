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
          var protocolstring = "generic,socket,out," ~ refresh ~ "," ~ host ~ "," ~ port ~",udp,fgcom-mumble";
          print("Addon FGCom-mumble activating protocol '"~protocolstring~"'");
          fgcommand("add-io-channel", props.Node.new({
            "config": protocolstring,
            "name":"fgcom-mumble"
          }));
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
}
