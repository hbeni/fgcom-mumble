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
