FGCom-mumble FGFS Addon
=================================
This Addon is a convinient addon package to let FlightGear know about the FGCom-mumble protocol. It adds menu item and a dialog where you can conviniently adjust the parameters without the need to restart flightgear.

Instead of using this addon, you can also invoke the protocol manually:

- copy the `fgcom-mumble.xml` fightgear protocol file to your flightgears `Protocol` folder.
- start flightgear with enabled fgcom-mumble protocol (add "`--generic=socket,out,10,127.0.0.1,16661,udp,fgcom-mumble`" to your launcher)



Installation
------------
After unzipping the FGCom-mumble release package, you just need to add the `fgfs` folder to your launchers *Add-ons* module list.  
The addon is activated automatically, so flightgear will try to connect to mumble with the default parameters.


Running the Addon
-----------------
When added to your launcher, the addon is automatically active.
No further steps are needed.

The FGFS protocol file will handle old 25kHz as well as newer 8.3kHz radios.
After starting flightgear, you can use your radio stack like with FGCom (default is *space* to talk on COM1 and *shift+space* for COM2).


Configuration
----------------------------
If you wish to adjust the parameters, you can access them via the new *Multiplayer* menu entry. This is usually not needed except you are running several mumble instances or mumble not on the same computer as FlightGear.  
Changes to the parameters will reinitialize the addon automatically, making them effective.