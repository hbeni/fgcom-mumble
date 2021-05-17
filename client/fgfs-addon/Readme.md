FGCom-mumble FGFS Addon
=================================
This set of files is a convenient FlightGear addon package to let FlightGear know about the FGCom-mumble protocol. It adds menu item and a dialog where you can conviniently adjust the parameters without the need to restart flightgear.

Installation
------------
After unzipping the FGCom-mumble release package, you just need to add the `fgfs-addon` folder to your launcher's *Add-ons* module list.  
The addon is activated automatically, so flightgear will try to connect to mumble with the default parameters.


Running the Addon
-----------------
When added to your launcher, the addon is automatically activated.
No further steps are needed.

The FGFS protocol file will handle old 25kHz as well as newer 8.3kHz radios.
After starting flightgear, you can use your radio stack like with FGCom (default is *space* to talk on COM1 and *shift+space* for COM2).

If your plane has more than two COM radios, you can use the _Combar_ dialog from the configuration dialog to access the PTTs of the radios, or define custom keybinds to set `/instrumentation/com[n]/ptt`.


Configuration
----------------------------
If you wish to adjust the parameters, you can access them via the new *Multiplayer* menu entry. This is usually not needed except you are running several mumble instances or mumble not on the same computer as FlightGear.  
Changes to the parameters will reinitialize the addon automatically, making them effective.