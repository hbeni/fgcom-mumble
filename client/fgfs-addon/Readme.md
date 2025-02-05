FGCom-mumble FGFS Addon
=================================
This set of files is a convenient FlightGear addon package to let FlightGear know about the FGCom-mumble protocol. It adds menu item and a dialog where you can conviniently adjust the parameters without the need to restart flightgear.

Installation
------------
After unzipping the FGCom-mumble release package, you just need to add the `fgfs-addon` folder to your launcher's *Add-ons* module list.  
The addon is activated automatically, so flightgear will try to connect to mumble with the default parameters.

### Updating
When the addon is starting, it will check github for update releases. If it finds a more recent version, it will inform the user with a small text window, so the pilot knows that he needs to take action.

Just go to the project website, download the latest addon release package and deploy like a fresh install, replacing the previous addon directory contents.


Running the Addon
-----------------
When added to your launcher, the addon is automatically activated.
No further steps are needed.

The FGFS protocol file will handle old 25kHz as well as newer 8.3kHz radios.
After starting flightgear, you can use your radio stack like with FGCom (default is *space* to talk on COM1 and *shift+space* for COM2).  
*alt+space* will transmit on COM3, and *ctrl+space* on the intercom.

If your plane has more than two COM radios, you can use the _Combar_ dialog from the configuration dialog to access the PTTs of the radios, or define custom keybinds to set `/instrumentation/comm[n]/ptt`.


Configuration
----------------------------
If you wish to adjust the parameters, you can access them via the new *Multiplayer* menu entry. This is usually not needed except you are running several mumble instances or mumble not on the same computer as FlightGear.  
Changes to the parameters will reinitialize the addon automatically, making them effective.

The settings dialog also shows some helpful informtion like the registered COM radios and PTT state.


Compatible aircraft
----------------------
Basicly every aircraft utilizing the standard radio implementation properties should work without modification.


### COM / ADF Radios
When initializing, the addon will inspect the defined radios and enable them for FGCom-Mumble. Currently this are the `comm` and `adf` subnodes in `/instrumentation/`.  
Only radios providing the property `operable` are considered (which is set by the standard C++ radio implementation). If no such radios are found, a dialog will open when loading, explaining the situation and providing a manual workaround.

The addon uses the following standard properties:

- COM radios:
  - `/instrumentation/comm[n]/operable`
  - `/instrumentation/comm[n]/volume`
  - `/instrumentation/comm[n]/frequencies/selected-mhz`
  - `/instrumentation/comm[n]/ptt`
  - `/instrumentation/comm[n]/cutoff-signal-quality`
  - `/instrumentation/comm[n]/frequencies/selected-channel-width-khz`
  - `/instrumentation/comm[n]/tx-power` (nonstandard and optional; introduced by FGCom-mumble)

- ADF radios (local only, they can't transmit):
  - `/instrumentation/adf[n]/operable`
  - `/instrumentation/adf[n]/volume-norm`
  - `/instrumentation/adf[n]/frequencies/selected-khz`
  - `/instrumentation/adf[n]/indicated-bearing-deg` (read/write)
  - `/instrumentation/adf[n]/ident-audible`
  - `/instrumentation/adf[n]/mode`

### Intercom
FlightGear has a copilot feature that allows you to ride alongside another pilot. Usually planes have some kind of intercom system.  
Since version 1.2.0 the FGFS-addon will periodically check if such a pilot/copilot connection has been made and provide intercom functionality, so you can talk to each other.

The intercom works like the other radios but in full-duplex mode. Currently, you can access the PTT button of the intercom using the combar.


#### Plane API
Plane developers can access the intercom device below `/addons/by-id/org.hallinger.flightgear.FGCom-mumble/intercom/IC[n]`, where each device gets a subnode with properties you can link to the planes audio panel (or nasal magic):

| Propery    | Description                                                                                                                                    |
|------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `channel`  | The Channel name. Change this to make the Intercom switch to another channel. This could be useful to simulate intercom isolation, for example.|
| `operable` | Set to `0` to disable the intercom (switch on/off).                            |                                                                                             
| `volume`   | `0.0` to `1.0`, to adjust the intercoms volume.                                |                                                                                                                                                 
| `ptt`      | `1` makes the intercom transmit.                                               |
| others     | The other properties are internal and should not be directly set by your code. |

You can also register additional Intercom devices by calling `var myNewDevice = FGComMumble_intercom.intercom_system.add_intercom_device();`. This will provide a fresh subnode you can handle. The resulting UDP packages will be gathered automatically, but things like channel name and PTT you need to handle yourself.  
For the intercom to be connected you need to call `myNewDevice.connect(["A","B"])` on the device (where `["A","B"]` is the combined callsigns to establish the default channel name (you can also use `connect(["someCustomChannelname"])` instead). You can also alter the channel name afterwards via the property described above).