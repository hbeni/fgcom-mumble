FGCom-mumble - a flightsim radio simulation framework based on mumble
=====================================================================

Architecture description
========================
The whole idea is that the system is modular, so if something breaks, it will not take the entire system down.
It's also alot easier to detect what exactly is broken and keep individual modules small enough to handle.
One additional advantage is, that each modules implementation may be swapped without affecting the other modules.

The FGCom mumble client plugin
------------------------------
This is the central cornerstone of the system. The plugin handles sending/receiving of the radio broadcasts from players and also bots.
For this to work, the plugins (and bots) share positional and frequency information trough mumbles builtin plugin data send interface. When the user connects, the plugin will start to share this data automatically and collect the information from already connected clients. This way, each local plugin has always a recent knowledge of the other users.

For the plugin to commence operations, a special channel `fgcom-mumble` must be joined (so other communication stays unaffected and the plugin can remain active for normal talking elsewhere).  
If a users fgcom mumble plugin then receives a new audio transmission, it will:
- look at its data to get the frequency of the current transmission
- look at the location of the sender
- look at current transmission state of the local user
Then, if the frequency is currently tuned AND the sender was in radio-range AND the current user is not transmitting himself on the frequency in question, the received transmision will be played; otherwise discarded.  
This inherently enables listening and sending on multiple frequencies in parallel.

"Frequency" thereby is an arbitary string, which enables to tune arbitary frequencies and also may used to simulate land-lines for ATC. To receive a transmission, the frequency string must match between sender and receiver. If the frequency is numeric, comparison is handled by the radio model.

### Plugin input data
To get the needed data the plugin offers a simple network socket listening for updates on UDP Port **16661** (original FGCom port, it's compatible).  
This can easily be linked to an FGFS generic protocol or to an external application (like ATC-Pie or OpenRadar) to push updates to the plugin.

Details are explained in the `plugin-spec.md` file.

### Plugin output data
The plugin will broadcast its state (callsign, listen/send frequencies, location) to the other plugins using the mumble internal plugin interface. Other plugins will pick this up and update their internal knowledge of other users.

Also, the plugin can send information via an UDP interface to third party software at 10Hz on UDP. The port is on localhost and defaults to the client source port.

Details are too explained in the `plugin-spec.md` file.


### Flightgear integration
To send data to the plugin, flightgear must be startet with property-tree synchronization trough a generic protocol.  
We strongly advise to use the new protocol format.
The [new protocol xml-file](client/fgfs/Protocol/fgcom-mumble.xml) is supplied in the source tree and documented (`client/fgfs/Protocol/fgcom-mumble.xml`).

Currently, we aim for compatibility to the [original FGCom protocol](https://sourceforge.net/p/flightgear/fgdata/ci/next/tree/Protocol/fgcom.xml) (Port 16661) as it provides all the data we need. The sole exceptions are:

 - `output-volume`: is currently tied to /sim/sound/atc/volume and thus not bound to the COM in question
 - `ptt-key-status`: currently an index denoting the active radio; the consequence of this is that you cannot broadcast at two frequencies at once.
 - `silence-threshold`: same, is not depending on the radio in question (but is not needed in fgcom-mumble anymore because of mumble taking care of that itself)

The plugin will handle the old FGCom protocol fields. If you want newer features (for example broadcasting on several radios in parallel) you need to use the new protocol fields.


ATC support
----------------------------
ATC clients can connect using the old FGCom UDP protocol or using the newer one.

## Position, `HGT=` setting / Antenna height
In either case, it is important to set a valid position and altitude. Altitude is the main range limiting factor in VHF radio ooperations, for example 1m heigth gives about 3.6km range until your transmission hits the earths surface. it is advised that you set the altitude to the antenna tip height above surface (so 8m building+2m Antenna gives 10m=32.8ft: `HGT=32.8`.

### Land lines
You can establish virtual land lines by adding a new "virtual radio" with a special custom frequency starting with `PHONE` like "PHONE-EDDM-TWR". Such connections are not subject to radio signal quality or range and allow for full-duplex operation.  
Volume settings and operational state of the simulated phone is applied, however.  
A good practice may be the syntax `PHONE:[ICAO]:[POS](:[LINE])`, like `PHONE:EDDM:TWR:1` or `PHONE:EDMO:GND`.


Radio station support
----------------------------
This is implemented modular trough a special set of mumble bots. The bots behave as ordinary mumble clients supplementing FGCom-mumble plugin information so the pilots client plugins will behave correctly. From the pilots view, they are just more ordinary clients.

### ATIS playback
A `fgcom-radio-playback`-bot can connect to the mumble server. For that to work properly, he will be called with the needed information: frequency to send on and its location. This information will be broadcasted over the mumble plugin interface, so the other mumble pugins of the pilots can pick it up. From then on, the bot behaves as an ordinary radio client from the view of the plugins.
The bot will read a specified audio file and braodcast it on the selected frequency, until either he is killed or the audio file is deleted (then he kills himself).

### ATIS recording
The following features should be implemented:

 1. *Location agnostic:* It should be possible to record and setup a broadcast anywhere on the planet. This way we can not only record ATIS, but any radio broadcast like radio stations easily.
 2. *Frequency agnostic:* It should be possible to record to any frequency, so we are not depending on a specific apt.dat/nav.dat instance and thus flightgear. This will allow us to transparently support frequency changes and even use real life aerial charts for radio comms. It is also important for the radio-station recording (see above).
 3. *Silent recording to other pilots:* It is not desirable that the recording is transmitted to nearby pilots instantly.
 4. *Easy recording:* No special software should be needed to conduct recording. It should be done via the in-place infrastructure.

This can be easily supported trough a special `radio-recorder` bot that will listen for incoming record requests over the mumble plugin API.  
Recording has to be done using a special frequency like `RECORD_<tgtFreq>`. The other pilots will not hear the recording, because they can't tune into this frequency. Just the `radio-recorder` bot will monitor all frequencies starting with `RECORD_`-prefix and record anything that comes in. As the target frequency and location must be set from the client (atc-instance in this case), the bot will receive anything that is needed to get frequency and location of the broadcast.  
The bot is expected to record on the same machine where the radio-playback bot will pick the recordings up, so there is no need for file synchronization. The network-stuff is already handled by the mumble infrastructure this way.

### Radio stations
Just invoke a `fgcom-radio-playback` bot with the radio station audio program file.


Status webpage
----------------------------
For user convinience there is also a webpage that shows the current status.  
refer to the *server/statuspage/Readme.statuspage.md* file for details.
