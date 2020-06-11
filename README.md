FGCom-mumble - a flightsim radio simulation framework based on mumble
=====================================================================

This project aims to provide a modular, mumble based radio simulation for flight simulators. The project startet mainly as a successor for the asterisk based FGCom implementation.

### The main goals are:
- Provide a realistic radio simulation
- Ease of use for the end user / pilot
- Capability to be integrated to flightgear, with the option to support third party applications (ATC, but also other flightsims)
- Standalone nature (no dependency on flightgear)
- Ease of server side installation and operation
- Modularity, so individual component implementations can be switched and its easy to add features


Install / Setup
===============

Server
-------------------

###  Setup requirements
- plain mumble server instance. The *fgcom-mumble* plugin on each client handles the rest.
- Create a new channel named `fgcom-mumble` for the airspace. The plugin only does it's things when on this channel.
- to additionally run the bots:
  - lua 5.1 for the bots (`apt-get install lua5.1`)
  - mumble.so in lua include path (/usr/lib/x86_64-linux-gnu/lua/5.1/; compiled from https://github.com/bkacjios/lua-mumble)
    - build dependencys on debian: `apt-get install libluajit-5.1-dev protobuf-c-compiler libprotobuf-c-dev libssl-dev libopus-dev libev-dev`
    - lua lib build process: `$ make all`
    - deploy the lib: `$ cp mumble.so /usr/lib/x86_64-linux-gnu/lua/5.1/`

### Compiling
Information for compiling the lua mumble.so is given at bkacjios github page.  
The lua bots shouldn't be needed to be compiled, just run them trough the lua interpreter.  
Compiling the mumble server is usually not neccessary, just use your distibutions version; this holds true also for the client.

### Running a server
- Have mumble server up and running
- Clients will connect and enable their local fgcom plugin. This handles all human communication on frequencies
- Start the `atis-bot-manager` which handles all needed bots.
- Manually start additional `radio-playback`-bots to play arbitary samples on frequencies (like radio stations).


Client
----------------
###  Setup requirements
- have a standard mumble client with recent plugin support (>= 1.4.0)
  - have the FGCom-mumble plugin loaded
- deploy the `fgcom-mumble.xml` to flightgears protocol directory

## Compiling
The FGCom-mumble client plugin needs to be in binary form.  
**TODO:** basicly a make based approach: get the source, get the dependencies, run make and load the resulting plugin trough your mumble client. Possibly a make install could copy the plugin to mubmles plugin directory? Lets see how this is implemented in the mumble client first....

### Running the client
TODO: Nicer text needed, but basicly:
- compatible to fgcom-standalone protocol, so vey much all halfaway recent fgfs instances should handle it out of the box
- connect to fgfs mumble server
- enable your plugin in your standard mumble client
- join the `fgcom-mumble` channel
- start flightgear with enabled fgcom-mumble protocol ("`--generic=socket,out,2,127.0.0.1,16661,udp,fgcom-mumble`")
- start using your radio stack



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
This inherently enables listening and sending on multiple frequencies.

"Frequency" thereby is an arbitary string, which enables to tune arbitary frequencies and also simulate land-lines. To receive a transmission, just the frequency string must match between sender and receiver.

### Plugin input data
To get the needed data the plugin offers a simple network socket listening for updates on UDP Port **16661** (original FGCom port, it's compatible).  
This can easily be linked to an FGFS generic protocol or to an external application (like ATC-Pie or OpenRadar) to push updaes to the plugin.

For the plugin to work properly, it needs the following data:
- callsign
- location on earth (lat, long, altitude)
- selected frequency per radio
- ptt/sending status per radio

Technically, each packet contains a string with several `Field=Value` variables set. Fields are separated using comma. Records are separated using newline. The plugin will parse the incoming string for the given fields (so it's possible to just send a new callsign for example).  
The available fields are described in the `fgcom-mumble.xml` protocol file.



### Plugin output data
The plugin will broadcast its state (callsign, listen/send frequencies, location) to the other plugins using the mumble internal plugin interface. Other plugins will pick this up and update their internal knowledge of other users.


### Flightgear integration
To send data to the plugin, flightgear must be startet with property-tree synchronization trough a generic protocol.
Currently, we aim for compatibility to the FGCom protocol (Port 16661; https://sourceforge.net/p/flightgear/fgdata/ci/next/tree/Protocol/fgcom.xml) as it provides all the data we need. The sole exceptions are:

 - `output-volume`: is currently tied to /sim/sound/atc/volume and thus not bound to the COM in question
 - `silence-threshold`: same, is not depending on the radio in question (this is not needed in fgcom-mumble anymore because of mumble taking care of that itself)
 - `ptt-key-status`: currently an index denoting the active radio; the consequence of this is that you cannot broadcast at two frequencies at once.

The plugin will handle the old FGCom protocol fields. If you want newer features (for example broadcasting on several radios in parallel) you need to use the new protocol fields.


ATIS / Radio station support
----------------------------
This is implemented modular trough a special set of mumble bots. The bots behave as ordinary mumble clients supplementing FGCom-mumble plugin information so the pilots client plugins will behave correctly. From the pilots view, they are just more ordinary clients.

### ATIS playback
A special `radio-playback`-bot can connect to the mumble server. For that to work properly, he will be called with the needed information: frequency to send on and its location. This information will be broadcasted over the mumble pugin interface, so the other mumble pugins of the pilots can pick it up. From then on, the bot behaves as an ordinary radio client from the view of the plugins.
The bot will read a specified audio file and braodcast it on the selected frequency, until either he is killed or the audio file is deleted (then he kills himself).

### ATIS recording
The following features should be implemented:

 1. *Location agnostic:* It should be possible to record and setup a broadcast anywhere on the planet. This way we can not only record ATIS, but any radio broadcast like radio stations easily.
 2. *Frequency agnostic:* It should be possible to record to any frequency, so we are not depending on a specific apt.dat/nav.dat instance and thus flightgear. This will allow us to transparently support frequency changes and even use real life aerial charts for radio comms. It is also important for the radio-station recording (see above).
 3. *Silent recording to other pilots:* It is not desirable that the recording is transmitted to nearby pilots instantly.
 4. *Easy recording:* No special software should be needed to conduct recording. It should be done via the in-place infrastructure.

This can be easily supported trough a special `radio-recorder` bot that will listen for incoming record requests over the mumble plugin API.  
Recording has to be done using a special frequency like `RECORD_<tgtFreq>`. The pilots will not hear the recording, because they can't tune into this frequency. Just the `radio-recorder` bot will monitor all frequencies starting with `RECORD_`-prefix and record anything that comes in. As the target frequency and location must be set from the client (atc-instance in this case), the bot will receive anything that is needed to get frequency and location of the broadcast.  
The bot is expected to record on the same machine where the radio-playback bot will pick the recordings up, so there is no need for file synchronization. The network-stuff is already handled by the mumble infrastructure this way.

### Radio stations
Just invoke an `radio-playback` bot with the radio station audio program file.

### Radio bot manager
This is a simple program that automates the spawning/killing of the atis related bots on the server side.  
  - She will spawn an `radio-recorder` bot which listens for new recording attempts.
  - She monitors recorded ATIS samples and spawns/kills `radio-playback` bots appropriate to the recordings.


Support for FGCom special frequencies
-------------------------------------
A common thing is that pilots may want to easily test if their setup works. This is implemented trough some special bots as well as the plugin itself. Also, FGCom-mumble has builtin special frequencies with alternative behaviour.

- 910.000 MHz: echo test frequency. Your voice will be echoed back after a short delay, to allow you to check that your microphone, speakers/headset and that your connection to the FGCom server works and to let you know how you are heared from others.
    This is implemented trough a special `echo-bot` in combination with special plugin handling: The echo bot always records and echoes back, but your local plugin does only playback when the message was from you.
- Note there is no global-chat frequency. If you want to globally chat, switch mumble channels.


The following traditional FGCom frequencies have been dropped; these are now implemented trough "default" comms (they were special before because of asterisk implementation details).
- 121.000 MHz, 121.500 MHz: "guard" frequencies reserved for emergency communications;
- 123.450 MHz, 123.500 MHz, 122.750 MHz: general chat frequencies;
- 700.000 MHz: radio station frequency. Depending on the FGCom server in use, a recorded radio message will be played;
- 723.340 MHz: French Air Patrol communication frequency;
- 911.000 MHz: "music on hold". The frequency continuously plays background music, allowing you to check that your connection to the FGCom server works.




IDEAS for the future
====================
- [ ] Extend the state of plugins and bots so output power is taken into account. This will influence the radio wave propagation simulation, i.e. determine the range of the signal.
- [ ] Make the plugin queryable, so it can share information about currently occurring broadcasts in range to external entities (like FGFS: we may tune our ADF to a radio station then :) )
- [ ] Implement a realistic radio propagation model where terrain (and weather?) also influences the propagation.
- [ ] Implement a generic radio station bot manager, that spawns/kills fake radio stations when fgfs-mpserver players are nearby
      This in particular is a similar improvement for the ATIS bots, so may be combined! (only spawn atis bots if planes are nearby)
