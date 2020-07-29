FGCom-mumble - a flightsim radio simulation framework based on mumble
=====================================================================

This project aims to provide a modular, mumble based radio simulation for flight simulators. The project startet mainly as a successor for the asterisk based FGCom implementation.

### The main goals are:
- Provide communication with geographic and channel separation
- Provide a realistic radio simulation
- Ease of use for the end user / pilot
- Arbitary frequency support
- ATIS recording and playback
- Radio station broadcast support
- Landline/Intercom support
- RDF detection for clients
- Ease of server side installation and operation
- Standalone nature (no dependency on flightgear)
- Capability to be integrated into flightgear, with the option to support third party applications (ATC, but also other flightsims)
- Modularity, so individual component implementations can be switched and its easy to add features
- Good and complete documentation

Documentation
=============
The documentation is split up into relevant parts:

- Readme.md (*this file*): General overview and client documentation
- [Readme.architecture.md](Readme.architecture.md) Details about the components that make up the system
- [client/plugin.spec.md](client/plugin.spec.md) Technical details on plugin design and its input/output data formats
- [server/Readme.server.md](server/Readme.server.md) Details on the server side components and how to run them
- [server/statuspage/Readme.statuspage.md](server/statuspage/Readme.statuspage.md) Technical details about the status page implementation

### Bugs/Feature requests/coding help
The project lives on github: https://github.com/hbeni/fgcom-mumble

If you want to request a feature or report a bug, you can do so on the issuetracker there. I appreciate help with coding, so feel free to clone the repository and hand in pull-requests!


Install / Setup for the Client
==============================

Setup requirements
----------------------
- have a standard mumble client with recent plugin support (>= v1.4.0)

Installation
-----------------------
- copy the plugin to mumbles `plugins`-folder. Mumble will pick it up automatically and show it in the plugins dialog.


Running the client
======================
- connect your mumble client to fgfs mumble server
- enable your plugin in your standard mumble client
- join the `fgcom-mumble` channel

You are ready for radio usage! Some client needs to supply information to the plugin now, so it knows about your location and radio stack.

### Generic compatibility
The plugin aims to be compatible to the legacy fgcom-standalone protocol, so vey much all halfway recent fgfs instances, ATC clients and aircraft should handle it out of the box at least with COM1.

Note that frequencies can be arbitary strings.  
But callsigns and Frequencies are not allowed to contain the comma symbol (`,`). Decimal point symbol has always to be a point (`.`).

### Flightgear specific
- copy the `fgcom-mumble.xml` fightgear protocol file to your flightgears `Protocol` folder.
- start flightgear with enabled fgcom-mumble protocol (add "`--generic=socket,out,2,127.0.0.1,16661,udp,fgcom-mumble`" to your launcher)
- start using your radio stack (standard FGCom PTT is space for COM1 and shift-space for COM2)

### OpenRadar specific
Currently, OpenRadar just supports one Radio per UDP port. In case you want several Radios (which is likely), you need to invoke several dedicated mumble processes. This will give you separate FGCom-mumble plugin instances listening on different ports, and in OpenRadar you can thus specify that ports.

### ATC-Pie specific
Currently ATC-Pie has the same issue (and the same workaround) as OpenRadar. There is a development version in the works that will enable better FGCom-mumble support.

Currently, for each instance of ATC-Pie you will need a linked mumble client session. This applies for example, if you want to simultaniosly service several Airports, or additional CTR.  
Once the ATC-Pie version with FGCom-mumble support is out, you just need to adjust the *local UDP port* option at the *start session* dialog to contain a uniqhe UDP source port per ATC-Session.


Support for FGCom special frequencies
-------------------------------------
A common thing is that pilots may want to easily test if their setup works. This is implemented trough some special bots as well as the plugin itself. Also, FGCom-mumble has builtin special frequencies with alternative behaviour.

Please note there is no global-chat frequency. If you want to globally chat, switch to normal mumble channels or use the landline feature (tune a `PHONE` frequency, see below).

### ATIS Recording
ATIS Recording is provided by a specialized server side bot. Look for the bot in mumbles channel list to see if the server supports ATIS recordings.

To record an ATIS sample, you need to:

- Setup your Callsign to the target one. The replay-bot will use that callsign to identify itself
- Setup your location on earth; pay attention to a proper height as this will mainly determine the range of the signal
- Tune a COM device to frequency `RECORD_<tgtFrq>`
- Start talking on the COM device by pressing its PTT
- When done, release PTT and retune to a normal frequency.

Regular recordings have a serverside limit of 120 seconds by default.

Note: Chances are good that your ATC client does all this for you and you just need to push some "Record ATIS" button.

### Landlines/Intercom
Landlines/Intercom connections are a feature meant to be used by ATC instances. They are not subject to radio limits like range or signal quality. They operate worldwide.

To talk on an intercom/landline connection:

- Tune a COM device to frequency `PHONE:[ICAO]:[POS](:[LINE])`, like `PHONE:EDDM:TWR:1` or `PHONE:EDMO:GND`.
- Use your PTT as usual

Note: Chances are good that your ATC client does set this up for you and provides some "Talk on Intercom" button.


### Test frequencies
Test frequencies are provided by a specialized server side bot. Look for the bot in mumbles channel list to see if the server supports Test frequencies.

  - 910.000 MHz: echo test frequency. Your voice will be echoed back after you release PTT, to allow you to check that your microphone, speakers/headset and that your connection to the FGCom server works and to let you know how you are heared from others. Test recordings are limited to 10 seconds by default.
  - NOT-IMPLEMENTED-YET: 911.000 MHz: The frequency continuously plays a test sample, allowing you to check that your connection to the FGCom server works.


### Obsolete legacy FGCom frequencies
The following traditional FGCom frequencies are not special anymore; these are now implemented trough "default" comms (they were special before because of asterisk implementation details).

- 121.000 MHz, 121.500 MHz: "guard" frequencies reserved for emergency communications;
- 123.450 MHz, 123.500 MHz, 122.750 MHz: general chat frequencies;
- 700.000 MHz: radio station frequency. Depending on the FGCom server in use, a recorded radio message will be played;
- 723.340 MHz: French Air Patrol communication frequency;


###  Special FGCom-mumble frequencies
- `<del>`: Providing this frequency will deregister the radio. A Radio on this frequency is never operable and thus never sends or receives transmissions.


Troubleshooting
------------------------
When you cannot hear other pilots or are unable to transmit on the radios, you can check the following:

- Make sure, your mumble is operational otherwise (so you can talk with others)
- Try to check against the FGCOM-Echo bot (tune 910.00 and transmit something; but needs the bot manager alive on the server)
- Check that you are not transmitting when you expect incoming messages (Radios are halfduplex -> look at your mumble symbol)
- Recheck the tuned frequencies and volume of radio and, if present, audio panel
- Make sure the radio is operable (powered, switched on, serviceable)
- Check that you really are in range (low altitude severely limits your available range!)
- Try to leave and rejoin the channel, so the plugin reinitializes
- Check that your software (ATC, flightsim) actually sends data to the plugin udp port. recheck the port the plugin listens to (the plugin tells you at startup in the mumble chat window)
- Look at the plugins debug messages (start mumble from terminal; you need to make a debug build for that)


Compiling the plugin
======================
The FGCom-mumble client plugin needs to be in binary form. If you want to use the latest code from github, you can compile yurself.   

- Prerequisites: `make`, `g++`, `mingw32` (for windows build)
- Go to the folder `client/mumble-plugin/`
- on linux type `make`
- or `make all-win64` for cross-compile to windows

Other interesting compile targets:

  - `make` is an alias for `make all`
  - `make all` builds for linux: the libs, the plugins and the test tools in test directory
  - `make all-debug` will build that too but add
 debug code that will print lots of stuff to the terminal window when running the plugin
  - `make plugin` will build just the the plugin for linux
  - `make plugin-win64` will build it for windows
  - `make release` builds a tar.gz and a zip containing linux/windows binaries
