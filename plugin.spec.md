FGCom mumble plugin specification
=================================
This document describes the technical specifications for the plugins interna as well as IO interfaces.

The basic idea is that the plugin is some intelligent mute/unmute manager for the mumble client. The muting/unmuting is governed by the underlaying radio simulation, i.e. the radios state, tuned frequencies and location.
These states should be provided to the plugin in an application agnostic manner, so it's easy to inteface as well as to flightgear and also third party ATC clients; and maybe also other flightsims...


Initialization
--------------
The plugin initializes with emtpy internal data.
When receiving local input dat (see below), the internal state is updated (ie new radios get registered, frequencies set etc).

If joining the special mumble channel `fgcom-mumble`, the plugin will locally mute all clients.  
When leaving that special channel, the plugin enters some 'noop' state so it will continue to collect updates from other client plugins, but mumble communication is unaffected otherwise.

Your local microphone will get muted when entering the special channel, as well as unmuted when leaving it.


Internal state
--------------
The plugin tracks the following state:

- Per radio:
  - tuned frequency
  - power knob on/off
  - electrical power availability
  - serviceable (is it failed?)
  - volume
  - ptt state of the radio
  - output watts of the radio
- Location:
  - latitutde
  - longitude
  - altitude
- Callsign


Plugin input data
-----------------
To get the needed data the plugin offers a simple network socket listening for updates on UDP Port **16661** (original FGCom port, it's compatible).  
This can easily be linked to an FGFS generic protocol or to an external application (like ATC-Pie or OpenRadar) to push updates to the plugin.

Each packet contains ASCII-data in a single string with several `Field=Value` variables set. Fields are separated using comma. Records are separated using newline. The plugin will parse the incoming string field by field. Empty values ("`Field=,`") are to be ignored; in case the field was not initialized previously, sane defaults should be assumed.

*For example*, if just a new frequency is submitted, it will just update that frequency. If the radio was not registered previously, a new instance will be created that defaults to "operational", until updates say otherwise (this is to support easy integration of ATC clients that do not want to simulate radio failures for example).

Parsed fields are as following (`COM`*n*`_`\* fields are per radio, "*n*" denotes a number starting from `1`):

| Field          | Format | Description                             | Default    |
|----------------|--------|-----------------------------------------|------------|
| `COM`*n*`_FRQ` | String | Selected frequency (arbitary string!)   | *mandatory*|
| `COM`*n*`_VLT` | Numeric| Electrical power; >0 means "has power"  | `12`       |
| `COM`*n*`_PBT` | Bool   | Power button state: 0=off, 1=on         | `1`        |
| `COM`*n*`_SRV` | Bool   | Serviceable: 0=failed, 1=operable       | `1`        |
| `COM`*n*`_PTT` | Bool   | PushToTalk: 0=off, 1=pushed/transmitting| `0`        |
| `COM`*n*`_VOL` | Float  | Volume: 0.0=mute, 1.0=full              | `1.0`      |
| `COM`*n*`_PWR` | Float  | Transmitting power in watts.            | `10.0`     |
| `LON`          | Float  | Longitudinal position                   | *mandatory*|
| `LAT`          | Float  | Latidunal position                      | *mandatory*|
| `ALT`          | Int    | Altitude in ft above sea-level          | *mandatory*|
| `CALLSIGN`     | String | Callsign (arbitary string)              | `ZZZZ`     |


The following fields are known from the old flightgear asterisk FGCom protocol and supported for compatibility reasons:

| Field | Format | Description                                                                                        |
|-------|--------|---------------------------------------------------------------------------------------------------|
| `PTT` | Int    | Currently active PTT radio (0=none, 1=COM1, 2=COM2). Gets converted to new `COM`*n*`_PTT` updates.|
| `OUTPUT_VOL` | Float | Output volume. Gets converted to a call to all available `COM`*n*`_VOL` instances. |


Plugin output data
------------------
### Mumble Plugin interface
The plugin will broadcast its state (callsign, listen/send frequencies, ptt-state, location, tx-power) to the other plugins using the mumble internal plugin interface (TCP based). Other plugins will pick this up and update their internal knowledge of the other users.

The data packets are constructed as following: The first sequence of bytes must form the ASCII-string `fgcom`. Only such packets are allowed to be processed from the plugin, other packets do no belong to the fgcom-implementation.

TODO: Design the protocol fields needed. Afte the plugin-ID we need some packet type and then the payload. Maybe make it easy and define an "update" type whose payload is FIELD=VALUE or something, probably best binary encoded; and then we can broadcast every change individually (order does not matter much here...)
Note: Thos types are needed so far:
- hello: Client tells other clients, that he is new and now activated the plugin and as uch can start to receive updates. Other clients should respond with their current state.


Transmitting radio transmissions
--------------------------------
When the plugin detects a change in one of the `COM`*n*`_PTT` fields, it will first check the affected radio(s) state: Is there power? is it turned on? is it serviceable?  

If yes, the PTT state change is transferred to other fgcom clients via mumbles plugin interface. Then your microphone is unmuted as long as at least one `COM`*n*`_PTT` remains `1`. Mumble will then transfer your voice as usual. After PTT is released, the change gets broadcasted again and mic muted.


Receiving radio transmissions
-----------------------------
When another client sends an PTT update, the plugin will check the state: Which frequency did the sender use (lookup PTT->radio->frequency)? is one of our radios tuned to that frequency? Is our radio powered/on/serviceable? Is the sender in range (distance and tx-power)?  

If yes, the sending client is locally unmuted, so you can hear the standard mumble voice data (additional adjustments of the audio stream may apply, like static-noise and volume adjustments).
When the PTT switches back to `0`, the sender is locally muted again.


Simple radio wave model
----------------
When receiving radio transmissions, it is important to see if the sender is in range. Frequencies are reused around the globe and so this is the only way to distinguish between neabry transmitters and the ones on the other side of the globe.

As a first draft, the plugin implements a simple radio wave propagation model that solely takes the output power and distance of the sender into account.
It is currently modelled very simply, so that the tx-power of 10W approximates linearly to 50 nautical miles in flat coordinate distance (i got this number for the Bendix KX165A by googling). The main purpose is pilots geographic radio net separation and not realistic range behaviour at this time.  
Please note that currently no (to me) known flightgear aircraft sets the radios tx-power, so it defaults to 10W/50nM (like current FGCom does).

In the future we surely should refine this model to be way more realistic (see https://en.wikipedia.org/wiki/Radio_propagation); maybe take even the terrain (mountains etc) and maybe also the weather into account.  
A good first step would probably be to add static noise and lessen volume for very distant senders, and to provide realistic numbers for the range/watts.