FGCom mumble plugin specification
=================================
This document describes the technical specifications for the plugins interna as well as IO interfaces.

The basic idea is that the plugin is some intelligent send/receive manager for the mumble client. The sending/receiving is governed by the underlaying radio simulation, i.e. the radios state, tuned frequencies and location.
These states should be provided to the plugin in an application agnostic manner, so it's easy to inteface as well as to flightgear and also third party ATC clients; and maybe also other flightsims...  
I have chosen a simple, text based UDP protocol for this reason.


Initialization
--------------
The plugin initializes with emtpy internal data.
When receiving local input dat (see below), the internal state is updated (ie new radios get registered, frequencies set etc).

If joining the special mumble channel `fgcom-mumble`, the plugin will start to handle all clients audio streams in that channel.  
When leaving that special channel, the plugin enters some 'noop' state so it will continue to collect updates from other client plugins, but mumble communication is unaffected otherwise.

Your local microphone will get switched to push-to-talk mode when entering the special channel (as well as restored when leaving it). When activating your flightsims PTT button on a radio, it will get switched on if that radio is operable.


State Updates
---------------
Communication between plugins is handled by mumbles internal plugin data interface.

When entering the fgcom-channel, your client will start to broadcast its state (and following changes) to remote clients.

Each time a new client joins the fgcom channel, local plugins will broadcast their state to that client to get it updated with current data.


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
This can easily be linked to an FGFS generic protocol or to an external application (like ATC-Pie or OpenRadar) to push updates to the plugin. If that port cannot be bound for some reason, the plugin will try 10 consecutive following ports before failing. The actually used port is reported in the mumble client.

Each packet contains ASCII-data in a single string with several `Field=Value` variables set. Fields are separated using comma. Records are separated using newline. The plugin will parse the incoming string field by field. Empty values ("`Field=,`") are to be ignored; in case the field was not initialized previously, sane defaults should be assumed. Fields are parsed from left to right; following repetitions of fields will overwrite earlier occurrences unless the latter value is emtpy. Field ordering is important only in this regard, but otherwise not significant.

*For example*, if just a new frequency is submitted, it will just update that frequency. If the radio was not registered previously, a new instance will be created that defaults to "operational", until updates say otherwise (this is to support easy integration of ATC clients that do not want to simulate radio failures for example).


### Core data
Parsed fields are as following (`COM`*n*`_`\* fields are per radio, "*n*" denotes a number starting from `1`):

| Field          | Format | Description                             | Default    |
|----------------|--------|-----------------------------------------|------------|
| `COM`*n*`_FRQ` | String | Selected frequency (arbitary string!) The string provided will be stripped from leading space and zeroes, and trailing spaces and zeroes after a decimal point. A value of `<del>` can be used to deregister a radio.  | *mandatory*|
| `COM`*n*`_VLT` | Numeric| Electrical power; >0 means "has power"  | `12`       |
| `COM`*n*`_PBT` | Bool   | Power button state: 0=off, 1=on         | `1`        |
| `COM`*n*`_SRV` | Bool   | Serviceable: 0=failed, 1=operable       | `1`        |
| `COM`*n*`_PTT` | Bool   | PushToTalk: 0=off, 1=pushed/transmitting| `0`        |
| `COM`*n*`_VOL` | Float  | Volume: 0.0=mute, 1.0=full              | `1.0`      |
| `COM`*n*`_PWR` | Float  | Transmitting power in watts.            | `10.0`     |
| `COM`*n*`_SQC` | Float  | Squelch setting (0.0=off, 1.0=full)     | `0.10`     |
| `LAT`          | Float  | Latitudinal position (decimal: 12.34567)| *mandatory*|
| `LON`          | Float  | Longitudinal position (decimal)         | *mandatory*|
| `HGT`          | Float  | Altitude in ft above ground-level       | *mandatory* (if `ALT` not given)|
| `CALLSIGN`     | String | Callsign (arbitary string)              | `ZZZZ`     |


### Legacy FGCom fields
The following fields are known from the old flightgear asterisk FGCom protocol and supported for compatibility reasons:

| Field        | Format | Description                                                                                       |
|--------------|--------|---------------------------------------------------------------------------------------------------|
| `ALT`        | Int    | Altitude in ft above sea-level. If both `HGT` and `ALT` is present in the UDP packet, `HGT` takes precedence. If only `ALT` is given, the radio horizon is artificially bigger than it should be, as we have no terrain model right now. |
| `PTT`        | Int    | Currently active PTT radio (0=none, 1=COM1, 2=COM2). Gets converted to new `COM`*n*`_PTT` updates.|
| `OUTPUT_VOL` | Float  | Output volume. Gets converted to a call to all available `COM`*n*`_VOL` instances. |


### Configuration options
The Following fields are configuration options that change some behaviour.

| Field          | Format | Description                             | Default    |
|----------------|--------|-----------------------------------------|------------|
| `COM`*n*`_RDF` | Bool   | Set to `1` to enable RDF output for signals received on this radio (details below: "*UDP client interface / RDF data*")   | `0`|


### Testing UDP input
Aside from using real clients, the UDP input interface can be tested using the linux tool "`netcat`": `echo "CALLSIGN=TEST1,COM1_FRQ=123.45" | netcat -q1 -u localhost 16661`
sets the callsign and frequency for COM1.


Plugin output data
------------------
### Mumble PluginData interface
The plugin will broadcast its state (callsign, listen/send frequencies, ptt-state, location, tx-power) to the other plugins using the mumble internal plugin data interface (TCP based). Other plugins will pick this up and update their internal knowledge of the other users.

The data packets are ASCII based and constructed as following: The `dataID` field must start with the string `FGCOM`. Only such packets are allowed to be processed from the plugin, other packets do no belong to the fgcom-implementation and are ignored.

The following bytes in the `dataID` field denote the packet type. Each packet consists of a comma-separated sequence of `KEY=VALUE` pairs and empty values are to be ignored too:

- `FGCOM:UPD_LOC` keys a location data update package:
  - `LON` (decimal)
  - `LAT` (decimal)
  - `ALT` (height above ground in meters, not to be confused with ALT from UDP packet!)
  - `CALLSIGN`
- `FGCOM:UPD_COM:`*n* keys a radio data update for radio *n* (=radio-id, starting at zero; so COM1 = `0`)
  - `FRQ`
  - `VLT` (not transmitted currently)
  - `PBT` (not transmitted currently)
  - `PTT`
  - `VOL` (not transmitted currently)
  - `PWR`
- `FGCOM:ICANHAZDATAPLZ` asks already present clients to send all state to us


### UDP client interface
The plugin can send information via an UDP interface to third party software at max 10Hz to localhost UDP port **19991**.

The packet format is similar to the UDP input format: a simple `Key=Value` ASCII string. Values are separated using comma, each packet is terminated by newline.  
If there is not data to send, nothing will be transmitted over the wire.  
Unknown fields or empty ones (eg. `Field=`) are to be ignored when parsing.

#### RDF data
While the plugin receives a signal trough a RDF-enabled radio (`COM`*n*`_RDF=1`, see *Plugin input data* above), it will send RDF packets.  
Absence of RDF data means that there is currently no such transmission.

RDF data is composed with the following fields. As the possibility exists that several
parallel transmissions are received, the ID *id* is put before the fields.  
*id* is composed like "`<mumble session id>-<radioID>`".

| Field                 | Format | Description                             |
|-----------------------|--------|-----------------------------------------|
| `RDF_`*id*`_CALLSIGN` | String | Callsign of the sender                  |
| `RDF_`*id*`_FRQ`      | String | Frquency of the signal                  |
| `RDF_`*id*`_DIR`      | Float  | Direction to the signal source (`0.0` to `359.99`; `0.0`=due WSG84 north)|
| `RDF_`*id*`_VRT`      | Float  | Vertical angle to the signal source (`-90.0` to `+90.0`; `0.0`=straight)|
| `RDF_`*id*`_QLY`      | Float  | Signal quality (`0.00` to `1.0`)        |

The `DIR` and `VRT` angles are in degrees and to be interpreted "as viewed from you to the signal source".  For example, assume you are an ATC station and receive `RDF_1-0_DIR=180.5,RDF_1-0_VRT=12.5`: The Airplane transmitting is thus directly south and above of you.  
The values are true bearings relative to your position, and `DIR=0.0` is due north relative to the WSG84 grid.

#### Checking UDP client output
Aside from using real clients, the UDP output can be displayed using the linux tool "`netcat`": `netcat -l -u -p 19991` will display all sent UDP packets to port 19991.


Transmitting radio transmissions
--------------------------------
When the plugin detects a change in one of the `COM`*n*`_PTT` fields, it will first check the affected radio(s) state: Is there power? is it turned on? is it serviceable?  

If yes, the PTT state change is transferred to other fgcom clients via mumbles plugin interface. Then your microphone is activated as long as at least one `COM`*n*`_PTT` remains `1` and its radio remains operational. Meanwhile Mumble will transfer your voice as usual. After PTT is released, the change gets broadcasted again and your mic deactivated.


Receiving radio transmissions
-----------------------------
When another client sends an audio stream, the plugin will check the remote clients state: Which frequency did the sender use (lookup PTT->radio->frequency)? is one of our radios tuned to that frequency? Is our radio powered/on/serviceable? After that, the signal strength is computed using the radio model to detect if the signal is strong enough.

If yes, the sending clients audio stream is let trough, so you can hear the standard mumble voice data (additional adjustments of the audio stream may apply, like static-noise and volume adjustments).

If either your radio is not operational or not tuned to the same frequency or not in range, the adio stream is canceled out, so you will not be able to hear it.


Simple radio wave model
------------------------
When receiving radio transmissions, it is important to see if the sender is in range. Frequencies are reused around the globe and so this is the only way to distinguish between nearby transmitters and the ones on the other side of the globe.

As a first draft, the plugin implements a simple radio wave propagation model that solely takes the output power, distance and line-of-sight of the sender into account (ie. a VHF radio model).  
It is currently modelled very simply, so that the tx-power of 10W approximates linearly to 50 nautical miles in flat coordinate distance (i got this number for the Bendix KX165A by googling). The main purpose is pilots geographic radio net separation and not realistic range behaviour at this time.  
Please note that currently no (to me) known flightgear aircraft sets the radios tx-power, so it defaults to 10W/50nM (like current FGCom does).

In the future we surely should refine this model to be way more realistic (see https://en.wikipedia.org/wiki/Radio_propagation); maybe take even the used antenna, the terrain (mountains etc) and maybe also the weather into account.  
A good first step would probably to provide more realistic numbers for the range/watts and static noise/volume numbers for very distant senders. Also another basic radio model for HF communications would be nice.
