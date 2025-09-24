FGCom mumble plugin specification
=================================
This document describes the technical specifications for the plugins interna as well as IO interfaces.

The basic idea is that the plugin is some intelligent send/receive manager for the mumble client. The sending/receiving is governed by the underlaying radio simulation, i.e. the radios state, tuned frequencies and location.
These states should be provided to the plugin in an application agnostic manner, so it's easy to inteface as well as to flightgear and also third party ATC clients; and maybe also other flightsims...  
I have chosen a simple, text based UDP protocol for this reason.


Initialization
--------------
The plugin initializes with emtpy internal data and default configuration options.

After loading, the plugin searches for a config file in various locations, whose contents will be parsed (the format is ini-style, e.g `key=value`, comments start with `;`). Contents overwrite previously set state, so there can be potentially an hierarchy of config files. The [example `fgcom-mumble.ini`](mumble-plugin/fgcom-mumble.ini) shows what options are supported currently. Installation and update instructions (like paths) are given in the [client `README.md`](../README.md) file.

When receiving local input data (see below), the internal state is updated (ie new radios get registered, frequencies set etc).

If joining a mumble channel starting with `fgcom-mumble`, the plugin will start to handle all clients audio streams in that channel.  
When leaving that special channel, the plugin enters some 'noop' state so it will continue to collect updates from other client plugins, but mumble communication is unaffected otherwise.

Your local microphone will get switched to push-to-talk mode when entering the special channel (as well as restored when leaving it). When activating your flightsims PTT button on a radio, it will get switched on if that radio is operable.


Internal state
--------------
Internal state is bound to an "identity". Each plugin instance can handle multiple identities. The identity IID is to be considered local and derived from the client port of the received UDP messages (so the first received port creates the default identity, and other ports respective additional identities).  
Usually the plugin has only one identity (especially with flightsims), however some ATC-clients may register additional ones to service more than one location per session.  
The plugis internal state is cleaned from outdated data regularly.

The plugin tracks the following state per identity:

- Callsign
- Location:
  - latitutde
  - longitude
  - altitude
- Per radio:
  - tuned carrier frequency
  - power knob on/off
  - electrical power availability
  - serviceable (is it failed?)
  - volume
  - ptt state of the radio
  - output watts of the radio


Internal State Updates
----------------------
Communication between plugins is handled by mumbles internal plugin data interface.

When entering the `fgcom-mumble` channel, your client will broadcast its state (and following changes) to remote clients. Your client will then ask the already present clients in the channel for their state. Each remote client will then send his state to your client independently. (Both that actions will also occur if you activate your plugin while already inside the special channel).

Notification of other clients take place on special events (like joining the channel or activating the plugin) and potentially when new data is recieved trough the UDP input interface:

 - Radio state updates and userstate are sent immediately ("urgent" notification).
 - Locationdata is sent at most at a rate of 1 Hz ("non-urgent"). If said data did not change for a period of time (10 seconds), a "ping" notification will be sent to others, notifying that the own plugin is still connected and alive.
 - All state is sent in reply to the asking client on incoming data synchronization requests.


Plugin input data
-----------------
To get the needed data the plugin offers a simple network socket listening for updates on UDP Port **16661** (original FGCom port, it's compatible).  
This can easily be linked to an FGFS generic protocol or to an external application (like ATC-Pie or OpenRadar) to push updates to the plugin. If that port cannot be bound for some reason, the plugin will try 10 consecutive following ports before failing. The actually used port is reported in the mumble client.

Each packet contains ASCII-data in a single string with several `Field=Value` variables set, and total packet length is restricted to 1024 bytes. Fields are separated using comma and restricted to 32 chars each. Records are separated using newline. The plugin will parse the incoming string field by field. Empty values ("`Field=,`") are to be ignored; in case the field was not initialized previously, sane defaults should be assumed. Fields are parsed from left to right; following repetitions of fields will overwrite earlier occurrences unless the latter value is emtpy. Field ordering is important only in this regard, but otherwise not significant. Floats are always expected with a point as decimal-point character. The field separator (`,`) is not allowed as field value.

*For example*, if just a new frequency is submitted, it will just update that frequency. If the radio was not registered previously, a new instance will be created that defaults to "operational", until updates say otherwise (this is to support easy integration of ATC clients that do not want to simulate radio failures for example).

The plugis internal state is cleaned from outdated data regularly. Any succesfull field parsing will update the `lastUpdate` timestamp for the affected identity, so UDP clients are expected to send data regularly (eg. every few seconds; for example the callsign).


### Core data
All participating clients must share a common definition of "frequency", and this should be the physical radio wave frequency and not the "channel" (esp. with 8.3 channels spacing).

Parsed fields are as following (`COM`*n*`_`\* fields are per radio, "*n*" denotes a number starting from `1`):

| Field          | Format | Description                             | Default    |
|----------------|--------|-----------------------------------------|------------|
| `LAT`          | Float  | Latitudinal position (decimal: 12.34567)| *mandatory*|
| `LON`          | Float  | Longitudinal position (decimal)         | *mandatory*|
| `HGT`          | Float  | Altitude in ft above ground-level       | *mandatory* (if `ALT` not given)|
| `CALLSIGN`     | String | Callsign (arbitary string)              | `ZZZZ`     |
| `COM`*n*`_FRQ` | String | Selected frequency (arbitary string or wave carrier frequency as float with minimum 4 decimals precision in MHz; see below section for details). A value of `<del>` can be used to deregister a radio.  | *mandatory*|
| `COM`*n*`_VLT` | Numeric| Electrical power; >0 means "has power"  | `12`       |
| `COM`*n*`_PBT` | Bool   | Power button state: 0=off, 1=on         | `1`        |
| `COM`*n*`_SRV` | Bool   | Serviceable: 0=failed, 1=operable       | `1`        |
| `COM`*n*`_PTT` | Bool   | PushToTalk: 0=off, 1=pushed/transmitting| `0`        |
| `COM`*n*`_VOL` | Float  | Volume: 0.0=mute, 1.0=full              | `1.0`      |
| `COM`*n*`_PWR` | Float  | Transmitting power in watts.            | `10.0`     |
| `COM`*n*`_SQC` | Float  | Squelch setting (0.0=off, 1.0=full)     | `0.10`     |
| `COM`*n*`_CWKHZ`| Float | Channel width in kHz                    | default depends on radio model (`8.33` for VHF) |



### Legacy FGCom fields
The following fields are known from the old flightgear asterisk FGCom protocol and supported for compatibility reasons:

| Field        | Format | Description                                                                                       |
|--------------|--------|---------------------------------------------------------------------------------------------------|
| `COM`*n*`_FRQ` | Float | Selected MHz channel frequency, gets converted to carrier frequency (see section below)  | *mandatory*|
| `ALT`        | Int    | Altitude in ft above sea-level. If both `HGT` and `ALT` is present in the UDP packet, `HGT` takes precedence. If only `ALT` is given, the radio horizon is artificially bigger than it should be, as we have no terrain model right now. |
| `PTT`        | Int    | Currently active PTT radio (0=none, 1=COM1, 2=COM2). Gets converted to new `COM`*n*`_PTT` updates.|
| `OUTPUT_VOL` | Float  | Output volume. Gets converted to a call to all available `COM`*n*`_VOL` instances. |

#### `COM`*n*`_FRQ` handling for "channel names"
The implementation internally operates on the basic common denominator, the carrier wave frequency. However, the selected radio model implementation may support "channel name" notion (like 8.33 vs. 25kHz VHF channels).  
Therefore the internal radio model may convert such "channel names" to the real wave frequency (refer to the section _Radio wave models_ for supported ones):

- if the supplied frequency is *numeric* and at least four digits precision, it is assumed a "real wave frequency" and used as-is.
- if the supplied frequency is *non-numeric* (eg. `PHONE:`... etc) it is used as-is.
- if the supplied frequency is *the recorder one* (`RECORD_<tgtFrq>`), the frequency part is subject to channel-conversion.
- if the supplied frequency *is* numeric, the frequency will be inspected for known "channel names". If so, it gets converted to the respective carrier frequency (like 25kHz `118.025` => `118.0250`; or 8.33kHz `118.015` => `118.0167`).


### Configuration options
The Following fields are configuration options that change plugin behaviour.

| Field            | Format | Description                             | Default    |
|------------------|--------|-----------------------------------------|------------|
| `COM`*n*`_RDF`   | Bool   | Set to `1` to enable RDF output for signals received on this radio (details below: "*UDP client interface / RDF data*")   | `0`|
| `COM`*n*`_PUBLISH`| Bool  | Set to `0` to prevent this radio from being published anymore. Use this at the first the radio field!  | `1`|
| `AUDIO_FX_RADIO` | Bool   | `0` will switch radio effects like static off. | `1` |
| `AUDIO_HEAR_ALL` | Bool   | `1` will enable hearing of non-plugin users. | `0` |
| `COM`*n*`_MAPMUMBLEPTT` | Bool   | `1` switches PTT handling to mumbles own talking state and activates _this_ radios PTT when mumble activates talking.| COM1=`1`, others=`0` |
| `ALWAYSMUMBLEPTT` | Bool   | `1` will handle mumbles PTT upon activating any COM device's PTT, even when the plugin is not active.| `0` |


### Testing UDP input
Aside from using real clients (maybe use the supplied RadioGUI application), the UDP input interface can be tested using the linux tool "`netcat`": `echo "CALLSIGN=TEST1,COM1_FRQ=123.45" | netcat -q0 -u localhost 16661 -p 50001`
sets the callsign and frequency for COM1 for the default identity (make sure the `-p` source port stays the same for each identity).


### Special usecases
#### Allow hearing of non-plugin users
By default, unknown users are muted (those without valid plugin data sent and wich are unknown to the local instance, i.e. the ones without active plugin).  
Mixing plugin users and those without plugin is discouraged, because it may be the source of communcation confusion. In some special situations it might be beneficial to hear all users on the channel. An example for that is if you are the ATC, the mumble channel represents not the entire world but just a small region (your airport) and you want to serve FGCom-mumble users and parallel users without the plugin.  
Hearing others can be switched on using the configuration file.


#### Force Identities
Each UDP client is considered as one "identity" for the plugin and thus has its own state. In case your client application switches UDP ports randomly, you can manually select an identity to which to apply the UDP fields to.  
Normally this is not needed, as UDP clients are supposed to keep the port stable and receive data at their source port.

| Field            | Format | Description                             | Default    |
|------------------|--------|-----------------------------------------|------------|
| `IID`            | Int    | Switch context of following UDP fields to ID of the identity `IID`. IDD is starting from `0`.  | derived from UDP client port |
| `UDP_TGT_PORT`   | Int    | Switch the identities UDP target Port.  | send to UDP client port of the identity |


Plugin output data
------------------
### Mumble PluginData interface
The plugin will broadcast its state (callsign, listen/send frequencies, ptt-state, location, tx-power) to the other plugins using the mumble internal plugin data interface (TCP based). Other plugins will pick this up and update their internal knowledge of the other users.

The data packets are ASCII based and constructed as following:

The *dataID* field has the syntax `FGCOM:<packetType>[:<iid>[:<params>]]`; ie. it must start with the string `FGCOM` and following fields are separated by colon. Only such packets are allowed to be processed from the plugin, other packets do no belong to the fgcom-implementation and are ignored.  
The second field denote the fgcom packet type.  
For PacketTypes encoding identity information, the next field contains the identity *iid* (`0` denotes the default identity).  
After that, some PacketTypes can contain further parameters.

Each packets *payload* consists of a comma-separated string sequence of `KEY=VALUE` pairs (empty values are to be ignored too). Floats are always expected with a point as decimal-point character. Field values are restricted to 32 chars each.

The following internal plugin data packets are defined:

- `FGCOM:UPD_USR:`*iid* keys a userdata data update package:
  - `CALLSIGN`
- `FGCOM:UPD_LOC:`*iid* keys a location data update package:
  - `LON` (decimal)
  - `LAT` (decimal)
  - `ALT` (height above ground in meters, not to be confused with ALT from UDP packet!)
- `FGCOM:UPD_COM:`*iid*`:`*n* keys a radio data update for radio *n* (=radio-id, starting at zero; so COM1 = `0`)
  - `FRQ` the real wave carrier frequency in MHz
  - `CHN` a raw value (what was given from the client in `COMn_FRQ`)
  - `VLT` (volts; not transmitted currently)
  - `PBT` (power-switch; not transmitted currently)
  - `SRV` (serviceable; not transmitted currently)
  - `OPR` If radio is operable (result of `VLT`, `PBT`, `SRV`)
  - `PTT` If PTT is active
  - `VOL` (volume, not transmitted currently)
  - `PWR` tx power in Watts
  - `ANT_TYPE` antenna type (vertical, yagi, loop, whip, etc.)
  - `FREQ_BAND` frequency band for regulatory compliance (amateur, commercial, military)
  - `PWR_EFF` power efficiency (0.0-1.0)
  - `PWR_LIMIT` power limiting enabled (true/false)
  - `SWR` standing wave ratio
  - `TEMP` antenna temperature in Celsius
  - `BATTERY` battery level (0.0-1.0)
  - `BAND` amateur radio band (e.g., "20m", "40m")
  - `MODE` amateur radio mode ("CW", "SSB", "AM")
  - `GRID` Maidenhead grid locator (e.g., "FN31pr")
  - `AMATEUR` amateur radio flag (0=commercial, 1=amateur)
  - `REGION` ITU Region (1, 2, 3)
  - `HEADING` vehicle heading in degrees (0-360, true heading)
  - `SPEED` vehicle speed in knots
  - `COURSE` course over ground in degrees (0-360)
  - `PITCH` vehicle pitch angle in degrees (-90 to +90)
  - `ROLL` vehicle roll angle in degrees (-180 to +180)
  - `YAW` vehicle yaw angle in degrees (0-360)
  - `VS` vertical speed in feet per minute
  - `ALT_AGL` altitude above ground level in feet
  - `ANT_AZ` antenna azimuth in degrees (0-360)
  - `ANT_EL` antenna elevation in degrees (-90 to +90)
  - `ANT_ROT` antenna rotation speed in degrees per second
- `FGCOM:ICANHAZDATAPLZ` asks already present clients to send all state to us (payload is insignificant)
- `FGCOM:PING` keys a ping package and lets others know which local identities are still alive but don't had any updates for some time (payload is INT list of alive IIDs).


### UDP client interface
The plugin can send information via an UDP interface to third party software at max 10Hz. The UDP target address is taken from the respective identities client port (can be overridden by `UDP_TGT_PORT`). The client host and port is derived from the UDP input servers packet for the identity.  
If there is no data to send, nothing will be transmitted over the wire.  

The packet format is similar to the UDP input format: a simple `Key=Value` ASCII string. Pairs are separated using comma, each packet is terminated by newline. Floats are always output with a point as decimal-point character.  
Unknown fields or empty ones (eg. `Field=`) are to be ignored when parsing.

#### Header
If any data is generated, each UDP packet starts with a header that consists of the string `FGCOM`, followed by version information, finished by a newline (`\n`) character.

#### RDF data
While the plugin receives a signal trough a RDF-enabled radio (`COM`*n*`_RDF=1`, see *Plugin input data* above), it will send RDF data.  
Absence of RDF data means that there is currently no such transmission.  
Each RDF enabled radio can receive multiple signals. It is up to the client to sort this out (eg. maybe only consider the strongest signal for a given source).

Each active signal per radio is reported on a separate output line (separated by `\n`).  
The signal source is reported by starting the RDF message string with `RDF:`, followed by the RDF data fields.  
The reported frequency is the effective real wave frequency in MHz.

| Field      | Format | Description                                      |
|------------|--------|--------------------------------------------------|
| `CS_TX`    | String | Callsign of the sender                           |
| `FRQ`      | String | Real wave frequency of the signal in MHz         |
| `DIR`      | Float  | Direction to the signal source (`0.0` clockwise to `359.99`; `0.0`=due WGS84 north)|
| `VRT`      | Float  | Vertical angle to the signal source (`-90.0` to `+90.0`; `0.0`=straight)|
| `QLY`      | Float  | Signal quality (`0.00` to `1.0`)                 |
| `ID_RX`    | Int    | Receiving radio number (e.g. 1 for COM1)         |

The `DIR` and `VRT` angles are in decimal degrees and to be interpreted "as viewed from you to the signal source".  For example, assume you are an ATC station and receive `RDF:CS_TX=Test,FRQ=123.45,DIR=180.5,VRT=12.5,QLY=0.98,ID_RX=1`: The Airplane transmitting is thus directly south and above of you.  
The values are true bearings relative to your position, and `DIR=0.0` is due north relative to the WSG84 grid.

Radio Models and Propagation
-----------------------------
The plugin supports multiple radio frequency models with realistic propagation characteristics:

### HF (High Frequency) - 3-30 MHz
- **Aviation HF**: Long-range communication for transoceanic flights
- **Maritime HF**: Ship-to-shore and ship-to-ship communication
- **Amateur Radio**: Ham radio bands with realistic propagation
- **Military HF**: NATO and Eastern Bloc military frequencies

### VHF (Very High Frequency) - 30-300 MHz
- **Aviation VHF**: Air traffic control and pilot communication (118-137 MHz)
- **Maritime VHF**: Ship-to-ship and ship-to-shore communication (156-162 MHz)
- **Amateur Radio**: 2m band (144-146 MHz) with professional Yagi antennas
- **Ground Station**: 10m height base station antennas with extended range

### UHF (Ultra High Frequency) - 300+ MHz
- **Military UHF**: Tactical communication (225-400 MHz)
- **Amateur Radio**: 70cm band (430-440 MHz) with high-gain Yagi antennas
- **Ground Station**: Professional base station installations
- **Satellite Communication**: Linear transponder access

### Physics-Based Propagation
The system implements realistic radio wave propagation including:
- **Free Space Path Loss**: Distance and frequency-dependent signal attenuation
- **Atmospheric Absorption**: Weather-dependent signal loss
- **Tropospheric Ducting**: Extended range under favorable conditions
- **Antenna Height Gain**: Professional base station performance modeling
- **Terrain Obstruction**: Realistic signal blocking and diffraction

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
"Same frequency" thereby means case-sensitive string matching for non-numeric frequencies and a frequency overlap calculation from the radio model for numbers.


Radio wave models
------------------------
When receiving radio transmissions, it is important to see if the sender is in range. Frequencies are reused around the globe and so this is the only way to distinguish between nearby transmitters and the ones on the other side of the globe.

As a first draft, the plugin implements a set of simple radio wave propagation models in a continuous spectrum. The models support tuning bands, so a slight overlap and off-tuning can be simulated.  
The main purpose is pilots geographic radio net separation and not realistic range behaviour at this time.

- **HF** (below 30MHz): Long range capabilities with sky wave propagation behind the horizon.  
  Behind the horizon the signal will degrade a little, but otherwise the signal quality depends solely on distance and output power. No advanced characteristics (like time of day or sunspot cycle affecting the ionosphere) are taken into consideration yet.
- **VHF** (30MHz to 300MHz): line-of-sight propagation, no reception behind the radio horizon.  
  Altitude of sender/receiver, output power and distance affects signal quality and range. It is currently modelled very simply, so that the tx-power of 10W approximates linearly to 50 nautical miles in flat coordinate distance (i got this number for the Bendix KX165A by googling).  
Please note that currently no (to me) known flightgear aircraft sets the radios tx-power, so it defaults to 10W/50nM (like current FGCom does).  
The VHF model supports the notion of "channels" which get converted to real wave frequencies automatically (see `COMn_FRQ` description above).
- **UHF** (above 300MHz): Modelled like VHF but with reduced range per output watt. No advanced calculations for obstructions like trees/buildings are done yet.

In the future we surely should refine this model to be way more realistic (see https://en.wikipedia.org/wiki/Radio_propagation); maybe take even the used antenna, the terrain (mountains etc) and maybe also the weather into account.  
A very good next step would probably to provide more realistic numbers for the frequency spacings, range/watts and static noise/volume numbers for very distant senders; for that i need someone with radio transmission experience in that fields. The `client/test/geotest` utility can be queried for playing around with the numbers.
