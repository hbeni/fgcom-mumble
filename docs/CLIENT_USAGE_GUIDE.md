# FGCom-mumble Client Usage Guide

**Complete guide for using FGCom-mumble with various flight simulators and clients**

## Running the Client

- Connect your mumble client to fgfs mumble server
- Enable your plugin in your standard mumble client
- Join a channel starting with `fgcom-mumble`

You are ready for radio usage! Some client needs to supply information to the plugin now, so it knows about your location and radio stack.

### API Integration (v2.0+)
FGCom-mumble v2.0+ provides comprehensive API integration for external applications:

- **RESTful API**: HTTP endpoints for propagation data, solar conditions, band status, antenna patterns, vehicle dynamics, power management, and system status
- **Band Segments API**: Read-only access to amateur radio frequency allocations, power limits, and regional restrictions
- **Preset Channel API**: Read-only access to preset channel information for radio models (AN/PRC-152 with 99 presets)
- **WebSocket Real-time Updates**: Live propagation updates, solar data changes, vehicle position tracking, and system monitoring
- **Client Examples**: JavaScript, Python, and C++ integration examples provided
- **Authentication**: API key management with secure storage and rotation
- **Rate Limiting**: Built-in abuse detection and prevention
- **Documentation**: Complete API reference with request/response examples

See [API Documentation](API_DOCUMENTATION.md), [Band Segments API Documentation](BAND_SEGMENTS_API_DOCUMENTATION.md), [Preset Channel API Documentation](PRESET_CHANNEL_API_DOCUMENTATION.md), [Noise Floor Distance Guide](NOISE_FLOOR_DISTANCE_GUIDE.md), [Environment Detection Guide](ENVIRONMENT_DETECTION_GUIDE.md), and [GPU Acceleration Guide](GPU_ACCELERATION_GUIDE.md) for complete integration details.

## Generic Compatibility

The plugin aims to be compatible to the legacy fgcom-standalone protocol, so very much all halfway recent fgfs instances, ATC clients and aircraft should handle it out of the box at least with COM1.

Note that frequencies can be arbitrary strings. That said, all participating clients must share a common definition of "frequency", this should be the physical radio wave frequency in MHz and not the "channel" (esp. with 8.3 channels spacing).  
Also note that callsigns and frequencies are not allowed to contain the comma symbol (`,`). Decimal point symbol has always to be a point (`.`).

The connected simulator is expected to provide PTT-information in order to activate radio transmissions, but you may also use the configfile to define mappings for mumble's internal voice activation. This way, you can use mumbles own PTT-binding to activate the radios you mapped. By default, the first Radio is already mapped for your convenience.

## RadioGUI

FGCom-mumble releases ship with a cross-platform java application that implements most of the UDP protocol and thus can be used not only for testing purposes, but also real operations without the need for another client.  
Core features are supported by any radioGUI version but use the latest to be sure to get all features (if in doubt, read the release notes).

### SimConnect (MSFS-2020) Support
RadioGUI can act as a SimConnect bridge to support MSFS2020 and other SimConnect compatible simulators (P3d, FSX, etc).
For details on how this can be done, look at RadioGUI's readme.

## FlightGear Specific

Just add and activate the [FGFS-addon](client/fgfs-addon/Readme.md) in your launcher (you can use FGCom-Mumble and the old FGCom in parallel).

The FGFS protocol file will handle old 25kHz as well as newer 8.3kHz radios.
After starting flightgear, you can use your radio stack like with FGCom (default is *space* to talk on COM1, *shift+space* for COM2, *alt+space* for COM3 and *ctrl+space* for intercom). Additional radios can be accessed by adding custom keybinds, or by using the _Combar_.  
The addon can be configured via a new entry in the *Multiplayer* menu.

Your ADF will recognize transmissions in the kHz range. With enabled _ADF_-mode the indicated bearing is recognized and visible on the instrument. The plane's audio system may also playback the received analog audio signal. This is usually switched at your plane's audio panel.

## ATC-Pie Specific

Since ATC-Pie v1.7.1 FGCom-mumble is supported out of the box.
Be sure to activate the fgcom-mumble option however, as the standard fgcom support does only work with COM1.

## OpenRadar Specific

Currently, OpenRadar just supports one Radio per UDP port. In case you want several Radios (which is likely), you need to invoke several dedicated mumble processes. This will give you separate FGCom-mumble plugin instances listening on different ports, and in OpenRadar you can thus specify that ports.

For better FGCom-mumble support, [patches are already pending](https://sourceforge.net/p/openradar/tickets/) and there is a [binary package available](http://fgcom.hallinger.org/OpenRadar_fgcom-mumble.jar).  
With that patches, you can select FGCom-mumble and then kindly add the same port for each radio (like "`16661,16661`" to get two radios connected to your single plugin instance).

## Radio Communication Issues

When you cannot hear other pilots or are unable to transmit on the radios, you can check the following:

- Make sure, your mumble is operational otherwise (so you can talk with others)
- Check mumbles client comment if the callsign and radio frequencies are registered
- Check the status webpage if it shows your entry (shows the data others receive from you)
- To send, you need to activate the PTT of the radio (pressing mumbles native PTT-key is just mapped to COM1 by default).
- Try to check against the FGCOM-Echo bot (tune 910.00 and transmit something; but needs the bot manager alive on the server)
- Check that you are not transmitting when you expect incoming messages (Radios are halfduplex -> look at your mumble symbol)
- Recheck the tuned frequencies and volume of radio and, if present, audio panel
- Make sure the radio is operable (powered, switched on, serviceable)
- Check that you really are in range (low altitude severely limits your available range!)
- Try to leave and rejoin the channel, so the plugin reinitializes; or restart mumble.
- Check that your software (ATC, flightsim) actually sends data to the plugin udp port. Recheck the port the plugin listens to (the plugin tells you at startup in the mumble chat window)
- Look at the plugins debug messages (start mumble from terminal; you need to make a debug build for that)
  - Look at the murmur server log for possible dropped plugin messages (look for the string `Dropping plugin message`), they may cause out of sync state. Reasons can be:
    - the setting *`pluginmessagelimit`* in `murmur.ini` may be too restrictive.
    - a bug in the plugin-io code: The plugin is expected to work well with default settings, so dropped messages may indicate a plugin bug; especially if they appear rapidly over a longer time.

## Troubleshooting

For detailed troubleshooting information, see [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md).

## Special Features

For information about special frequencies and features, see [Special Frequencies Guide](SPECIAL_FREQUENCIES_GUIDE.md).

## Configuration

For detailed configuration options, see [Installation Guide](INSTALLATION_GUIDE.md#plugin-configuration).
