# FGCom-mumble Special Frequencies Guide

**Complete guide to special frequencies and features in FGCom-mumble**

## Support for FGCom Special Frequencies

A common thing is that pilots may want to easily test if their setup works. This is implemented through some special bots as well as the plugin itself. Also, FGCom-mumble has built-in special frequencies with alternative behavior.

Please note there is no global-chat frequency. If you want to globally chat, switch to normal mumble channels or use the landline feature (tune a `PHONE` frequency, see below).

## ATIS (Automatic Terminal Information Service)

ATIS Recording and -playback is provided by a set of specialized server side bots. Look for the recorder bot in mumbles channel list to see if the server supports ATIS recordings.

### Recording
To record an ATIS sample, you need to:

- Setup your Callsign to the target one. The replay-bot will use that callsign to identify itself
- Setup your location on earth; pay attention to a proper height as this will mainly determine the range of the signal
- Tune a COM device to frequency `RECORD_<tgtFrq>`
- Start talking on the COM device by pressing its PTT
- When done, release PTT and retune to a normal frequency.

Regular recordings have a server-side limit of 120 seconds by default.

Note: Chances are good that your ATC client does all this for you and you just need to push some "Record ATIS" button.  
The RadioGUI has a tuning template for that. It may be a good idea to start a separate instance of the RadioGUI for recording in order to be able to leave the original client data untouched.

### Playback
If a `botmanager` is running at the server, the recorderbot will notify it to start a matching replay-bot. the recording user is by default authenticated to the playback bot and can thus manage it using chat commands (try saying `/help` to him to get started).

## Landlines/Intercom

Landlines/Intercom connections are a feature meant to be used by ATC instances. They are not subject to radio limits like range or signal quality. They operate worldwide and in full duplex.  
Landline channel names starts with `PHONE` and intercom with `IC:`. The difference between the two is audio characteristics.

To talk on an intercom/landline connection:

- Tune a COM device to frequency `PHONE:[ICAO]:[POS](:[LINE])`, like `PHONE:EDDM:TWR:1` or `PHONE:EDMO:GND`.
- Use your PTT as usual

Note: Chances are good that your ATC client does set this up for you and provides some "Talk on Intercom" button.

## Test Frequencies

Test frequencies are provided by a specialized server side bot. Look for the bot in mumbles channel list to see if the server supports test frequencies:

- **910.000 MHz**: echo test frequency. Your voice will be echoed back after you release PTT, to allow you to check that your microphone, speakers/headset and that your connection to the FGCom server works and to let you know how you are heard from others. Test recordings are limited to 10 seconds by default.
- **NOT-IMPLEMENTED-YET: 911.000 MHz**: The frequency continuously plays a test sample, allowing you to check that your connection to the FGCom server works.

## Obsolete Legacy FGCom Frequencies

The following traditional FGCom frequencies are not special anymore; these are now implemented through "default" comms (they were special before because of asterisk implementation details):

- **121.000 MHz, 121.500 MHz**: "guard" frequencies reserved for emergency communications;
- **123.450 MHz, 123.500 MHz, 122.750 MHz**: general chat frequencies (they are obsolete anyway since 8.33 channels where introduced 20.12.2019! -> new is 122.540, 122.555, 130.430 MHz);
- **700.000 MHz**: radio station frequency. Depending on the FGCom server in use, a recorded radio message will be played;
- **723.340 MHz**: French Air Patrol communication frequency.

## Special FGCom-mumble Frequencies

- **`<del>`**: Providing this frequency will deregister the radio. A Radio on this frequency is never operable and thus never sends or receives transmissions.

## Usage Examples

### Testing Your Setup
1. Tune to **910.000 MHz**
2. Press PTT and say "Testing, testing, one two three"
3. Release PTT - you should hear your voice echoed back
4. If you hear the echo, your setup is working correctly

### Recording ATIS
1. Set your callsign to the target airport (e.g., "KJFK")
2. Set your location to the airport coordinates
3. Tune to **RECORD_121.650** (replace with your target frequency)
4. Press PTT and read your ATIS information
5. Release PTT and retune to normal frequency

### Using Landlines
1. Tune to **PHONE:KJFK:TWR** for Kennedy Tower
2. Press PTT to talk to the tower
3. Release PTT to listen for responses

### Emergency Communications
1. Tune to **121.500 MHz** (emergency frequency)
2. Press PTT and state your emergency
3. Release PTT and listen for responses

## Troubleshooting Special Frequencies

### ATIS Not Working
- Check if the recorder bot is running on the server
- Verify your callsign is set correctly
- Ensure you're using the correct frequency format: `RECORD_<frequency>`
- Check that you're within range of the target frequency

### Test Frequency Not Working
- Verify the echo bot is running on the server
- Check that you're tuned to exactly 910.000 MHz
- Ensure your microphone and speakers are working
- Check that you're not transmitting when expecting the echo

### Landlines Not Working
- Verify the landline format: `PHONE:[ICAO]:[POS](:[LINE])`
- Check that the target ATC is online
- Ensure you're using the correct ICAO code
- Verify the position identifier is correct

## Server Configuration

For server administrators, special frequencies require specific bot configuration:

### ATIS Bot Configuration
```ini
[atis_bot]
enabled = true
max_recording_time = 120
auto_playback = true
```

### Echo Bot Configuration
```ini
[echo_bot]
enabled = true
test_frequency = 910.000
max_test_time = 10
```

### Landline Configuration
```ini
[landline]
enabled = true
worldwide_coverage = true
full_duplex = true
```

## Advanced Features

### Custom Test Frequencies
Server administrators can configure custom test frequencies:

```ini
[custom_test_frequencies]
911.000 = continuous_test
912.000 = range_test
913.000 = quality_test
```

### ATIS Management Commands
When authenticated to an ATIS bot, you can use these chat commands:

- `/help` - Show available commands
- `/play` - Start playback
- `/stop` - Stop playback
- `/status` - Show current status
- `/delete` - Delete the recording

## Integration with ATC Clients

Most ATC clients provide automatic integration with these special frequencies:

- **ATC-Pie**: Automatic ATIS recording and playback
- **OpenRadar**: Built-in test frequency support
- **RadioGUI**: Template for ATIS recording

Check your ATC client documentation for specific integration details.

## Best Practices

### For Pilots
- Always test your setup on 910.000 MHz before flying
- Use proper callsigns when recording ATIS
- Be aware of frequency usage and avoid cluttering test frequencies
- Use landlines for ATC communication when appropriate

### For ATC
- Set up proper ATIS recordings with clear, professional content
- Monitor test frequencies for pilot issues
- Use landlines for direct communication with pilots
- Maintain proper frequency discipline

## Troubleshooting

For general troubleshooting, see [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md).

For client usage information, see [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md).
