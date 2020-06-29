Basicly, you just need a standad mumble server >1.14, so the plugins can exchange information. This will enable radio coms.

However, there are advanced features that need serverside support. Mumble-Bots will provide that functionality.


ATIS Manager Bot
================
Start the bot with `lua atis-manager.bot.lua -h` to get usage info.

The ATIS manager bot has two functions:

  1. He monitors the `fgcom-mumble` channel for ATIS recoding requests. If he detects one, the ATIS message will be recorded and stored for further usage.
  2. Manage ATIS-playback bots. If ATIS messages have been recorded, the bot will spawn appropriate `radio-playback` bots serving the ATIS message.


Radio recording request
----------------------
An ATIS recording request is an ordinary transmission, but on a special tuned frequency in the format `RECORD_<target-frequency>`. As soon as a client transmitts, the bot captures the output and stores it.  
When the transmission is complete, the bot notes the target frequency, tx-power, geolocation and callsign of the sender.
The bot will now spawn a `radio-playback` bot that broadcasts the stored audio from the location with the callsign. It will also be terminated from the manager bot after a timeout.

Note that the recording is not ATIS-specific. Using the technique described here also allows to make radio stations etc.


Radio Playback Bot
==================
Start the bot with `lua radio-playback -h` to get usage info.

The bot basically connects to the server, sets up fgcom-mumble plugin location information and broadcasts it to clients. It then starts to transmit the contents of an adio file in a loop until either the file is deleted or the bot is killed.

**TODO:** What file format is expected?
**TODO:** callup example


Client certificate
==================
 The bot needs a certificate and key pair to connect to the mumble server. Generate these like this:
```
openssl genrsa -out bot.key 2048 2> /dev/null
openssl req -new -sha256 -key bot.key -out bot.csr -subj "/"
openssl x509 -req -in bot.csr -signkey bot.key -out bot.pem 2> /dev/null
```