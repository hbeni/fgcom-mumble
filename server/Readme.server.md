FGCom-mumble - a flightsim radio simulation framework based on mumble
===================================================================== 

This is the server side documentation for the FGCom-mumble implementation.

There is also a german translation available: [-> deutsche Version](Reamde.server-de_DE.md).

Install / Setup for the Server
==============================

Setup requirements
------------------
- plain mumble murmur server instance; >= v1.4.0.

Thats enough to run a basic FGCom-mumble server. The *fgcom-mumble* plugin on each client handles everything else.

More functionality like ATIS recordings come with serverside bots. To run those bots, you need to install additional components:

- a luajit 5.1 interpreter (`apt-get install luajit lua5.1 lua-bitop`)
  - lua mumble support (*mumble.so*) in lua include path (/usr/lib/x86_64-linux-gnu/lua/5.1/; compiled from [https://github.com/bkacjios/lua-mumble])


Running a server
----------------------
- Have mumble server up and running
- Create a new channel named `fgcom-mumble` for the airspace. The plugin only does it's things when on this channel.
- Clients will connect and enable their local fgcom plugin. This handles all human communication on frequencies
- Make a certificate for the bots (details below)
- Start the `fgcom-bot-manager` which handles all needed bots: `./fgcom-botmanager.sh`

Basicly, you just need a standard mumble server >=1.4, so the plugins can exchange information. This will enable radio coms.

However, there are advanced features that need serverside support. Mumble-Bots will provide that functionality.


The Bot manager
==================
`./fgcom-botmanager.sh --help` will give usage instructions.

The bot manager will start the basic set of bots.  
He also will setup the needed interprocess communication for the recorder bot to notify about new recordings. He then spawns a recorder bot and listens for new recordings. When receiving a new recording, a playback bot is invoked.

The status bot can advertise the status page url in it's mumble comment. to activate this, use `./fgcom-botmanager.sh --sweb=<url>`.


Radio Recording Bot
===================
If you want to start the bot manually, you can inspect its available options with `luajit fgcom-radio-recorder.bot.lua -h`.

The `radio-recorder` monitors the `fgcom-mumble` channel for users recording requests. If such a request is detected, the samples get recorded and put to an sample file on disk.  
Those disk samples can be picked up from the `radio-playback` bot, which is usually invoked automatically from the botmanager. For this, the recorder bot has an notification interface to the botmanger.

Radio (ATIS) recording request
------------------------------
An ATIS recording request is an ordinary transmission, but on a special tuned frequency in the format `RECORD_<target-frequency>`. As soon as a client transmitts, the bot captures the output and stores it.  
When the transmission is complete, the bot notes the target frequency, tx-power, geolocation and callsign of the sender.
Then, a `radio-playback` bot that broadcasts the stored audio from the location with the callsign will be spawned. It will also be terminated from the manager bot after a timeout.

Note that the recording is not ATIS-specific. Using the technique described here also allows to make radio stations etc.


910.00 Test frequency recording request
---------------------------------------
These recordings are normal ones in regard of this specification. However they have the following notable parmeters:

- Recording occurs on the freuqency `910.00`, ie. without `RECORD_` prefix.
- Playback must occur at this frequency too.
- Playback must occur at the senders position.
- The playback variant is oneshot only and only valid for a brief period of time (TTL). The bot must terminate finally after the playback.

This is implemented by the recording bot monitoring the frequency and writing the `fgcs` fileheader accordingly.


FGCom Sample file disk format (`.fgcs`)
-----------------------------
This file format holds samples together with its meta information. The file should have a unique name, with the postfix `.fgcs`.  
Its content begins with a linewise human readable `string` formatted header, each finished with a newline character:

| Line | Content                                |
|------|----------------------------------------|
|   1  | Version and Type field: "1.0 FGCS"     |
|   2  | Callsign                               |
|   3  | LAT          (decimal)                 |
|   4  | LON          (decimal)                 |
|   5  | HGT          (altitude in meter AGL)   |
|   6  | Frequency                              |
|   7  | TX-Power     (in Watts)                |
|   8  | PlaybackType (`oneshot` or `loop`)     |
|   9  | TimeToLive   (seconds; `0`=persistent) |
|  10  | RecTimestamp (unix timestamp)          |
|  11  | VoiceCodec   (`int` from lua-mumble)   |
|  12  | SampleSpeed  (seconds between samples) |

This header is directly followed with a variable ammount of voice packets; they each have the format `<(2 bytes)length><(n bytes)voice>`.

The *Version* field is there to support or block parsing of older version headers in future revisions. Its structure is space separated: `<major>.<minor> <type> <optionalDescriptiveStuffWhichIsToBeIgnored>`

The *TimeToLive* is relative to the recordings timestamp. If `timestamp + TTL < now`, the sample is not valid anymore and should be cleared from disk. A TTL of `0` or less signals a "persistent" sample.

The *SampleSpeed* is usually 0.02, but depending on the clients settings.


Radio Playback Bot
==================
If you want to start the bot manually, you can inspect its available options with `luajit fgcom-radio-playback.bot.lua -h`.

The bot basically connects to the server, sets up fgcom-mumble plugin location information and broadcasts it to clients. It then starts to transmit the contents of an audio file in a loop until either the file is not valid anymore, deleted or the bot is manually killed.

The needed information is read fom the `fgcs`-fileheader or provided by commandline (the latter taking precedence if given).

The bot is assumed to clean its own files when he is done with playback of `fgcs` files.

The playback is currently limited to the sample file format output from the `radio-recorder` described above.
**TODO:** also let OGG files play, for that use command line options to specify location etc. OGG files are supposed to be persistent and manually called, so do not delete them after playback!


Client Bot certificates
=======================
The bots each need a certificate and key pair to connect to the mumble server. Generate these like this:
```
for w in rec play status;
  do  openssl genrsa -out ${w}bot.key 2048 2> /dev/null
  openssl req -new -sha256 -key ${w}bot.key -out ${w}bot.csr -subj "/"
  openssl x509 -req -in ${w}bot.csr -signkey ${w}bot.key -out ${w}bot.pem 2> /dev/null
done
```

You need separate certificates for the recorder and playback bots, otherwise the server might kick them.


Compiling server parts
===========================
- The lua bots shouldn't needed to be compiled, just run them trough the luajit interpreter.
- Compiling the mumble server is usually not neccessary, just use your distibutions version; this holds true also for the client.

- Information for compiling the lua *mumble.so* is given at [bkacjios github page](https://github.com/bkacjios/lua-mumble). You need it deployed in your systems lua libs folder for running the lua bots.  
  - Build dependencys on debian: `apt-get install libluajit-5.1-dev protobuf-c-compiler libprotobuf-c-dev libssl-dev libopus-dev libev-dev`
  - lua lib build process: `$ make all`
  - deploy the lib: `$ cp mumble.so /usr/lib/x86_64-linux-gnu/lua/5.1/`
