FGCom-mumble - a flightsim radio simulation framework based on mumble
===================================================================== 


Install / Setup for the Server
==============================

Setup requirements
------------------
- plain mumble murmur server instance; >= v1.4.0.

Thats all to run a basic FGCom-mumble server. The *fgcom-mumble* plugin on each client handles everything else.

More functionality like ATIS recordings come with serverside bots. To run those bots, you need to install additional components:

- a lua >=5.1 interpreter (`apt-get install lua5.1 lua-bitop`)
  - lua mumble support (*mumble.so*) in lua include path (/usr/lib/x86_64-linux-gnu/lua/5.1/; compiled from [https://github.com/bkacjios/lua-mumble])


Running a server
----------------------
- Have mumble server up and running
- Create a new channel named `fgcom-mumble` for the airspace. The plugin only does it's things when on this channel.
- Clients will connect and enable their local fgcom plugin. This handles all human communication on frequencies
- Start the `fgcom-bot-manager` which handles all needed bots: `lua fgcom-botmanager.bot.lua`
- Manually start additional `fgcom-radio`-bots to play arbitary samples on frequencies (like radio stations).

Basicly, you just need a standard mumble server >=1.4, so the plugins can exchange information. This will enable radio coms.

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


Client Bot certificate
==================
 The bot needs a certificate and key pair to connect to the mumble server. Generate these like this:
```
openssl genrsa -out bot.key 2048 2> /dev/null
openssl req -new -sha256 -key bot.key -out bot.csr -subj "/"
openssl x509 -req -in bot.csr -signkey bot.key -out bot.pem 2> /dev/null
```

Compiling server parts
===========================
- The lua bots shouldn't needed to be compiled, just run them trough the lua interpreter.
- Compiling the mumble server is usually not neccessary, just use your distibutions version; this holds true also for the client.

- Information for compiling the lua *mumble.so* is given at [bkacjios github page](https://github.com/bkacjios/lua-mumble). You need it deployed in your systems lua libs folder for running the lua bots.  
  - Build dependencys on debian: `apt-get install libluajit-5.1-dev protobuf-c-compiler libprotobuf-c-dev libssl-dev libopus-dev libev-dev`
  - lua lib build process: `$ make all`
  - deploy the lib: `$ cp mumble.so /usr/lib/x86_64-linux-gnu/lua/5.1/`