FGCom-mumble - a flightsim radio simulation framework based on mumble
===================================================================== 


Status website for FGCom-mumble
===============================

The status page aims to provide an overview about currently connected clients, their positions and radio frequencies as well as occuring ATIS broadcasts.

For this, the webpage consists of three components:

- A PHP website, showing the current status out of a shared data interface.
- A special bot that collects current client information and feeds it to a shared data interface.
- The shared data interface.

The reason for this setup is, that the information should be gathered asynchronuosly so the webpage can answer as fast as possible. The possibility of overloading of the mumble infrastructure trough excessive web requests is also avoided.  
To display all information of the radio state, we need some deeper view into the clients data, which cannot be provided from the ICE-bus at this time (an idea might be to collect this information from the clients comments, once the mumble-API allows changing them. This would remove the need for a bot generating that info for us).


Setup requirements
------------------
- a Webserver supporting PHP
- PHP >= 7.0.0 (probably php5 might work too)
- Lua: See Readme.server.md


Deployment
------------------

### Webpage
Just define a new webroot and set it to this directory. Configure your webserver to deliver index.php via the PHP interpreter.

Copy the `config.dist.ini` to `config.ini`. You also may want to adapt the webpage configuration file.

### mumble status bot
The bot will usually be started from the bot manager script, but in case you want to start it manually, `fgcom-status.bot.lua -h` gives usage information.

The bot will initialize the database at startup, if not done yet. For this he will wipe clean an existing database. then he asks all other FGCom clients to provide their data to the bot, who will add it to the database.


Shared data interface
---------------------
The shared data interface is currently a simple file containing json records. The bot and the webpage must be pointed to the same file. The bot is the data povider, the webpage the consumer.

The default path is `/tmp/fgcom-web.db` so the database usually lives in memory and won't survive a reboot. This is on purpose.


### Schema description
There is just a single table containing the information per connected client. In addition to that, the timestamp-collumn "lastUpdate" will contain the last time the data was updated. The webpage will skip old entries.