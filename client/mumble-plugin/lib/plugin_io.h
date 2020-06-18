// Common  shared functions of plugin i/o

#ifndef FGCOM_PLUGIN_IO_H
#define FGCOM_PLUGIN_IO_H


#define FGCOM_PORT 16661    // port to listen to (16661 is the known FGCom udp port)
#define MAXLINE    1024     // max byte size of a udp packet


// Mubmle API global vars.
// They get initialized from the plugin interface (see fgcom-mumble.cpp)
extern MumbleAPI mumAPI;
extern mumble_connection_t activeConnection;
extern plugin_id_t ownID;
extern bool connectionSynchronized;


/*
 * Spawn the udp server thread.
 * He should constantly monitor the port for incoming data.
 * 
 * @param ??? TODO: Pointer to the shared data structure. Currently access is via globalvar
 * @return nothing so far. Maybe thread handle?
 */
void fgcom_spawnUDPServer();


/*
 * Trigger shutdown of the udp server
 */
void fgcom_shutdownUDPServer();



/*
 * Notify other clients on changes to local data.
 * This will construct a binary datastream message and push
 * it to the mumble plugin send function.
 * 
 * @param what:     0=all local info; 1=location data; 2=comms
 * @param selector: ignored, when 'what'=2: id of radio (0=COM1,1=COM2,...)
 */
void notifyRemotes(int what, int selector=-1);


// for debugging internal stuff
void fgcom_udp_parseMsg(char buffer[1024]);
#endif
