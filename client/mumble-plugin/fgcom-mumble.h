/*******************************************************************//**
 * @file        fgcom-mumble.h
 * @brief       Declares FgcomPlugin Class
 * @authors     Benedikt Hallinger & mill-j
 * @copyright   (C) 2021 under GNU GPL v3
 **********************************************************************/
 
#include "mumble/plugin/MumblePlugin.h"
 
#include <iostream>
#include <string>
#include <thread>

#ifdef MINGW_WIN64
    #include <winsock2.h>
    typedef int socklen_t;
#else
    #include <sys/socket.h> 
    #include <arpa/inet.h> 
    #include <netinet/in.h>
#endif

#include "src/fgcom_identity.cpp"
#include "src/fgcom_location.cpp"
#include "src/fgcom_radio.cpp"
#include "src/fgcom_keyvalue.cpp"

#define BUFLEN 1024	//Max length of buffer
#define PORT 16661	//The port on which to listen for incoming data

class FgcomPlugin : public MumblePlugin {
private:
	fgcom_identity localUser; 					///>Holds local user info
	std::vector<fgcom_identity> remoteUsers;	///>Holds remote user info
	std::string specialChannel = "fgcom-mumble";///>@todo Make changeable
	
	//Local UDP server functions
	std::thread fgcom_readThread;				///>Udp server thread
	void fgcom_spawnUDPServer();
	bool udpServerRunning;						///>Used to shutdown thread
	
	//PTT and transmission functions ans vars
	mumble_transmission_mode_t fgcom_prevTransmissionMode = TM_VOICE_ACTIVATION; // we use voice act as default in case something goes wrong
	
public:
	FgcomPlugin() : MumblePlugin("Fgcom2", "mill-j",
					   "A Mumble based radio simulation for flight simulators") {}
	
	virtual void onServerSynchronized(mumble_connection_t connection) noexcept override;
	virtual void onServerDisconnected(mumble_connection_t connection) noexcept override;
	virtual void onServerConnected(mumble_connection_t connection) noexcept override;
	
	virtual void onChannelExited(mumble_connection_t connection, mumble_userid_t userID, 
		mumble_channelid_t channelID ) noexcept override;
	
	virtual void onChannelEntered (mumble_connection_t connection, 
		mumble_userid_t userID, mumble_channelid_t  previousChannelID, 
			mumble_channelid_t newChannelID)  noexcept override;

	
	virtual void releaseResource(const void *ptr) noexcept override {
		// We don't allocate any resources so we can have a no-op implementation
		// We'll terminate though in case it is called as that is definitely a bug
		std::cout<<"[Fgcom2] Releasing Resources"<<std::endl;
		std::terminate();
	}
	
	void pluginLog(std::string log);
	void pluginDbg(std::string log);
};
