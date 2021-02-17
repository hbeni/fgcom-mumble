/*******************************************************************//**
 * @file        fgcom-mumble.h
 * @brief       Declares FgcomPlugin Class
 * @date        02/17/2021 
 * @authors     mill-j &
 * @copyright   (C) 2021 under GNU GPL v3
 **********************************************************************/
 
#include "mumble/plugin/MumblePlugin.h"
 
#include <iostream>
#include <string>

class FgcomPlugin : public MumblePlugin {
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
