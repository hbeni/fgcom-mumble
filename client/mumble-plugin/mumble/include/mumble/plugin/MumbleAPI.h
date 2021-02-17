// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MUMBLEPLUGIN_MUMBLEAPI_H_
#define MUMBLEPLUGIN_MUMBLEAPI_H_

#include "mumble/plugin/MumbleArray.h"
#include "mumble/plugin/MumbleString.h"
#include "mumble/plugin/internal/MumbleAPI_v_1_0_x.h"

#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class MumbleAPIException : public std::exception {
private:
	mumble_error_t m_errorCode;
	std::string m_message;

public:
	MumbleAPIException(mumble_error_t errorCode, const std::string &message);

	const char *what() const noexcept;
	mumble_error_t errorCode() const noexcept;
};

class MumbleAPI {
	friend class MumblePlugin;

private:
	MumbleAPI_v_1_0_x m_apiStruct;
	mumble_plugin_id_t m_pluginID;

	void setPluginID(mumble_plugin_id_t pluginID) noexcept;

	MumbleAPI() = default;

public:
	explicit MumbleAPI(MumbleAPI_v_1_0_x apiStruct, mumble_plugin_id_t pluginID = 0);
	~MumbleAPI();

	void freeMemory(const void *pointer) const;
	mumble_connection_t getActiveServerConnection() const;
	bool isConnectionSynchronized(mumble_connection_t connection) const;
	mumble_userid_t getLocalUserID(mumble_connection_t connection) const;
	MumbleString getUserName(mumble_connection_t connection, mumble_userid_t userID) const;
	MumbleString getChannelName(mumble_connection_t connection, mumble_channelid_t channelID) const;
	MumbleArray< mumble_userid_t > getAllUsers(mumble_connection_t connection) const;
	MumbleArray< mumble_channelid_t > getAllChannels(mumble_connection_t connection) const;
	mumble_channelid_t getChannelOfUser(mumble_connection_t connection, mumble_userid_t userID) const;
	MumbleArray< mumble_userid_t > getUsersInChannel(mumble_connection_t connection,
													 mumble_channelid_t channelID) const;
	mumble_transmission_mode_t getLocalUserTransmissionMode() const;
	bool isUserLocallyMuted(mumble_connection_t connection, mumble_userid_t userID) const;
	bool isLocalUserMuted() const;
	bool isLocalUserDeafened() const;
	MumbleString getUserHash(mumble_connection_t connection, mumble_userid_t userID) const;
	MumbleString getServerHash(mumble_connection_t connection) const;
	MumbleString getUserComment(mumble_connection_t connection, mumble_userid_t userID) const;
	MumbleString getChannelDescription(mumble_connection_t connection, mumble_channelid_t channelID) const;
	mumble_error_t requestLocalUserTransmissionMode(mumble_transmission_mode_t transmissionMode) const noexcept;
	mumble_error_t requestUserMove(mumble_connection_t connection, mumble_userid_t userID, mumble_channelid_t channelID,
								   const char *password = nullptr) const noexcept;
	mumble_error_t requestMicrophoneActivationOvewrite(bool activate) const noexcept;
	mumble_error_t requestLocalMute(mumble_connection_t connection, mumble_userid_t userID, bool muted) const noexcept;
	mumble_error_t requestLocalUserMute(bool muted) const noexcept;
	mumble_error_t requestLocalUserDeaf(bool deafened) const noexcept;
	mumble_error_t requestSetLocalUserComment(mumble_connection_t connection, const char *comment) const noexcept;
	mumble_userid_t findUserByName(mumble_connection_t connection, const char *userName) const;
	std::optional< mumble_userid_t > findUserByName_noexcept(mumble_connection_t connection,
															 const char *userName) const noexcept;
	mumble_channelid_t findChannelByName(mumble_connection_t connection, const char *channelName) const;
	std::optional< mumble_channelid_t > findChannelByName_noexcept(mumble_connection_t connection,
																   const char *channelName) const noexcept;
	bool getMumbleSetting_bool(mumble_settings_key_t key) const;
	int getMumbleSetting_int(mumble_settings_key_t key) const;
	double getMumbleSetting_double(mumble_settings_key_t key) const;
	MumbleString getMumbleSetting_string(mumble_settings_key_t key) const;
	void setMumbleSetting_bool(mumble_settings_key_t key, bool value) const;
	void setMumbleSetting_int(mumble_settings_key_t key, int value) const;
	void setMumbleSetting_double(mumble_settings_key_t key, double value) const;
	void setMumbleSetting_string(mumble_settings_key_t key, const char *value) const;
	void sendData(mumble_connection_t connection, const std::vector< mumble_userid_t > &receivers,
				  const std::vector< uint8_t > &data, const char *dataID) const;
	void log(const char *message) const;
	mumble_error_t log_noexcept(const char *message) const noexcept;
	void playSample(const char *samplePath) const;
};

#endif // MUMBLEPLUGIN_MUMBLEAPI_H_
