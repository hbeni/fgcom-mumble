// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "mumble/plugin/MumbleAPI.h"
#include "mumble/plugin/MumbleResourceWrapper.h"

#include <cstring>

#define HANDLE_ERROR(errorCode, function)                                                                   \
	if (errorCode != STATUS_OK) {                                                                           \
		throw MumbleAPIException(errorCode, std::string(#function " errored: ") + errorMessage(errorCode)); \
	}

#define WRAP_RESOURCE(type, resource) MumbleResourceWrapper< type >(resource, m_pluginID, m_apiStruct.freeMemory)

MumbleAPIException::MumbleAPIException(mumble_error_t errorCode, const std::string &message)
	: m_errorCode(errorCode), m_message(message) {
}

const char *MumbleAPIException::what() const noexcept {
	return m_message.c_str();
}

mumble_error_t MumbleAPIException::errorCode() const noexcept {
	return m_errorCode;
}


MumbleAPI::MumbleAPI(MumbleAPI_v_1_0_x apiStruct, mumble_plugin_id_t pluginID)
	: m_apiStruct(apiStruct), m_pluginID(pluginID) {
}

MumbleAPI::~MumbleAPI() {
}

void MumbleAPI::setPluginID(mumble_plugin_id_t pluginID) noexcept {
	m_pluginID = pluginID;
}

void MumbleAPI::freeMemory(const void *pointer) const {
	mumble_error_t errorCode = m_apiStruct.freeMemory(m_pluginID, pointer);

	HANDLE_ERROR(errorCode, freeMemory);
}

mumble_connection_t MumbleAPI::getActiveServerConnection() const {
	mumble_connection_t connection;
	mumble_error_t errorCode = m_apiStruct.getActiveServerConnection(m_pluginID, &connection);

	HANDLE_ERROR(errorCode, getActiveServerConnection);

	return connection;
}

bool MumbleAPI::isConnectionSynchronized(mumble_connection_t connection) const {
	bool isSynchronized;
	mumble_error_t errorCode = m_apiStruct.isConnectionSynchronized(m_pluginID, connection, &isSynchronized);

	HANDLE_ERROR(errorCode, isConnectionSynchronized);

	return isSynchronized;
}

mumble_userid_t MumbleAPI::getLocalUserID(mumble_connection_t connection) const {
	mumble_userid_t userID;
	mumble_error_t errorCode = m_apiStruct.getLocalUserID(m_pluginID, connection, &userID);

	HANDLE_ERROR(errorCode, getLocalUserID);

	return userID;
}

MumbleString MumbleAPI::getUserName(mumble_connection_t connection, mumble_userid_t userID) const {
	const char *namePtr;
	mumble_error_t errorCode = m_apiStruct.getUserName(m_pluginID, connection, userID, &namePtr);

	HANDLE_ERROR(errorCode, getUserName);

	std::size_t size = std::strlen(namePtr);

	return MumbleString(WRAP_RESOURCE(const char, namePtr), size);
}

MumbleString MumbleAPI::getChannelName(mumble_connection_t connection, mumble_channelid_t channelID) const {
	const char *namePtr;
	mumble_error_t errorCode = m_apiStruct.getChannelName(m_pluginID, connection, channelID, &namePtr);

	HANDLE_ERROR(errorCode, getUserName);

	std::size_t size = std::strlen(namePtr);

	return MumbleString(WRAP_RESOURCE(const char, namePtr), size);
}

MumbleArray< mumble_userid_t > MumbleAPI::getAllUsers(mumble_connection_t connection) const {
	std::size_t userCount;
	mumble_userid_t *users;

	mumble_error_t errorCode = m_apiStruct.getAllUsers(m_pluginID, connection, &users, &userCount);

	HANDLE_ERROR(errorCode, getAllUsers);

	return MumbleArray< mumble_userid_t >(WRAP_RESOURCE(mumble_userid_t, users), userCount);
}

MumbleArray< mumble_channelid_t > MumbleAPI::getAllChannels(mumble_connection_t connection) const {
	std::size_t channelCount;
	mumble_channelid_t *channels;

	mumble_error_t errorCode = m_apiStruct.getAllChannels(m_pluginID, connection, &channels, &channelCount);

	HANDLE_ERROR(errorCode, getAllChannels);

	return MumbleArray< mumble_channelid_t >(WRAP_RESOURCE(mumble_channelid_t, channels), channelCount);
}

mumble_channelid_t MumbleAPI::getChannelOfUser(mumble_connection_t connection, mumble_userid_t userID) const {
	mumble_channelid_t channelID;

	mumble_error_t errorCode = m_apiStruct.getChannelOfUser(m_pluginID, connection, userID, &channelID);

	HANDLE_ERROR(errorCode, getChannelOfUser);

	return channelID;
}

MumbleArray< mumble_userid_t > MumbleAPI::getUsersInChannel(mumble_connection_t connection,
															mumble_channelid_t channelID) const {
	std::size_t size;
	mumble_userid_t *users;

	mumble_error_t errorCode = m_apiStruct.getUsersInChannel(m_pluginID, connection, channelID, &users, &size);

	HANDLE_ERROR(errorCode, getUsersInChannel);

	return MumbleArray< mumble_userid_t >(WRAP_RESOURCE(mumble_userid_t, users), size);
}


mumble_transmission_mode_t MumbleAPI::getLocalUserTransmissionMode() const {
	mumble_transmission_mode_t transmissionMode;

	mumble_error_t errorCode = m_apiStruct.getLocalUserTransmissionMode(m_pluginID, &transmissionMode);

	HANDLE_ERROR(errorCode, getLocalUserTransmissionMode);

	return transmissionMode;
}

bool MumbleAPI::isUserLocallyMuted(mumble_connection_t connection, mumble_userid_t userID) const {
	bool muted;

	mumble_error_t errorCode = m_apiStruct.isUserLocallyMuted(m_pluginID, connection, userID, &muted);

	HANDLE_ERROR(errorCode, isUserLocallyMuted);

	return muted;
}

bool MumbleAPI::isLocalUserMuted() const {
	bool muted;

	mumble_error_t errorCode = m_apiStruct.isLocalUserMuted(m_pluginID, &muted);

	HANDLE_ERROR(errorCode, isLocalUserMuted);

	return muted;
}

bool MumbleAPI::isLocalUserDeafened() const {
	bool deafened;

	mumble_error_t errorCode = m_apiStruct.isLocalUserDeafened(m_pluginID, &deafened);

	HANDLE_ERROR(errorCode, isLocalUserDeafened);

	return deafened;
}

MumbleString MumbleAPI::getUserHash(mumble_connection_t connection, mumble_userid_t userID) const {
	const char *hash;

	mumble_error_t errorCode = m_apiStruct.getUserHash(m_pluginID, connection, userID, &hash);

	HANDLE_ERROR(errorCode, getUserHash);

	std::size_t size = std::strlen(hash);

	return MumbleString(WRAP_RESOURCE(const char, hash), size);
}

MumbleString MumbleAPI::getServerHash(mumble_connection_t connection) const {
	const char *hash;

	mumble_error_t errorCode = m_apiStruct.getServerHash(m_pluginID, connection, &hash);

	HANDLE_ERROR(errorCode, getServerHash);

	std::size_t size = std::strlen(hash);

	return MumbleString(WRAP_RESOURCE(const char, hash), size);
}

MumbleString MumbleAPI::getUserComment(mumble_connection_t connection, mumble_userid_t userID) const {
	const char *comment;

	mumble_error_t errorCode = m_apiStruct.getUserComment(m_pluginID, connection, userID, &comment);

	HANDLE_ERROR(errorCode, getUserComment);

	std::size_t size = std::strlen(comment);

	return MumbleString(WRAP_RESOURCE(const char, comment), size);
}

MumbleString MumbleAPI::getChannelDescription(mumble_connection_t connection, mumble_channelid_t channelID) const {
	const char *description;

	mumble_error_t errorCode = m_apiStruct.getChannelDescription(m_pluginID, connection, channelID, &description);

	HANDLE_ERROR(errorCode, getChannelDescription);

	std::size_t size = std::strlen(description);

	return MumbleString(WRAP_RESOURCE(const char, description), size);
}

mumble_error_t MumbleAPI::requestLocalUserTransmissionMode(mumble_transmission_mode_t transmissionMode) const noexcept {
	return m_apiStruct.requestLocalUserTransmissionMode(m_pluginID, transmissionMode);
}

mumble_error_t MumbleAPI::requestUserMove(mumble_connection_t connection, mumble_userid_t userID,
										  mumble_channelid_t channelID, const char *password) const noexcept {
	return m_apiStruct.requestUserMove(m_pluginID, connection, userID, channelID, password);
}

mumble_error_t MumbleAPI::requestMicrophoneActivationOvewrite(bool activate) const noexcept {
	return m_apiStruct.requestMicrophoneActivationOvewrite(m_pluginID, activate);
}

mumble_error_t MumbleAPI::requestLocalMute(mumble_connection_t connection, mumble_userid_t userID,
										   bool muted) const noexcept {
	return m_apiStruct.requestLocalMute(m_pluginID, connection, userID, muted);
}

mumble_error_t MumbleAPI::requestLocalUserMute(bool muted) const noexcept {
	return m_apiStruct.requestLocalUserMute(m_pluginID, muted);
}

mumble_error_t MumbleAPI::requestLocalUserDeaf(bool deafened) const noexcept {
	return m_apiStruct.requestLocalUserDeaf(m_pluginID, deafened);
}

mumble_error_t MumbleAPI::requestSetLocalUserComment(mumble_connection_t connection,
													 const char *comment) const noexcept {
	return m_apiStruct.requestSetLocalUserComment(m_pluginID, connection, comment);
}

mumble_userid_t MumbleAPI::findUserByName(mumble_connection_t connection, const char *userName) const {
	mumble_userid_t userID;

	mumble_error_t errorCode = m_apiStruct.findUserByName(m_pluginID, connection, userName, &userID);

	HANDLE_ERROR(errorCode, findUserByName)

	return userID;
}

std::optional< mumble_userid_t > MumbleAPI::findUserByName_noexcept(mumble_connection_t connection,
																	const char *userName) const noexcept {
	try {
		return findUserByName(connection, userName);
	} catch (const MumbleAPIException &) {
		return std::nullopt;
	}
}

mumble_channelid_t MumbleAPI::findChannelByName(mumble_connection_t connection, const char *channelName) const {
	mumble_channelid_t channelID;

	mumble_error_t errorCode = m_apiStruct.findChannelByName(m_pluginID, connection, channelName, &channelID);

	HANDLE_ERROR(errorCode, findChannelByName)

	return channelID;
}

std::optional< mumble_channelid_t > MumbleAPI::findChannelByName_noexcept(mumble_connection_t connection,
																		  const char *channelName) const noexcept {
	try {
		return findChannelByName(connection, channelName);
	} catch (const MumbleAPIException &) {
		return std::nullopt;
	}
}

bool MumbleAPI::getMumbleSetting_bool(mumble_settings_key_t key) const {
	bool value;

	mumble_error_t errorCode = m_apiStruct.getMumbleSetting_bool(m_pluginID, key, &value);

	HANDLE_ERROR(errorCode, getMumbleSetting_bool);

	return value;
}

int MumbleAPI::getMumbleSetting_int(mumble_settings_key_t key) const {
	int value;

	mumble_error_t errorCode = m_apiStruct.getMumbleSetting_int(m_pluginID, key, &value);

	HANDLE_ERROR(errorCode, getMumbleSetting_int);

	return value;
}

double MumbleAPI::getMumbleSetting_double(mumble_settings_key_t key) const {
	double value;

	mumble_error_t errorCode = m_apiStruct.getMumbleSetting_double(m_pluginID, key, &value);

	HANDLE_ERROR(errorCode, getMumbleSetting_double);

	return value;
}

MumbleString MumbleAPI::getMumbleSetting_string(mumble_settings_key_t key) const {
	const char *value;

	mumble_error_t errorCode = m_apiStruct.getMumbleSetting_string(m_pluginID, key, &value);

	HANDLE_ERROR(errorCode, getMumbleSetting_string);

	std::size_t size = std::strlen(value);

	return MumbleString(WRAP_RESOURCE(const char, value), size);
}

void MumbleAPI::setMumbleSetting_bool(mumble_settings_key_t key, bool value) const {
	mumble_error_t errorCode = m_apiStruct.setMumbleSetting_bool(m_pluginID, key, value);

	HANDLE_ERROR(errorCode, setMumbleSetting_bool);
}

void MumbleAPI::setMumbleSetting_int(mumble_settings_key_t key, int value) const {
	mumble_error_t errorCode = m_apiStruct.setMumbleSetting_int(m_pluginID, key, value);

	HANDLE_ERROR(errorCode, setMumbleSetting_bool);
}

void MumbleAPI::setMumbleSetting_double(mumble_settings_key_t key, double value) const {
	mumble_error_t errorCode = m_apiStruct.setMumbleSetting_double(m_pluginID, key, value);

	HANDLE_ERROR(errorCode, setMumbleSetting_bool);
}

void MumbleAPI::setMumbleSetting_string(mumble_settings_key_t key, const char *value) const {
	mumble_error_t errorCode = m_apiStruct.setMumbleSetting_string(m_pluginID, key, value);

	HANDLE_ERROR(errorCode, setMumbleSetting_bool);
}

void MumbleAPI::sendData(mumble_connection_t connection, const std::vector< mumble_userid_t > &receivers,
						 const std::vector< uint8_t > &data, const char *dataID) const {
	static_assert(!std::is_same< mumble_userid_t, bool >::value,
				  "mumble_userid_t must not be a bool for this implementation to work");
	static_assert(!std::is_same< uint8_t, bool >::value, "uint8_t must not be a bool for this implementation to work");

	mumble_error_t errorCode = m_apiStruct.sendData(m_pluginID, connection, receivers.data(), receivers.size(),
													data.data(), data.size(), dataID);

	HANDLE_ERROR(errorCode, sendData);
}

void MumbleAPI::log(const char *message) const {
	mumble_error_t errorCode = log_noexcept(message);

	HANDLE_ERROR(errorCode, log);
}

mumble_error_t MumbleAPI::log_noexcept(const char *message) const noexcept {
	return m_apiStruct.log(m_pluginID, message);
}

void MumbleAPI::playSample(const char *samplePath) const {
	mumble_error_t errorCode = m_apiStruct.playSample(m_pluginID, samplePath);

	HANDLE_ERROR(errorCode, playSample);
}
