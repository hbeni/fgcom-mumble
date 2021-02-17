// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MUMBLEPLUGIN_MUMBLEPLUGIN_H_
#define MUMBLEPLUGIN_MUMBLEPLUGIN_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mumble/plugin/MumbleAPI.h"

#include "mumble/plugin/internal/PluginComponents_v_1_0_x.h"

using mumble_plugin_id_t = uint32_t;

struct ProgramInformation {
	const char *name;
	uint64_t pid;
};

class MumblePlugin {
private:
	mumble_plugin_id_t m_assignedID = -1;
	std::string m_name;
	std::string m_author;
	std::string m_description;

protected:
	MumbleAPI m_api;

public:
	MumblePlugin(const std::string &name, const std::string &author, const std::string &description = std::string());
	virtual ~MumblePlugin();

	virtual mumble_error_t internal_init(mumble_plugin_id_t id) noexcept final;
	virtual mumble_error_t init() noexcept;
	virtual MumbleStringWrapper getName() const noexcept final;
	virtual mumble_version_t getAPIVersion() const noexcept final;
	virtual void registerAPIFunctions(void *api) noexcept final;
	virtual void releaseResource(const void *pointer) noexcept = 0;
	virtual void internal_shutdown() noexcept final;
	virtual void shutdown() noexcept;
	virtual MumbleStringWrapper getAuthor() const noexcept final;
	virtual MumbleStringWrapper getDescription() const noexcept final;
	virtual void setMumbleInfo(mumble_version_t mumbleVersion, mumble_version_t mumbleAPIVersion,
							   mumble_version_t minimalExpectedAPIVersion) const noexcept;
	virtual mumble_version_t getVersion() const noexcept;
	virtual uint32_t getFeatures() const noexcept;
	virtual uint32_t deactivateFeatures(uint32_t features) noexcept;

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO
	uint8_t internal_initPositionalData(const char **programNames, const uint64_t *programPIDs,
										std::size_t programCount) noexcept;
	virtual uint8_t initPositionalData(std::vector< ProgramInformation > &programs) noexcept;
	virtual bool fetchPositionalData(float *avatarPos, float *avatarDir, float *avatarAxis, float *cameraPos,
									 float *cameraDir, float *cameraAxis, const char **context,
									 const char **identity) noexcept;
	virtual void shutdownPositionalData() noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS
	virtual void onServerConnected(mumble_connection_t connection) noexcept;
	virtual void onServerDisconnected(mumble_connection_t connection) noexcept;
	virtual void onServerSynchronized(mumble_connection_t connection) noexcept;
	virtual void onChannelEntered(mumble_connection_t connection, mumble_userid_t userID,
								  mumble_channelid_t previousChannelID, mumble_channelid_t newChannelID) noexcept;
	virtual void onChannelExited(mumble_connection_t connection, mumble_userid_t userID,
								 mumble_channelid_t channelID) noexcept;
	virtual void onUserTalkingStateChanged(mumble_connection_t connection, mumble_userid_t userID,
										   mumble_talking_state_t talkingState) noexcept;
	virtual void onUserAdded(mumble_connection_t connection, mumble_userid_t userID) noexcept;
	virtual void onUserRemoved(mumble_connection_t connection, mumble_userid_t userID) noexcept;
	virtual void onChannelAdded(mumble_connection_t connection, mumble_channelid_t channelID) noexcept;
	virtual void onChannelRemoved(mumble_connection_t connection, mumble_channelid_t channelID) noexcept;
	virtual void onChannelRenamed(mumble_connection_t connection, mumble_channelid_t channelID) noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS
	virtual bool onAudioInput(short *inputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRate,
							  bool isSpeech) noexcept;
	virtual bool onAudioSourceFetched(float *outputPCM, uint32_t sampleCount, uint16_t channelCount,
									  uint32_t sampleRate, bool isSpeech, mumble_userid_t userID) noexcept;
	virtual bool onAudioAboutOutputAboutToPlay(float *outputPCM, uint32_t sampleCount, uint16_t channelCount,
											   uint32_t sampleRate) noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS
	virtual bool onReceiveData(mumble_connection_t connection, mumble_userid_t senderID, const uint8_t *data,
							   std::size_t dataLength, const char *dataID) noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS
	virtual void onKeyEvent(uint32_t keyCode, bool wasPress) noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES
	virtual bool hasUpdate() noexcept;
	virtual MumbleStringWrapper getUpdateDownloadURL() const noexcept;
#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES

	/**
	 * @returns A reference to a static instance of the plugin object that should be
	 * used for this wrapper. This function has to be implemented by the user of
	 * the wrapper framework in order to return their actual plugin object.
	 */
	static MumblePlugin &getPlugin() noexcept;
};

#endif // MUMBLEPLUGIN_MUMBLEPLUGIN_H_
