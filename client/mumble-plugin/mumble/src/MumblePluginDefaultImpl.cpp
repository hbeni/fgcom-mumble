// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "mumble/plugin/MumblePlugin.h"

#include "mumble/plugin/internal/MumblePlugin_v_1_0_x.h"

#include <iostream>

#define UNUSED(var) (void) var

MumblePlugin::MumblePlugin(const std::string &name, const std::string &author, const std::string &description)
	: m_name(name), m_author(author), m_description(description) {
}

MumblePlugin::~MumblePlugin() {
}

mumble_error_t MumblePlugin::internal_init(mumble_plugin_id_t id) noexcept {
	m_assignedID = id;

	m_api.setPluginID(id);

	// Forward call
	return init();
}

void MumblePlugin::internal_shutdown() noexcept {
	// Forward call
	shutdown();
}

mumble_version_t MumblePlugin::getAPIVersion() const noexcept {
	return MUMBLE_PLUGIN_API_VERSION;
}

void MumblePlugin::registerAPIFunctions(void *api) noexcept {
	// We construct an "invalid" MumbleAPI object since the API doesn't know of a pluginID yet.
	// That is okay though since there is no callback inside the plugin class that will be called
	// before we had a chance to pass the pluginID to the API class.
	m_api = MumbleAPI(MUMBLE_API_CAST(api));
}

MumbleStringWrapper MumblePlugin::getName() const noexcept {
	// The plugin class will exist until the end of the program and therefore it is safe to basically treat its
	// members as having "static storage"
	MumbleStringWrapper wrapper;
	wrapper.data           = m_name.c_str();
	wrapper.size           = m_name.size();
	wrapper.needsReleasing = false;

	return wrapper;
}

MumbleStringWrapper MumblePlugin::getAuthor() const noexcept {
	// The plugin class will exist until the end of the program and therefore it is safe to basically treat its
	// members as having "static storage"
	MumbleStringWrapper wrapper;
	wrapper.data           = m_author.c_str();
	wrapper.size           = m_author.size();
	wrapper.needsReleasing = false;

	return wrapper;
}

MumbleStringWrapper MumblePlugin::getDescription() const noexcept {
	// The plugin class will exist until the end of the program and therefore it is safe to basically treat its
	// members as having "static storage"
	MumbleStringWrapper wrapper;
	wrapper.data           = m_description.c_str();
	wrapper.size           = m_description.size();
	wrapper.needsReleasing = false;

	return wrapper;
}

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO
uint8_t MumblePlugin::internal_initPositionalData(const char **programNames, const uint64_t *programPIDs,
												  std::size_t programCount) noexcept {
	std::vector< ProgramInformation > programs;
	programs.reserve(programCount);

	for (std::size_t i = 0; i < programCount; i++) {
		programs.push_back({ programNames[i], programPIDs[i] });
	}

	return initPositionalData(programs);
}
#endif

mumble_error_t MumblePlugin::init() noexcept {
	return STATUS_OK;
}

void MumblePlugin::shutdown() noexcept {
}

void MumblePlugin::setMumbleInfo(mumble_version_t mumbleVersion, mumble_version_t mumbleAPIVersion,
								 mumble_version_t minimalExpectedAPIVersion) const noexcept {
	UNUSED(mumbleVersion);
	UNUSED(mumbleAPIVersion);
	UNUSED(minimalExpectedAPIVersion);
}

mumble_version_t MumblePlugin::getVersion() const noexcept {
	// Report 1.0.0 by default
	return { 1, 0, 0 };
}

uint32_t MumblePlugin::getFeatures() const noexcept {
	return FEATURE_NONE;
}

uint32_t MumblePlugin::deactivateFeatures(uint32_t features) noexcept {
	return features;
}

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO
uint8_t MumblePlugin::initPositionalData(std::vector< ProgramInformation > &programs) noexcept {
	// Report permanent error by default in order to turn positional data off
	return PDEC_ERROR_PERM;
}

bool MumblePlugin::fetchPositionalData(float *avatarPos, float *avatarDir, float *avatarAxis, float *cameraPos,
									   float *cameraDir, float *cameraAxis, const char **context,
									   const char **identity) noexcept {
	UNUSED(avatarPos);
	UNUSED(avatarDir);
	UNUSED(avatarAxis);
	UNUSED(cameraPos);
	UNUSED(cameraDir);
	UNUSED(cameraAxis);
	UNUSED(context);
	UNUSED(identity);

	return false;
}

void MumblePlugin::shutdownPositionalData() noexcept {
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS
void MumblePlugin::onServerConnected(mumble_connection_t connection) noexcept {
	UNUSED(connection);
}

void MumblePlugin::onServerDisconnected(mumble_connection_t connection) noexcept {
	UNUSED(connection);
}

void MumblePlugin::onServerSynchronized(mumble_connection_t connection) noexcept {
	UNUSED(connection);
}

void MumblePlugin::onChannelEntered(mumble_connection_t connection, mumble_userid_t userID,
									mumble_channelid_t previousChannelID, mumble_channelid_t newChannelID) noexcept {
	UNUSED(connection);
	UNUSED(userID);
	UNUSED(previousChannelID);
	UNUSED(newChannelID);
}

void MumblePlugin::onChannelExited(mumble_connection_t connection, mumble_userid_t userID,
								   mumble_channelid_t channelID) noexcept {
	UNUSED(connection);
	UNUSED(userID);
	UNUSED(channelID);
}

void MumblePlugin::onUserTalkingStateChanged(mumble_connection_t connection, mumble_userid_t userID,
											 mumble_talking_state_t talkingState) noexcept {
	UNUSED(connection);
	UNUSED(userID);
	UNUSED(talkingState);
}

void MumblePlugin::onUserAdded(mumble_connection_t connection, mumble_userid_t userID) noexcept {
	UNUSED(connection);
	UNUSED(userID);
}

void MumblePlugin::onUserRemoved(mumble_connection_t connection, mumble_userid_t userID) noexcept {
	UNUSED(connection);
	UNUSED(userID);
}

void MumblePlugin::onChannelAdded(mumble_connection_t connection, mumble_channelid_t channelID) noexcept {
	UNUSED(connection);
	UNUSED(channelID);
}

void MumblePlugin::onChannelRemoved(mumble_connection_t connection, mumble_channelid_t channelID) noexcept {
	UNUSED(connection);
	UNUSED(channelID);
}

void MumblePlugin::onChannelRenamed(mumble_connection_t connection, mumble_channelid_t channelID) noexcept {
	UNUSED(connection);
	UNUSED(channelID);
}

#endif // MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS
bool MumblePlugin::onAudioInput(short *inputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRate,
								bool isSpeech) noexcept {
	UNUSED(inputPCM);
	UNUSED(sampleCount);
	UNUSED(channelCount);
	UNUSED(sampleRate);
	UNUSED(isSpeech);

	return false;
}

bool MumblePlugin::onAudioSourceFetched(float *outputPCM, uint32_t sampleCount, uint16_t channelCount,
										uint32_t sampleRate, bool isSpeech, mumble_userid_t userID) noexcept {
	UNUSED(outputPCM);
	UNUSED(sampleCount);
	UNUSED(channelCount);
	UNUSED(sampleRate);
	UNUSED(isSpeech);
	UNUSED(userID);

	return false;
}

bool MumblePlugin::onAudioAboutOutputAboutToPlay(float *outputPCM, uint32_t sampleCount, uint16_t channelCount,
												 uint32_t sampleRate) noexcept {
	UNUSED(outputPCM);
	UNUSED(sampleCount);
	UNUSED(channelCount);
	UNUSED(sampleRate);

	return false;
}

#endif // MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS
bool MumblePlugin::onReceiveData(mumble_connection_t connection, mumble_userid_t senderID, const uint8_t *data,
								 std::size_t dataLength, const char *dataID) noexcept {
	UNUSED(connection);
	UNUSED(senderID);
	UNUSED(data);
	UNUSED(dataLength);
	UNUSED(dataID);

	return false;
}

#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS
void MumblePlugin::onKeyEvent(uint32_t keyCode, bool wasPress) noexcept {
	UNUSED(keyCode);
	UNUSED(wasPress);
}

#endif // MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES
bool MumblePlugin::hasUpdate() noexcept {
	return false;
}

MumbleStringWrapper MumblePlugin::getUpdateDownloadURL() const noexcept {
	MumbleStringWrapper wrapper;
	wrapper.data           = nullptr;
	wrapper.size           = 0;
	wrapper.needsReleasing = false;

	return wrapper;
}

#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES
