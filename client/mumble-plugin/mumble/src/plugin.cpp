// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "mumble/plugin/MumblePlugin.h"
#include "mumble/plugin/internal/MumblePlugin_v_1_0_x.h"

extern "C" {
PLUGIN_EXPORT mumble_error_t PLUGIN_CALLING_CONVENTION mumble_init(uint32_t id) {
	return MumblePlugin::getPlugin().internal_init(id);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_shutdown() {
	MumblePlugin::getPlugin().internal_shutdown();
}

PLUGIN_EXPORT struct MumbleStringWrapper PLUGIN_CALLING_CONVENTION mumble_getName() {
	return MumblePlugin::getPlugin().getName();
}

PLUGIN_EXPORT mumble_version_t PLUGIN_CALLING_CONVENTION mumble_getAPIVersion() {
	return MumblePlugin::getPlugin().getAPIVersion();
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_registerAPIFunctions(void *apiStruct) {
	MumblePlugin::getPlugin().registerAPIFunctions(apiStruct);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_releaseResource(const void *pointer) {
	MumblePlugin::getPlugin().releaseResource(pointer);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_setMumbleInfo(mumble_version_t mumbleVersion,
																  mumble_version_t mumbleAPIVersion,
																  mumble_version_t minimalExpectedAPIVersion) {
	MumblePlugin::getPlugin().setMumbleInfo(mumbleVersion, mumbleAPIVersion, minimalExpectedAPIVersion);
}

PLUGIN_EXPORT mumble_version_t PLUGIN_CALLING_CONVENTION mumble_getVersion() {
	return MumblePlugin::getPlugin().getVersion();
}

PLUGIN_EXPORT struct MumbleStringWrapper PLUGIN_CALLING_CONVENTION mumble_getAuthor() {
	return MumblePlugin::getPlugin().getAuthor();
}

PLUGIN_EXPORT struct MumbleStringWrapper PLUGIN_CALLING_CONVENTION mumble_getDescription() {
	return MumblePlugin::getPlugin().getDescription();
}

PLUGIN_EXPORT uint32_t PLUGIN_CALLING_CONVENTION mumble_getFeatures() {
	return MumblePlugin::getPlugin().getFeatures();
}

PLUGIN_EXPORT uint32_t PLUGIN_CALLING_CONVENTION mumble_deactivateFeatures(uint32_t features) {
	return MumblePlugin::getPlugin().deactivateFeatures(features);
}

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO
PLUGIN_EXPORT uint8_t PLUGIN_CALLING_CONVENTION mumble_initPositionalData(const char **programNames,
																		  const uint64_t *programPIDs,
																		  size_t programCount) {
	return MumblePlugin::getPlugin().internal_initPositionalData(programNames, programPIDs, programCount);
}

PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_fetchPositionalData(float *avatarPos, float *avatarDir,
																		float *avatarAxis, float *cameraPos,
																		float *cameraDir, float *cameraAxis,
																		const char **context, const char **identity) {
	return MumblePlugin::getPlugin().fetchPositionalData(avatarPos, avatarDir, avatarAxis, cameraPos, cameraDir,
														 cameraAxis, context, identity);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_shutdownPositionalData() {
	MumblePlugin::getPlugin().shutdownPositionalData();
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS
PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onServerConnected(mumble_connection_t connection) {
	MumblePlugin::getPlugin().onServerConnected(connection);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onServerDisconnected(mumble_connection_t connection) {
	MumblePlugin::getPlugin().onServerDisconnected(connection);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onServerSynchronized(mumble_connection_t connection) {
	MumblePlugin::getPlugin().onServerSynchronized(connection);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onChannelEntered(mumble_connection_t connection,
																	 mumble_userid_t userID,
																	 mumble_channelid_t previousChannelID,
																	 mumble_channelid_t newChannelID) {
	MumblePlugin::getPlugin().onChannelEntered(connection, userID, previousChannelID, newChannelID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onChannelExited(mumble_connection_t connection,
																	mumble_userid_t userID,
																	mumble_channelid_t channelID) {
	MumblePlugin::getPlugin().onChannelExited(connection, userID, channelID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onUserTalkingStateChanged(mumble_connection_t connection,
																			  mumble_userid_t userID,
																			  mumble_talking_state_t talkingState) {
	MumblePlugin::getPlugin().onUserTalkingStateChanged(connection, userID, talkingState);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onUserAdded(mumble_connection_t connection,
																mumble_userid_t userID) {
	MumblePlugin::getPlugin().onUserAdded(connection, userID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onUserRemoved(mumble_connection_t connection,
																  mumble_userid_t userID) {
	MumblePlugin::getPlugin().onUserRemoved(connection, userID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onChannelAdded(mumble_connection_t connection,
																   mumble_channelid_t channelID) {
	MumblePlugin::getPlugin().onChannelAdded(connection, channelID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onChannelRemoved(mumble_connection_t connection,
																	 mumble_channelid_t channelID) {
	MumblePlugin::getPlugin().onChannelRemoved(connection, channelID);
}

PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onChannelRenamed(mumble_connection_t connection,
																	 mumble_channelid_t channelID) {
	MumblePlugin::getPlugin().onChannelRenamed(connection, channelID);
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS
PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_onAudioInput(short *inputPCM, uint32_t sampleCount,
																 uint16_t channelCount, uint32_t sampleRate,
																 bool isSpeech) {
	return MumblePlugin::getPlugin().onAudioInput(inputPCM, sampleCount, channelCount, sampleRate, isSpeech);
}

PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_onAudioSourceFetched(float *outputPCM, uint32_t sampleCount,
																		 uint16_t channelCount, uint32_t sampleRate,
																		 bool isSpeech, mumble_userid_t userID) {
	return MumblePlugin::getPlugin().onAudioSourceFetched(outputPCM, sampleCount, channelCount, sampleRate, isSpeech,
														  userID);
}

PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_onAudioOutputAboutToPlay(float *outputPCM, uint32_t sampleCount,
																			 uint16_t channelCount,
																			 uint32_t sampleRate) {
	return MumblePlugin::getPlugin().onAudioAboutOutputAboutToPlay(outputPCM, sampleCount, channelCount, sampleRate);
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS
PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_onReceiveData(mumble_connection_t connection,
																  mumble_userid_t senderID, const uint8_t *data,
																  size_t dataLength, const char *dataID) {
	return MumblePlugin::getPlugin().onReceiveData(connection, senderID, data, dataLength, dataID);
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS
PLUGIN_EXPORT void PLUGIN_CALLING_CONVENTION mumble_onKeyEvent(uint32_t keyCode, bool wasPress) {
	MumblePlugin::getPlugin().onKeyEvent(keyCode, wasPress);
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS

#ifdef MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES
PLUGIN_EXPORT bool PLUGIN_CALLING_CONVENTION mumble_hasUpdate() {
	return MumblePlugin::getPlugin().hasUpdate();
}

PLUGIN_EXPORT struct MumbleStringWrapper PLUGIN_CALLING_CONVENTION mumble_getUpdateDownloadURL() {
	return MumblePlugin::getPlugin().getUpdateDownloadURL();
}
#endif // MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES
};
