// Copyright 2019-2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

/// This header file contains the definition of Mumble's API

#ifndef MUMBLE_PLUGIN_API_H_
#define MUMBLE_PLUGIN_API_H_

#include "PluginComponents.h"
#include <stdint.h>

// API version
const int32_t MUMBLE_PLUGIN_API_MAJOR = 1;
const int32_t MUMBLE_PLUGIN_API_MINOR = 0;
const int32_t MUMBLE_PLUGIN_API_PATCH = 0;
const version_t MUMBLE_PLUGIN_API_VERSION = { MUMBLE_PLUGIN_API_MAJOR, MUMBLE_PLUGIN_API_MINOR, MUMBLE_PLUGIN_API_PATCH };


struct MumbleAPI {
	/////////////////////////////////////////////////////////
	////////////////////// GENERAL NOTE /////////////////////
	/////////////////////////////////////////////////////////
	//
	// All functions that take in a connection as a paremeter may only be called **after** the connection
	// has finished synchronizing. The only exception from this is isConnectionSynchronized.
	//
	// Strings returned by the API are UTF-8 encoded
	// Strings passed to the API are expected to be UTF-8 encoded


	// -------- Memory management --------
	
	/// Frees the given pointer.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param pointer The pointer to free
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *freeMemory)(plugin_id_t callerID, const void *pointer);


	
	// -------- Getter functions --------

	/// Gets the connection ID of the server the user is currently active on (the user's audio output is directed at).
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param[out] connection A pointer to the memory location the ID should be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then it is valid to access the
	/// 	value of the provided pointer
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getActiveServerConnection)(plugin_id_t callerID, mumble_connection_t *connection);

	/// Checks whether the given connection has finished initializing yet.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param[out] A pointer to the boolean variable that'll hold the info whether the server has finished synchronization yet
	/// 	after this function has executed successfully.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *isConnectionSynchronized)(plugin_id_t callerID, mumble_connection_t connection, bool *synchronized);

	/// Fills in the information about the local user.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param[out] userID A pointer to the memory the user's ID shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getLocalUserID)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t *userID);

	/// Fills in the information about the given user's name.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The user's ID whose name should be obtained
	/// @param[out] userName A pointer to where the pointer to the allocated string (C-encoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getUserName)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_userid_t userID, char **userName);

	/// Fills in the information about the given channel's name.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param channelID The channel's ID whose name should be obtained
	/// @param[out] channelName A pointer to where the pointer to the allocated string (C-ecoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getChannelName)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_channelid_t channelID, char **channelName);

	/// Gets an array of all users that are currently connected to the provided server. Passing a nullptr as any of the out-parameter
	/// will prevent that property to be set/allocated. If you are only interested in the user count you can thus pass nullptr as the
	/// users parameter and save time on allocating + freeing the channels-array while still getting the size out.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param[out] users A pointer to where the pointer of the allocated array shall be written. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @param[out] userCount A pointer to where the size of the allocated user-array shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getAllUsers)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t **users,
			size_t *userCount);

	/// Gets an array of all channels on the provided server. Passing a nullptr as any of the out-parameter will prevent
	/// that property to be set/allocated. If you are only interested in the channel count you can thus pass nullptr as the
	/// channels parameter and save time on allocating + freeing the channels-array while still getting the size out.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param[out] channels A pointer to where the pointer of the allocated array shall be written. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @param[out] channelCount A pointer to where the size of the allocated channel-array shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getAllChannels)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_channelid_t **channels, size_t *channelCount);

	/// Gets the ID of the channel the given user is currently connected to.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The ID of the user to search for
	/// @param[out] A pointer to where the ID of the channel shall be written
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getChannelOfUser)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t userID,
			mumble_channelid_t *channel);

	/// Gets an array of all users in the specified channel.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param channelID The ID of the channel whose users shall be retrieved
	/// @param[out] userList A pointer to where the pointer of the allocated array shall be written. The allocated memory has
	/// 	to be freed by a call to freeMemory by the plugin eventually. The memory will only be allocated if this function
	/// 	returns STATUS_OK.
	/// @param[out] userCount A pointer to where the size of the allocated user-array shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getUsersInChannel)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_channelid_t channelID, mumble_userid_t **userList, size_t *userCount);

	/// Gets the current transmission mode of the local user.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param[out] transmissionMode A pointer to where the transmission mode shall be written.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getLocalUserTransmissionMode)(plugin_id_t callerID, transmission_mode_t *transmissionMode);

	/// Checks whether the given user is currently locally muted.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The ID of the user to search for
	/// @param[out] muted A pointer to where the local mute state of that user shall be written
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *isUserLocallyMuted)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_userid_t userID, bool *muted);

	/// Gets the hash of the given user (can be used to recognize users between restarts)
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The ID of the user to search for
	/// @param[out] hash A pointer to where the pointer to the allocated string (C-encoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getUserHash)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_userid_t userID, char **hash);

	/// Gets the hash of the server for the given connection (can be used to recognize servers between restarts)
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection
	/// @param[out] hash A pointer to where the pointer to the allocated string (C-encoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getServerHash)(plugin_id_t callerID, mumble_connection_t connection, char **hash);

	/// Gets the comment of the given user. Note that a user might have a comment configured that hasn't been synchronized
	/// to this client yet. In this case this function will return EC_UNSYNCHRONIZED_BLOB. As of now there is now way
	/// to request the synchronization to happen via the Plugin-API.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection
	/// @param userID the ID of the user whose comment should be obtained
	/// @param[out] comment A pointer to where the pointer to the allocated string (C-encoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getUserComment)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_userid_t userID, char **comment);

	/// Gets the description of the given channel. Note that a channel might have a description configured that hasn't been synchronized
	/// to this client yet. In this case this function will return EC_UNSYNCHRONIZED_BLOB. As of now there is now way
	/// to request the synchronization to happen via the Plugin-API.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection
	/// @param channelID the ID of the channel whose comment should be obtained
	/// @param[out] description A pointer to where the pointer to the allocated string (C-encoded) should be written to. The
	/// 	allocated memory has to be freed by a call to freeMemory by the plugin eventually. The memory will only be
	/// 	allocated if this function returns STATUS_OK.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *getChannelDescription)(plugin_id_t callerID, mumble_connection_t connection,
			mumble_channelid_t channelID, char **description);


	// -------- Request functions --------
	
	/// Requests Mumble to set the local user's transmission mode to the specified one. If you only need to temporarily set
	/// the transmission mode to continous, use requestMicrophoneActivationOverwrite instead as this saves you the work of
	/// restoring the previous state afterwards.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param transmissionMode The requested transmission mode
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *requestLocalUserTransmissionMode)(plugin_id_t callerID, transmission_mode_t transmissionMode);

	/// Requests Mumble to move the given user into the given channel
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The ID of the user that shall be moved
	/// @param channelID The ID of the channel to move the user to
	/// @param password The password of the target channel (UTF-8 encoded as a C-string). Pass NULL if the target channel does not require a
	/// 	password for entering
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *requestUserMove)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t userID,
			mumble_channelid_t channelID, const char *password);

	/// Requests Mumble to overwrite the microphone activation so that the microphone is always on (same as if the user had chosen
	/// the continous transmission mode). If a plugin requests this overwrite, it is responsible for deactivating the overwrite again
	/// once it is no longer required
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param activate Whether to activate the overwrite (false deactivates an existing overwrite)
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *requestMicrophoneActivationOvewrite)(plugin_id_t callerID, bool activate);

	/// Requests Mumble to set the local mute state of the given client. Note that this only affects the **local** mute state
	/// opposed to a server-mute (client is globally muted by the server) or the client's own mute-state (client has muted its
	/// microphone and thus isn't transmitting any audio).
	/// Furthermore it must be noted that muting the local user with this function does not work (it doesn't make sense). If
	/// you try to do so, this function will fail. In order to make this work, this function will also fail if the server
	/// has not finished synchronizing with the client yet.
	///
	/// @param callerID The ID of the plugin calling this function.
	/// @param connection The ID of the server-connection to use as a context
	/// @param userID The ID of the user that shall be moved
	/// @param muted Whether to locally mute the given client (opposed to unmuting it)
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *requestLocalMute)(plugin_id_t callerID, mumble_connection_t connection, 
				mumble_userid_t userID, bool muted);

	/// Sets the comment of the local user
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection
	/// @param comment The new comment to use (C-encoded). A subset of HTML formatting is supported.
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer
	/// 	may be accessed
	mumble_error_t (PLUGIN_CALLING_CONVENTION *requestSetLocalUserComment)(plugin_id_t callerID, mumble_connection_t connection,
			const char *comment);



	// -------- Find functions --------
	
	/// Fills in the information about a user with the specified name, if such a user exists. The search is case-sensitive.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param userName The respective user's name
	/// @param[out] userID A pointer to the memory the user's ID shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer may
	/// 	be accessed.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *findUserByName)(plugin_id_t callerID, mumble_connection_t connection, const char *userName,
			mumble_userid_t *userID);

	/// Fills in the information about a channel with the specified name, if such a channel exists. The search is case-sensitive.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to use as a context
	/// @param channelName The respective channel's name
	/// @param[out] channelID A pointer to the memory the channel's ID shall be written to
	/// @returns The error code. If everything went well, STATUS_OK will be returned. Only then the passed pointer may
	/// 	be accessed.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *findChannelByName)(plugin_id_t callerID, mumble_connection_t connection,
			const char *channelName, mumble_channelid_t *channelID);



	// -------- Miscellaneous --------
	
	/// Sends the provided data to the provided client(s). This kind of data can only be received by another plugin active
	/// on that client. The sent data can be seen by any active plugin on the receiving client. Therefore the sent data
	/// must not contain sensitive information or anything else that shouldn't be known by others.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param connection The ID of the server-connection to send the data through (the server the given users are on)
	/// @param users An array of user IDs to send the data to
	/// @param userCount The size of the provided user-array
	/// @param data The data array that shall be sent. This can be an arbitrary sequence of bytes.
	/// @param dataLength The length of the data array
	/// @param dataID The ID of the sent data. This has to be used by the receiving plugin(s) to figure out what to do with
	/// 	the data. This has to be a C-encoded String.
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *sendData)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t *users,
			size_t userCount, const uint8_t *data, size_t dataLength, const char *dataID);

	/// Logs the given message (typically to Mumble's console). All passed strings have to be UTF-8 encoded.
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param message The message to log
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *log)(plugin_id_t callerID, const char *message);

	/// Plays the provided sample. It uses libsndfile as a backend so the respective file format needs to be supported by it
	/// in order for this to work out (see http://www.mega-nerd.com/libsndfile/).
	///
	/// @param callerID The ID of the plugin calling this function
	/// @param samplePath The path to the sample that shall be played (UTF-8 encoded)
	/// @returns The error code. If everything went well, STATUS_OK will be returned.
	mumble_error_t (PLUGIN_CALLING_CONVENTION *playSample)(plugin_id_t callerID, const char *samplePath);
};

#endif
