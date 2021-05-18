/*******************************************************************//**
 * @file        fgcom_stateManager.cpp
 * @brief       Defines fgcom_stateManager class
 * @authors    	mill-j & 
 * @copyright   (C) 2021 under GNU GPL v3 
 *  
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * @todo Move definition into header
 **********************************************************************/
#ifndef _FGCOM_STATEMANAGER__
#define _FGCOM_STATEMANAGER__

#include <vector>
#include "fgcom_identity.cpp"

/**
 * @class fgcom_stateManager
 * @brief A class for storing and managing multiple fgcom_identity instances.
 */
class fgcom_stateManager {
private:
	fgcom_identity localUser; 					///>Holds local user info
	std::vector<fgcom_identity> remoteUsers;	///>Holds remote user info
	int findUserByID(int UID);
public:	
	void clearRemoteUsers();
	
	void deleteRemoteUser(int Select);
	
	int getCount();
	fgcom_identity getLocalUser();
	fgcom_identity getRemoteUser(int Select);
	std::vector<mumble_userid_t> getUserIDs();
	
	void setLocalUser(fgcom_identity);
	void setLocalUid(int UID);
	void setRemoteUser(fgcom_identity);
};

///Deletes all remote user identities
void fgcom_stateManager::clearRemoteUsers(){remoteUsers.clear();}

///Deletes the fgcom_identity instance from the internal array of users
void fgcom_stateManager::deleteRemoteUser(int UID) {
	if(findUserByID(UID) != -1)
		remoteUsers.erase(remoteUsers.begin() + findUserByID(UID));
}

/**
 * @brief Used internally only. Converts a UID into an array selector(0 - getCount()) 
 * @returns -1 if UID not found
 */
int fgcom_stateManager::findUserByID(int UID) {
	for(unsigned int a = 0; a < getCount();a++)
		if(remoteUsers[a].getUid() == UID)
			return a;
	return -1;
}

///Returns the number of stored remote users
int fgcom_stateManager::getCount() {return remoteUsers.size();}

///Returns local fgcom_identity instance
fgcom_identity fgcom_stateManager::getLocalUser(){return localUser;}

/**
 * @brief Returns the fgcom_identity with a UID matching the UID argument.
 * @returns An empty fgcom_identity if matching UID is not found.
 * @todo Maybe add fgcom_identity if UID not found? Should never happen though.
 */
fgcom_identity fgcom_stateManager::getRemoteUser(int UID) {
	fgcom_identity empty;
	if(findUserByID(UID) != -1)
		return remoteUsers[findUserByID(UID)];
	else
		return empty;
}

/**
 * @brief This function is for use with MumbleAPI::sendData() if you need 
 * to send data to all remote users.
 */
std::vector<mumble_userid_t> fgcom_stateManager::getUserIDs() {
	std::vector<mumble_userid_t> IDs;
	for(unsigned int a = 0; a < getCount();a++) {
		IDs.push_back(remoteUsers[a].getUid());
	}
	return IDs;
}

///Sets the local fgcom_identity instance
void fgcom_stateManager::setLocalUser(fgcom_identity User){localUser = User;}

///Convenience function, Sets the UID for the local user.
void fgcom_stateManager::setLocalUid(int UID) {localUser.setUid(UID);}

/**
 * @brief Uses the UID in the fgcom_identity instance to select the user to update.
 * Adds the user to the array if matching UID is not found
 */
void fgcom_stateManager::setRemoteUser(fgcom_identity User) {
	if(findUserByID(User.getUid()) != -1)
		remoteUsers[findUserByID(User.getUid())] = User;
	else
		remoteUsers.push_back(User);
}

#endif
