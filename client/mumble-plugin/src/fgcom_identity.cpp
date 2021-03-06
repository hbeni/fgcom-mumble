/*******************************************************************//**
 * @file        fgcom-identity.cpp
 * @brief       Defines fgcom_identity class
 * @authors    	Benedikt Hallinger & mill-j
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
 * @todo Move definition into fgcom_identity header
 */



#ifndef _FGCOM_IDENTITY_
#define _FGCOM_IDENTITY_

#include <vector>
#include <string>

#include "fgcom_radio.cpp"
#include "fgcom_location.cpp"
#include "fgcom_keyvalue.cpp"

/** 
 * Notification types
 * 0=all local info; 1=location data; 2=comms, 3=ask for data, 4=userdata, 5=ping
 */
enum FGCOM_NOTIFY_T {
    NTFY_ALL = -1,
    NTFY_USR = 4,
    NTFY_LOC = 1,
    NTFY_COM = 2,
    NTFY_ASK = 3,
    NTFY_PNG = 5
};

/**
 * @class fgcom_identity
 * @brief A class holding data for one user. This includes callsign, location
 * radios, etc.
 */
 
class fgcom_identity {
private:
	std::vector<fgcom_radio> radios;
	fgcom_location location;
	std::string callsign = "";
	int uid = -1;
public:
	

	void addRadio(fgcom_radio radio);
	
	fgcom_radio getRadio(int sel);
	fgcom_location getLocation();
	std::string getCallsign();
	int getUid();
	
	std::string getUdpId(FGCOM_NOTIFY_T Mode, int Com);
	std::vector<unsigned char> getUdpMsg(FGCOM_NOTIFY_T Mode, int Com);
	
	bool isAnyPTT();
		
	int radioCount();
		
	void setRadio(fgcom_radio radio, int sel);
	void setCallsign(std::string Callsign);
	void setLocation(fgcom_location Location);
	void setUid(int UID);
};

/**
 * @brief Pushes another radio the the array. Use setRadio() to change an 
 * existing one.
 * @see setRadio()
 */
void fgcom_identity::addRadio(fgcom_radio radio) {
	radios.push_back(radio);
}


///Returns the selected radio
fgcom_radio fgcom_identity::getRadio(int sel) {
	fgcom_radio empty;
	if(sel >= radioCount())
		return empty;
	
	return radios[sel];
}
///Returns the user's location
fgcom_location fgcom_identity::getLocation() {return location;}
///Returns the user's callsign
std::string fgcom_identity::getCallsign() {return callsign;}
///Returns user's unique id
int fgcom_identity::getUid() {return uid;}

///Returns a string with udp dataID
std::string fgcom_identity::getUdpId(FGCOM_NOTIFY_T Mode,int Com) {
	switch(Mode) {
		case NTFY_USR: {
			return "FGCOM:UPD_USR:"+std::to_string(uid);
		}
		case NTFY_LOC: { 
			return "FGCOM:UPD_LOC:"+std::to_string(uid);
		}
		case NTFY_COM: {
			///@todo Maybe Use frequency instead of dialed frequency
			return "FGCOM:UPD_COM:"+std::to_string(uid)+":"+std::to_string(Com);
		}
		case NTFY_ASK: {
			return "FGCOM:ICANHAZDATAPLZ";
		}
		case NTFY_PNG: {
			return "FGCOM:PING";
		}
	}
}


///Returns a fgcom_keyvalue object with the id and message.
std::vector<unsigned char> fgcom_identity::getUdpMsg(FGCOM_NOTIFY_T Mode, int Com) {
	std::string msg;
	
	switch(Mode) {
		case NTFY_USR: {
			msg =  "CALLSIGN="+callsign;
			break;
		}
		case NTFY_LOC: { 
			msg =  location.getUdpLoc()+",";
			break;
		}
		case NTFY_COM: {
			///@todo Maybe Use frequency instead of dialed frequency
			msg =  "FRQ="+radios[Com].getDialedFrequency()+","
				+ "CHN="+radios[Com].getDialedFrequency()+","
                + "PTT="+radios[Com].getPTT()+","
				+ "PWR="+std::to_string(radios[Com].getWatts());
			break;
		}
		case NTFY_ASK: {
			msg =  "allYourDataBelongsToUs!";
			break;
		}
		default: {
			msg =  "";
			break;
		}
	}
	
	std::cout<<"Send Data: "<<msg<<std::endl;
	return std::vector<unsigned char>( msg.begin(), msg.end() );
}



///Returns the number of radios in this identity
int fgcom_identity::radioCount() {return radios.size();}

///Returns true if any of the radios have a ptt toggled
bool fgcom_identity::isAnyPTT() {
	for(int a = 0; a < radioCount(); a++)
		if(radios[a].isPTT())
			return true;
	return false;
}


/**
 * @brief Sets the selected radio. If radio does not exist it creates it.
 * However it currently only creates a new radio if sel == radios.size().
 * If sel is > radios.size() nothing is done.
 */
void fgcom_identity::setRadio(fgcom_radio radio, int sel) {
	
	if(sel < radios.size())
		radios[sel] = radio;
	else if(sel == radios.size()) {
		fgcom_radio radio;
		radios.push_back(radio);
		radios[sel] = radio;
	}
		
}

///Updates the callsign
void fgcom_identity::setCallsign(std::string Callsign) {callsign = Callsign;}
///Updates the location
void fgcom_identity::setLocation(fgcom_location Location) {location = Location;}
///Sets the unique ID for this fgcom_identity
void fgcom_identity::setUid(int UID) {uid = UID;}

#endif
