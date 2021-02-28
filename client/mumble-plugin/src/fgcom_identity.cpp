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
	
	void setAll(int UID, std::vector<fgcom_radio> Radios,fgcom_location Location, std::string Callsign);
	
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
fgcom_radio fgcom_identity::getRadio(int sel) {return radios[sel];}
///Returns the user's location
fgcom_location fgcom_identity::getLocation() {return location;}
///Returns the user's callsign
std::string fgcom_identity::getCallsign() {return callsign;}
///Returns user's unique id
int fgcom_identity::getUid() {return uid;}

void fgcom_identity::setAll(int UID, std::vector<fgcom_radio> Radios,fgcom_location Location, std::string Callsign) {
	
}

void fgcom_identity::setRadio(fgcom_radio radio, int sel) {
	
	if(sel < radios.size())
		radios[sel] = radio;
	else if(sel == radios.size()) {
		fgcom_radio radio;
		radios.push_back(radio);
		radios[sel] = radio;
	}
		
}
void fgcom_identity::setCallsign(std::string Callsign) {callsign = Callsign;}
void fgcom_identity::setLocation(fgcom_location Location) {location = Location;}
void fgcom_identity::setUid(int UID) {uid = UID;}
#endif
