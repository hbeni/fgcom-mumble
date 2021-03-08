/*******************************************************************//**
 * @file        fgcom_location.cpp
 * @brief       Defines fgcom_location class
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
 */


#ifndef _FGCOM_LOCATION_
#define _FGCOM_LOCATION_

#include <string>

/**
 * @class fgcom_location
 * @brief A class holding location data.
 * functions.
 */
class fgcom_location {
private:
	float longitude = 0.000;
	float latitude = 0.000;
	float altitude = 0.000;
public:
	float getLon();
    float getLat();
    float getAlt();
    std::string getUdpLoc();

	bool isEqual(fgcom_location loc);
	
	void set(float lon,float lat,float alt);
	void setLon(float);
    void setLat(float);
    void setAlt(float);
};

///Returns stored longitude
float fgcom_location::getLon(){return longitude;}
///Returns stored latitude
float fgcom_location::getLat(){return latitude;}
///Returns stored altitude
float fgcom_location::getAlt(){return altitude;}

///Returns location as a string to send ia udp
std::string fgcom_location::getUdpLoc() {
	return "LAT="+std::to_string(latitude)+","+"LON="+std::to_string(longitude)+"," +"ALT="+std::to_string(altitude);
}

///Returns true if both fgcom_locations are equal
bool fgcom_location::isEqual(fgcom_location loc) {
	if(longitude != loc.getLon() || 
			latitude != loc.getLat() ||
					altitude != loc.getAlt()) 
		return false;
	else
		return true;
}

/**
 * @brief Sets or updates values if they do not match currently stored 
 * values. 
 */

void fgcom_location::set(float lon,float lat,float alt) {
	longitude = lon;
	latitude = lat;
	altitude = alt;
}

///Sets latitude
void fgcom_location::setLat(float lat) {latitude = lat;}
///Sets longitude
void fgcom_location::setLon(float lon) {longitude = lon;}
///Sets altitude
void fgcom_location::setAlt(float alt) {altitude = alt;}
#endif
