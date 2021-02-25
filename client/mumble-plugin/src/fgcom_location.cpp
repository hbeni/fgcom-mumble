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

/**
 * @class fgcom_location
 * @brief A class holding location data. Also provides range calculation 
 * functions.
 */
class fgcom_location {
private:
	float longitude = 0.000;
	float latitude = 0.000;
	float altitude = 0.000;
	bool dirty = false;
public:
	float getLon();
    float getLat();
    float getAlt();

	bool isDirty();
	bool isInRange(fgcom_location loc);
	
	void setClean();
	void set(float lon,float lat,float alt);
};

///Returns stored longitude
float fgcom_location::getLon(){return longitude;}
///Returns stored latitude
float fgcom_location::getLat(){return latitude;}
///Returns stored altitude
float fgcom_location::getAlt(){return altitude;}
///Checks to see if location changed since it was set clean
bool fgcom_location::isDirty() {return dirty;}

/**
 * @brief Checks to see if supplied location is in range of stored location.
 * @todo Needs calculation code here. Still always returns true.
 */

bool fgcom_location::isInRange(fgcom_location loc) {
	return true;	
}

///Clears dirty status
void fgcom_location::setClean() {dirty = false;}


/**
 * @brief Sets or updates values if they do not match currently stored 
 * values. Also sets dirty status when updated.
 * @see isDirty()
 * @see setClean();
 */

void fgcom_location::set(float lon,float lat,float alt) {
	if(lon != longitude) {
		longitude = lon;
		dirty = true;
	}
	if(lat != latitude) {
		latitude = lat;
		dirty = true;
	}
	if(alt != altitude) {
		altitude = alt;
		dirty = true;
	}
}

#endif
