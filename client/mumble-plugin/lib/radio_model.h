// A radio model for the FGCom-mumble plugin
//
// This just defines some functions that are used from the plugin.
//

#ifndef FGCOM_RADIOMODEL_H
#define FGCOM_RADIOMODEL_H

/*
 * Calculates the distance to horizon for an given observer at height h.
 *
 * @param h height in meters above surface
 * @returns the distance to horizon in km
 */
double fgcom_radiowave_getDistToHorizon(float h);


/*
 * See if two observers can see each other.
 * 
 * @param dist Distance between the two observers in km
 * @param hA   height of observer A, in meters above surface
 * @param hB   height of observer B, in meters above surface
 * @return height of observer B above A's horizon in meters (if this is negative, its hidden).
 */
double fgcom_radiowave_heightAboveHorizon(double dist, float hA, float hB);


/*
 * Get slant distance (length of line of sight)
 * 
 * @param surfacedist surface distance between the two objects in km
 * @param hah  visible height of observed object above horizon in m (@see heightAboveHorizon()), must be corrected for own height!
 * @return double slant distance in km
 */
double fgcom_radiowave_getSlantDistance(double surfacedist, double hah);


/*
 * Get angle of visible height above horizon.
 * 
 * @param surfacedist surface distance between the two objects in km
 * @param hah  visible height of observed object above horizon in m (@see heightAboveHorizon()), must be corrected for own height!
 * @return float Degrees of the visible height
 */
double fgcom_radiowave_degreeAboveHorizon(double surfacedist, double hah);


/*
 * Get distance (great circle) for two objects based on lat/lon
 * 
 * @param lat1  Latitude of object A
 * @param lon1  Longitude of object A
 * @param lat2  Latitude of object B
 * @param lon2  Longitude of object B
 * @return great circle distance in km (as the crow flies)
 */
double fgcom_radiowave_getSurfaceDistance(double lat1, double lon1, double lat2, double lon2);


#endif
