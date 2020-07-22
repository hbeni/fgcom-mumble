/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
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
 */


// A radio model for the FGCom-mumble plugin
//
// This just defines some functions that are used from the plugin.
//

#include <iostream> 
#include <cmath>
#include "radio_model.h"

#define EARTH_RADIUS_CONST 3.57  // earth radius factor constant for m/km
#define EARTH_RADIUS_AVG   6371  // earth radius constant in km

double fgcom_radiowave_getDistToHorizon(float h) {
    // Formula is the simple one from https://en.wikipedia.org/wiki/Horizon#Objects_above_the_horizon
    // it is not perfectly accurate, but good enough for our purpose.
    return EARTH_RADIUS_CONST * sqrt(h);
}

double fgcom_radiowave_heightAboveHorizon(double dist, float hA, float hB) {
    double horizA          = fgcom_radiowave_getDistToHorizon(hA);
    double distB_behHoriz  = dist - horizA;
    if (distB_behHoriz < 0) {
        // negative: object is nearer than horizon = fully visible
        return hB;
        
    } else {
        // positive: the object is somewhere behind A's horizon and thus at least partly covered by earth
        double heightB_visible = pow(distB_behHoriz / EARTH_RADIUS_CONST, 2); // the result is the minimum visible altitude at that distance (A sees anything that is higher than this)
        double opticalHeight = hB - heightB_visible; // opticalHeight = real height - earth radius clipping
        
        return opticalHeight; // when negative: the object is hidden behind earth positive: the object appears that much above the horizont
    }
}

double fgcom_radiowave_getSlantDistance(double surfacedist, double hah) {
    // simple pythargoras, where we search the hypotehnuse :)
    return sqrt( pow(surfacedist, 2) + pow(hah/1000, 2) );
}

double fgcom_radiowave_degreeAboveHorizon(double surfacedist, double hah) {
    // simple pythargoras, where we search the angle alpha
    double distM = surfacedist * 1000; // in m because hah is also in m
    double hypo  = sqrt( pow(distM, 2) + pow(hah, 2) ); 
    
    if (hah == 0)  return 0; // in case of horizontal alignment
    if (hypo == 0) return (hah >=0)? 90: -90; // in case the tgt point lies directly above/below
    double sinA = hah / hypo;
    double angle = (sinA != 0)? asin(sinA) * (180.0 / M_PI) : 0;
    return angle;
}

double fgcom_radiowave_getDirection(double lat1, double lon1, double lat2, double lon2) {
    // Get the target point as viewed from coordinate origin, so atan2 can get the quadrant right
    // We apply haversine here, so we get the real length based on lat/lon position on
    // earth (wgs84 cells are only regularly shaped near the equator: size depends on location)
    double dLat = fgcom_radiowave_getSurfaceDistance(lat1, lon1, lat2, lon1); // y distance in km
    double dLon = fgcom_radiowave_getSurfaceDistance(lat1, lon1, lat1, lon2); // x distance in km
    if (lat2 < lat1) dLat *= -1; // apply sign (down is negative vector)
    if (lon2 < lon1) dLon *= -1; // apply sign (left is negative vector)

    double brng = atan2(dLat, dLon) * (180.0 / M_PI);  // 0°=east, 90°=north, etc; lat=y, lon=x
    brng = 360 - brng; // count degrees clockwise
    brng += 90; // atan returns with east=0°, so we need to rotate right (atan counts counter-clockwise)
    
    // normalize values from -180/+180 to range 0/360
    if (brng < 360) brng += 360;
    if (brng > 360) brng -= 360;
    if (brng == 360) brng = 0;

    return brng;
}

double fgcom_radiowave_getSurfaceDistance(double lat1, double lon1, 
                        double lat2, double lon2) {
    
    // The Haversine function does solve this for us.
    // Note that haversine assumes a perfect circular geoid, but earth is not perfect round.
    // for the distance we are talking here, that does not really matter tough.
    
    // This is the haversine function from Mahadev. Thank you very much!
    // taken from: https://www.geeksforgeeks.org/haversine-formula-to-find-distance-between-two-points-on-a-sphere/
    
    // distance between latitudes 
    // and longitudes 
    double dLat = (lat2 - lat1) * 
                    M_PI / 180.0; 
    double dLon = (lon2 - lon1) *  
                    M_PI / 180.0; 

    // convert to radians 
    lat1 = (lat1) * M_PI / 180.0; 
    lat2 = (lat2) * M_PI / 180.0; 

    // apply formulae 
    double a = pow(sin(dLat / 2), 2) +  
                pow(sin(dLon / 2), 2) *  
                cos(lat1) * cos(lat2); 
    double rad = EARTH_RADIUS_AVG; // average earth radius
    double c = 2 * asin(sqrt(a)); 
    return rad * c; 
} 

fgcom_radiowave_signal fgcom_radiowave_getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    struct fgcom_radiowave_signal signal;
    
    // get distance to radio horizon (that is the both ranges combined)
    double radiodist = fgcom_radiowave_getDistToHorizon(alt1) + fgcom_radiowave_getDistToHorizon(alt2);
    
    // get surface distance
    double dist = fgcom_radiowave_getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // get if they can see each other. VHF will have no connection when no line-of-sight is present.
    double heightAboveHorizon = fgcom_radiowave_heightAboveHorizon(dist, alt1, alt2);
    if (heightAboveHorizon < 0) return signal;  // no, they cant, bail out without signal.

    // get slant distance (in km) so we can calculate signal strenght based on distance
    double slantDist = fgcom_radiowave_getSlantDistance(dist, heightAboveHorizon-alt1);
    
    // power/distance model
    // It is currently modelled very simply (linearly) and NOT REALISTICALLY!
    // Main target now is to get some geographic separation. Main Factor vor VHF is line-of-sight anyways.
    // TODO: Make this more realistic! Depends probably also on antenna used at sender and receiver.
    // TODO: Take terrain effects into account. We could probably use the 3° ASTER/SRTM data for that. This will mute the radio behind mountains :)
    // current formula: (-1/wr*x^2+100)/100, where wr=wattpower*50 and x=slatDistance in km
    float wr = power * 50; // gives maximum range in km for the supplied power
    float ss = (-1/wr*pow(slantDist,2)+100)/100;  // gives @10w: 50km=0.95 100km=0.8 150km=0.55 200km=0.2
    
    if (ss <=0.0) return signal; // in case signal strength got neagative, that means we are out of range (too less tx-power)
    
    // when distance is near the radio horizon, we smoothly cut off the signal, so it doesn't drop sharply to 0
    float usedRange = slantDist/radiodist;
    float usedRange_cutoffPct = 0.9; // at which percent of used radio horizon we start to cut off
    if (usedRange > usedRange_cutoffPct) {
        float loss    = (usedRange - usedRange_cutoffPct) * 10; //convert to percent range: 0.9=0%  0.95=0.5(50%)  1.0=1.0(100%)
        //printf("DBG: distance near radio horizon (%.2f/%.2f=%.2f); raw strength=%.2f; loss=%.2f; result=%.2f\n", slantDist, radiodist, usedRange, ss, loss, ss*(1-loss) );
        ss = ss * (1-loss); // apply loss to signal
    }
    
    // prepare return struct
    signal.quality       = ss;
    signal.direction     = fgcom_radiowave_getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = fgcom_radiowave_degreeAboveHorizon(dist, alt2-alt1);
    return signal;
}
