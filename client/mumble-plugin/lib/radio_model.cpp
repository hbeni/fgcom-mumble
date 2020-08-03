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
#include <regex>
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


/*
 * Extract numeric frequency from string and clean string from leading zeroes/spaces
 */
fgcom_radiowave_freqConvRes fgcom_radiowave_splitFreqString(std::string frq) {
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    // construct default return value: use as-is
    struct fgcom_radiowave_freqConvRes res;
    res.frequency = frq;
    res.isNumeric = false;
    
    try {
        std::smatch sm;
        if (std::regex_match(frq, sm, std::regex("^[\\s0]*((?:RECORD_)?)([0-9.]+?)[\\s]*$") )) {
            // numeric frequency detected.
            // note: it is important for further detection that we keep the nmber of decimals unaltered!
            res.prefix    = sm[1];
            res.frequency = sm[2];
            res.isNumeric = true;
            return res;
        } else {
            // not numeric: use as-is
            return res;
        }
    } catch (const std::exception& e) {
        // parsing error: fall back to use-as-is
        return res;
    }
}


/* 
 * Convert 25kHz/8.33kHz channel name frequencies to real carrier frequency.
 * 
 * This is done according to the list from https://833radio.com/news/show/7
 * and much appreciated help from Michael "mickybadia" Filhol (ATC-Pie developer, where some of the code here is borrowed)
 * 
 * @param frq cleaned frequency string like "118.02" or "118.025"
 * @return frequency string of corresponding real wave frequency, like "118.0250"
 */
std::string fgcom_radiowave_conv_chan2freq(std::string frq) {
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
    std::smatch sm;
    if (std::regex_match(frq, sm, std::regex("^\\d+(\\.?)$") )) {
        // we have some MHz frequency like "123". We ensure a frequency with decimals.
        if (sm[1].length() == 0) {
            frq = frq+".00";
        } else {
            frq = frq+"00";
        }
//         std::cout << "fgcom_radiowave_conv_chan2freq(): added two decimals: " << frq << std::endl;
    } else if (std::regex_match(frq, std::regex("^\\d+\\.\\d$") )) {
        // we have some MHz frequency like "123.3". We ensure a frequency with decimals.
        frq = frq+"0";
//         std::cout << "fgcom_radiowave_conv_chan2freq(): added one decimal: " << frq << std::endl;
    }

    if (std::regex_match(frq, sm, std::regex("^(\\d+)\\.(\\d)(\\d)$") )) {
        // we have a 25kHz shortened channel name like "123.35". Valid endings are 0, 2, 5, 7
//         std::cout << "fgcom_radiowave_conv_chan2freq(): 25khz short name detected: " << frq << std::endl;
        if (sm[3] == "2" || sm[3] == "7") {
            // ._2 and ._7 endings are old shortened names for odd 25kHz-step freq's (.02 -> .0250)
            return frq + "50";
        } else if (sm[3] == "0" || sm[3] == "5") {
            // ._0 and ._5 endings are old shortened names for whole 25kHz-step freq's (.05 -> .0500)
            return frq + "00";
        } else {
//             std::cout << "fgcom_radiowave_conv_chan2freq(): invalid ending: " << sm[3] << std::endl;
            return frq; // invalid ending, just return the frq
        }
        
    } else if (std::regex_match(frq, sm, std::regex("^(\\d+)\\.(\\d)(\\d)(\\d)$") )) {
        // we have a proper 25kHz channel name (like "118.025") OR an 8.33 channel name (like "118.015")
        
        std::string lastTwo = std::string(sm[3]) + std::string(sm[4]);
        // if the last two digits form a valid 8.33 spacing channel name, we need to convert them to the base frequency
        if (lastTwo == "05" || lastTwo == "10" ||
            lastTwo == "15" || lastTwo == "30" ||
            lastTwo == "35" || lastTwo == "40" ||
            lastTwo == "55" || lastTwo == "60" ||
            lastTwo == "65" || lastTwo == "80" ||
            lastTwo == "85" || lastTwo == "90"    ) {
//             std::cout << "fgcom_radiowave_conv_chan2freq(): 8.33khz channel name detected: " << frq << std::endl;
            // valid 8.33 channel name: Expand to corresponding real frequency
        
            // convert first subchannel to its 25kHz base frequency (like "._30" -> "._25")
//             std::cout << "fgcom_radiowave_conv_chan2freq():  preswap=" << lastTwo;
            if (lastTwo == "05") lastTwo = "00";
            if (lastTwo == "30") lastTwo = "25";
            if (lastTwo == "55") lastTwo = "50";
            if (lastTwo == "80") lastTwo = "75";
//             std::cout << "; postswap=" << lastTwo << std::endl;
            std::string tgtfrq = std::string(sm[1]) + "." + std::string(sm[2]) + lastTwo;
//             std::cout << "tgtfrq=" << tgtfrq << std::endl;
  
            if (lastTwo == "00" || lastTwo == "25" || lastTwo == "50" || lastTwo == "75") {
                // just map trough the fixed old 25kHz representations
//                 std::cout << "  mapTrough=" << tgtfrq+"00" << std::endl;
                return tgtfrq+"00";
            } else {
                // get the nearest multiple of the spacing
                float spacing_MHz = .025 / 3;   // 8.33 kHz in mHz = 0.00833333
                float tgtfrq_f = std::stof(tgtfrq);
                int ch_833 = round(tgtfrq_f / spacing_MHz);    // get 8.33 channel number; eg round( 118.025 / 0.0083333)
                float realFrq_f = ch_833 * spacing_MHz; // calculate 8real .33 channel numbers frequency
//                 printf("  calculated channel#=%i (=%.5f)\n", ch_833, realFrq_f);
                
                // convert back to string for return
                char buffer [50];
                int len = sprintf (buffer, "%.5f", realFrq_f);   // 5 digits is 10Hz resolution.
                return std::string(buffer, len);
            }
        
        } else {
//             std::cout << "fgcom_radiowave_conv_chan2freq(): 25khz straight channel name detected: " << frq << std::endl;
            return frq + "0"; // 00, 25, 50, 75 are already straight 25kHz frequencies (.025 => .0250)
        }
        
    } else {
        // it was not parseable (unhandled format, note, we also don't need to handle real wave frequencies; the're used as-is)
//         std::cout << "fgcom_radiowave_conv_chan2freq(): unhandled : " << frq << std::endl;
        return frq;
    }
    
}


/*
 * See if the frequencies match.
 */
float fgcom_radiowave_getFrqMatch(std::string frq1_real, std::string frq2_real) {
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
    // default: case-sensitive string comparison
    float filter = (frq1_real == frq2_real)? 1.0 : 0.0;
    
//     std::cout << "fgcom_radiowave_getFrqMatch('" << frq1_real.c_str() << "', '" <<frq2_real.c_str() << "')" << std::endl;
//     std::cout << "fgcom_radiowave_getFrqMatch() default string match=" << filter << std::endl;
    
    // see if we can it make more precise.
    // that is the case if we have numerical values (after ignoring prefixes).
    try {
        fgcom_radiowave_freqConvRes frq1_p = fgcom_radiowave_splitFreqString(frq1_real);
        fgcom_radiowave_freqConvRes frq2_p = fgcom_radiowave_splitFreqString(frq2_real);
        if (frq1_p.isNumeric && frq2_p.isNumeric) {
            // numeric frequencies
            float frq1_f = std::stof(frq1_p.frequency);
            float frq2_f = std::stof(frq2_p.frequency);
            
            // calculate absolute "off" tuning / tunable window
            // 1.5-500x  => gives >1.0 at 0.001 (1kHz) difference, declining to 0.0. at 0.003 (3 kHz),
            //              yielding a tunable band of 6kHz around the 8.33kHz channel center,
            //              where the range 7.33->9.33 is perfect signal and 50% signal is at about 2kHz off.
            // TODO: Note, i completely made up those numbers. I have no idea of tuning radios. I just wanted to make sure, that 25kHz radios will receive 8.33 channels with overlapping stepsize while keeping the 8.33 channels distinct and with a gap between windows...
            float diff = std::fabs(frq1_f - frq2_f);
//             std::cout << "DBG CALC:" << std::endl;
//             std::cout << "   frq1_p=" << frq1_p.frequency << std::endl;
//             std::cout << "   frq1_f=" << frq1_f << std::endl;
//             std::cout << "   frq2_p=" << frq2_p.frequency << std::endl;
//             std::cout << "   frq2_f=" << frq1_f << std::endl;
            filter     = 1.5 - 500 * diff;
//             std::cout << "   diff=" << diff << "; filter=" << filter << std::endl;
            if (filter > 1.0) filter = 1.0;
            if (filter < 0.0) filter = 0.0;
            
            return filter;
        } else {
            // not numeric: return default
            return filter;
        }
    } catch (const std::exception& e) {
        // fallback in case of errors: return default
        return filter;
    }
}
