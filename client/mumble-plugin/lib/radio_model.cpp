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


// A modular radio model for the FGCom-mumble plugin
//
// The radio model is constructed from an abstract base class,
// which gets extended by concrete models for parts of the frequency spectrum.
// The model to be used for a given frequency can be retrived by the
// factory method fgcom_select_radiowave_model().

// include base implementation
#include "radio_model.h"
#include "radio_config.h"

// include concrete implementations
#include "radio_model_vhf.h"
#include "radio_model_hf.h"
#include "radio_model_uhf.h"
#include "radio_model_string.h"
#include "radio_model_amateur.h"
#include "non_amateur_hf.h"
#include "advanced_modulation.h"


/*
* First some utitliy functions
*/

// Calculate and store current operable state of a radio
bool fgcom_radio_updateOperable(fgcom_radio &r){
    bool oldOperableValue = r.operable;
    if (r.frequency == "<del>") {
        r.operable = false; // deleted radios are never operable!
    } else {
        bool serviceable = r.serviceable;
        bool switchedOn  = r.power_btn;
        bool powered     = (r.volts >= 1.0)? true:false; // some aircraft report boolean here, so treat 1.0 as powered
        r.operable = (serviceable && switchedOn && powered);
    }
    
    return (r.operable != oldOperableValue);
}


/****************************************************/
/*          Implement base class                    */
/* Submodels are implemented separate and inherit   */
/****************************************************/

/*
* Radio model Factory: Selects the correct model based on the frequency given
* 
* @param  freq the frequency string
* @return FGCom_radiowaveModel instance that handles the frequency
*/
std::unique_ptr<FGCom_radiowaveModel> FGCom_radiowaveModel::selectModel(std::string freq) {
    // Parse frequency string to extract numeric value and determine if it's a valid frequency
    fgcom_radiowave_freqConvRes freq_p = FGCom_radiowaveModel::splitFreqString(freq);
    if (freq_p.isNumeric) {
        // FREQUENCY BAND SELECTION LOGIC:
        // This factory method selects the appropriate radio model based on frequency.
        // Models may have overlapping frequency ranges, so order of checking is critical.
        // Priority: Special cases → Aviation → Maritime → Amateur → Standard bands
        
        float frq_num = std::stof(freq_p.frequency);
        
        // CRITICAL FIX: Use configuration system instead of hardcoded values
        // This allows runtime configuration and eliminates magic numbers
        float echo_test_freq = FGCom_RadioConfig::getFloat(FGCom_RadioConfig::ECHO_TEST_FREQUENCY, 910.0f);
        if (frq_num == echo_test_freq) {
            return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_VHF());
        }
        
        // AVIATION HF FREQUENCIES (3-30 MHz)
        // Commercial aviation uses specific HF frequencies for long-range communication
        // These frequencies have different propagation characteristics than amateur HF
        FGCom_NonAmateurHF::initialize();
        if (FGCom_NonAmateurHF::isAviationFrequency(frq_num)) {
            return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_AviationHF(35000.0, "COMMERCIAL"));
        }
        
        // MARITIME HF FREQUENCIES (2-30 MHz)
        // International maritime communication uses specific HF frequencies
        // These have different power limits and usage patterns than amateur HF
        if (FGCom_NonAmateurHF::isMaritimeFrequency(frq_num)) {
            return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_MaritimeHF("COMMERCIAL", true));
        }
        
        // AMATEUR RADIO FREQUENCIES (1.8-54 MHz)
        // Amateur radio has specific frequency allocations in the HF and VHF bands
        // These frequencies have different power limits and operating procedures
        if (frq_num >= 1800.0 && frq_num <= 54000.0) {
            // Initialize amateur radio data to check if this is a valid amateur frequency
            FGCom_AmateurRadio::initialize();
            // For now, use region 1 (can be made configurable later)
            if (FGCom_AmateurRadio::isAmateurFrequency(frq_num, 1)) {
                return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_Amateur(1));
            }
        }
        
        // STANDARD FREQUENCY BAND SELECTION:
        // HF: 0-30 MHz (long-range, sky wave propagation)
        // VHF: 30-300 MHz (line-of-sight, ground wave propagation)  
        // UHF: 300+ MHz (line-of-sight, very short range)
        if (frq_num <=  30.0)                    return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_HF());
        if (frq_num >  30.0 && frq_num <= 300.0) return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_VHF());
        if (frq_num > 300.0)                     return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_UHF());
        
        // FALLBACK: Use VHF model for any unhandled frequency
        // VHF model provides line-of-sight propagation which is safe for most cases
        return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_VHF());
    } else {
        // NON-NUMERIC FREQUENCY: Use string model for special frequency names
        // This handles cases like "GUARD", "EMERGENCY", "TAC", etc.
        return std::unique_ptr<FGCom_radiowaveModel>(new FGCom_radiowaveModel_String());
    }
}


/*
 * Extract numeric frequency from string and clean string from leading zeroes/spaces
 */
fgcom_radiowave_freqConvRes FGCom_radiowaveModel::splitFreqString(std::string frq) {
    setlocale(LC_NUMERIC,"C"); // decimal points always ".", not ","
    // construct default return value: use as-is
    struct fgcom_radiowave_freqConvRes res;
    res.frequency = frq;
    res.isNumeric = false;
    
    try {
        std::smatch sm;
        if (std::regex_match(frq, sm, std::regex("^[\\s0]*((?:RECORD_)?)([0-9.]+?)[\\s]*$") )) {
            // numeric frequency detected.
            // note: it is important for further detection that we keep the number of decimals unaltered!
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




/********* default implementations, may be overloaded *************/

bool FGCom_radiowaveModel::isCompatible(FGCom_radiowaveModel *otherModel) {
    return this->getType() == otherModel->getType();
}


double FGCom_radiowaveModel::getDistToHorizon(float h) {
    // Formula is the simple one from https://en.wikipedia.org/wiki/Horizon#Objects_above_the_horizon
    // it is not perfectly accurate, but good enough for our purpose.
    return EARTH_RADIUS_CONST * sqrt(h);
}

double FGCom_radiowaveModel::heightAboveHorizon(double dist, float hA, float hB) {
    double horizA          = FGCom_radiowaveModel::getDistToHorizon(hA);
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

double FGCom_radiowaveModel::getSlantDistance(double surfacedist, double hah) {
    // simple pythargoras, where we search the hypotehnuse :)
    return sqrt( pow(surfacedist, 2) + pow(hah/1000, 2) );
}

double FGCom_radiowaveModel::degreeAboveHorizon(double surfacedist, double hah) {
    // simple pythargoras, where we search the angle alpha
    double distM = surfacedist * 1000; // in m because hah is also in m
    double hypo  = sqrt( pow(distM, 2) + pow(hah, 2) ); 
    
    if (hah == 0)  return 0; // in case of horizontal alignment
    if (hypo == 0) return (hah >=0)? 90: -90; // in case the tgt point lies directly above/below
    double sinA = hah / hypo;
    double angle = (sinA != 0)? asin(sinA) * (180.0 / M_PI) : 0;
    return angle;
}

double FGCom_radiowaveModel::getDirection(double lat1, double lon1, double lat2, double lon2) {
    // Get the target point as viewed from coordinate origin, so atan2 can get the quadrant right
    // We apply haversine here, so we get the real length based on lat/lon position on
    // earth (wgs84 cells are only regularly shaped near the equator: size depends on location)
    double dLat = FGCom_radiowaveModel::getSurfaceDistance(lat1, lon1, lat2, lon1); // y distance in km
    double dLon = FGCom_radiowaveModel::getSurfaceDistance(lat1, lon1, lat1, lon2); // x distance in km
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

double FGCom_radiowaveModel::getSurfaceDistance(double lat1, double lon1, 
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


/**
 * FREQUENCY CHANNEL ALIGNMENT CALCULATION
 * 
 * This method calculates how well two radio frequencies match within a channel.
 * It implements a realistic frequency response curve that matches actual radio behavior.
 * 
 * MATHEMATICAL MODEL:
 * - Channel has a "core" region (perfect match) and "width" region (partial match)
 * - Inside core: 90-100% match with linear rolloff
 * - Outside core but within width: exponential decay from 90% to 0%
 * - Outside width: 0% match (no communication possible)
 * 
 * @param frq1_real First frequency in MHz
 * @param frq2_real Second frequency in MHz  
 * @param width_kHz Total channel width in kHz
 * @param core_kHz Channel core width in kHz (typically half of total width)
 * @return Match quality (0.0 = no match, 1.0 = perfect match)
 */
float FGCom_radiowaveModel::getChannelAlignment(float frq1_real, float frq2_real, float width_kHz, float core_kHz) {
    // PARAMETER VALIDATION:
    // Channel width and core must be positive values for valid calculation
    if (width_kHz < 0) throw "FGCom_radiowaveModel::getFrqMatch() calling error: width_kHz not defined!";
    if (core_kHz  < 0) throw "FGCom_radiowaveModel::getFrqMatch() calling error: core_kHz not defined!";
    
    // LOCALE SETTING:
    // Ensure decimal points are always "." not "," for consistent parsing
    setlocale(LC_NUMERIC,"C");
    float filter = 0.0; // Default: no match in case of errors
    
    // FREQUENCY DIFFERENCE CALCULATION:
    // Calculate absolute difference between frequencies in kHz
    // This determines how far apart the frequencies are
    float diff_kHz = std::fabs(frq1_real - frq2_real) * 1000; // Convert MHz to kHz
    
    // CHANNEL BOUNDARY CALCULATIONS:
    // Calculate effective channel boundaries for comparison
    float widthKhz_eff = (width_kHz) / 2;  // Half channel width (from center to edge)
    float corekHz_eff  = core_kHz  / 2;    // Half channel core (from center to core edge)

    // FREQUENCY RESPONSE CURVE CALCULATION:
    // This implements a realistic radio frequency response curve
    // that matches actual radio behavior with three distinct regions:
    
    if (diff_kHz <= corekHz_eff) {
        // REGION 1: INSIDE CHANNEL CORE (Perfect Match Zone)
        // Frequencies are very close - excellent communication quality
        // Linear rolloff from 100% to 90% match within core region
        filter = 1.0 - (diff_kHz / corekHz_eff) * 0.1;  // 90-100% match quality
    } else if (diff_kHz <= widthKhz_eff) {
        // REGION 2: OUTSIDE CORE BUT WITHIN CHANNEL (Partial Match Zone)
        // Frequencies are within channel but outside core - degraded quality
        // Exponential decay from 90% to 0% match as frequency difference increases
        float normalized_diff = (diff_kHz - corekHz_eff) / (widthKhz_eff - corekHz_eff);
        filter = 0.9 * std::exp(-3.0 * normalized_diff);  // Exponential decay curve
    } else {
        // REGION 3: OUTSIDE CHANNEL (No Match Zone)
        // Frequencies are too far apart - no communication possible
        filter = 0.0;
    }
    
    // BOUNDS CHECKING:
    // Ensure result is within valid range [0.0, 1.0]
    if (filter > 1.0) filter = 1.0;
    if (filter < 0.0) filter = 0.0;

    return filter;
}
