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
#include <iostream> 
#include <cmath>
#include <regex>

// A radio model for the FGCom-mumble plugin
//
// This just defines some functions that are used from the plugin.
//

#ifndef FGCOM_RADIOMODEL_H
#define FGCOM_RADIOMODEL_H


#define EARTH_RADIUS_CONST 3.57  // earth radius factor constant for m/km
#define EARTH_RADIUS_AVG   6371  // earth radius constant in km


// This represents the state of a radio
struct fgcom_radio {
	std::string  frequency; // tuned frequency (real carrier frequency)
	std::string  dialedFRQ; // dialed frequency (aka "channel"; what was supplied from the COMn_FRQ= field)
	bool  power_btn;     // true if switched on
	float volts;         // how much electric power it has (>0 = on)
	bool  serviceable;   // false if broken
	bool  ptt;           // true if PTT is pushed
	float volume;        // volume, 0.0->1.0
	float pwr;           // tx power in watts
	float squelch;       // squelch setting (cutoff signal below this quality)
	bool  rdfEnabled;    // if radio can receive RDF information
	float channelWidth;  // channel width in kHz
	
	fgcom_radio()  {
        frequency   = "";
        dialedFRQ   = "";
        power_btn   = true;
        volts       = 12;
        serviceable = true;
        ptt         = false;
        volume      = 1.0;
        pwr         = 10;
        squelch     = 0.1;
        rdfEnabled  = false;
        channelWidth = -1;   // let the selected radio model decide on defaults
    };
};


// Received signal information for a radio instance
// direction and verticalAngle are only valid if qualtiy > 0.0
struct fgcom_radiowave_signal {
    float quality;        // 0.0=no signal, 1.0=perfect signal
    float direction;      // 0.0=north, 90=east, 180=south, 270=west
    float verticalAngle;  // 0.0=straight, 90=above, -90=below
    
    fgcom_radiowave_signal()  {
        quality       = -1;
        direction     = -1;
        verticalAngle = -1;
    };
};


// Frequency conversion result
struct fgcom_radiowave_freqConvRes {
    std::string prefix;    // extracted prefix
    std::string frequency; // extracted and converted frequency
    bool isNumeric;        // tells if frequency is a valid numeric
};



/*
 * FGCom Radiowave model abstract base class definition.
 * 
 * The radio model defines an abstract base class implementing this definition,
 * and concrete models will inherit from that, overwriting/implementing as needed.
 */
class FGCom_radiowaveModel {
public:
         
    /*********************************************/
    /* Model dependendant methods, need to be    */
    /* implemented from each inheriting class    */
    /*********************************************/
    
    /*
    * Report this models frequency type. Different models should not be compared to each other.
    * 
    * @return string with the type name
    */
    virtual std::string getType() = 0;  // pure-virtual: cannot be provided by the base class
    
    
    /*
    * Get signal strength
    * 
    * @param lat1  Latitude of object A
    * @param lon1  Longitude of object A
    * @param alt1  height of observer A, in meters above surface
    * @param lat2  Latitude of object B
    * @param lon2  Longitude of object B
    * @param alt2  height of observer A, in meters above surface
    * @param power Signal sending power in watts
    * @return fgcom_radiowave_signal
    */
    virtual fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) = 0;

    
    /*
    * Convert /for ecample 25kHz/8.33kHz) channel names to a physical carrier wave frequency
    * 
    * @param frq the frequency string to normalize
    * @return fgcom_radiowave_freqConvRes; frequency key is always set, prefix only if parsed correctly.
    */
    virtual std::string conv_chan2freq(std::string frq) = 0;

    
    /*
    * See how good frequencies of two radios align.
    *
    * This method may call getChannelAlignment() for convinience.
    *
    * @param  r1 first radio
    * @param  r2 second radio
    * @return float alignment factor: 0.0=outside band, 1.0=in core region
    */
    virtual float getFrqMatch(fgcom_radio r1, fgcom_radio r2) = 0;


    /********************************************************************/
    /*  Abstract methods; they are usually not needed to be overloaded, */
    /*  the base class defines defaults and concrete models are         */
    /*  supposed to use those.                                          */
    /********************************************************************/
    
    
    /*
    * See how good frequencies align, based on a channel definition.
    *
    * We assume that the frequencies are discrete frequencies, so no off-band tuning is possible.
    * (ie. one of the frequencies is always assumed to aligned with the channels center carrier frequency;
    *  This may be easily used to check if a channel is tuned to the carrier channel spacing correctly.)
    *
    * A channel has a defined bandwidth. The core region defines the range where a "perfect" fit is assumed.
    * The difference of channel width and core region define the steepness of the tuning courve outside the core region.
    *
    * This method is intended to be use by concrete getFrqMatch() implementations of the models. They may call
    * the parameterized abstract implementation given here.
    * The paameters width_kHz and core_kHz must be greater zero, otherwise an error is thrown.
    *
    * @param  frq1_real   first frequency (real wave freq in mHz)
    * @param  frq2_real   second frequency (real wave freq in mHz)
    * @param  width_kHz   channel width in kHz
    * @param  core_kHz    core region width in kHz
    * @return float alignment factor: 0.0=outside band, 1.0=in core region
    */
    virtual float getChannelAlignment(float frq1_real, float frq2_real, float width_kHz, float core_kHz);
    
    
    /*
    * See if models are compatible and frequencies can be compared by getFrqMatch().
    * 
    * @param otherModel
    * @return boolean
    */
    virtual bool isCompatible(FGCom_radiowaveModel *otherModel);
    
    
    /*
    * Calculates the distance to horizon for an given observer at height h.
    *
    * @param h height in meters above surface
    * @returns the distance to horizon in km
    */
    virtual double getDistToHorizon(float h);


    /*
    * See if two observers can see each other.
    * 
    * @param dist Distance between the two observers in km
    * @param hA   height of observer A, in meters above surface
    * @param hB   height of observer B, in meters above surface
    * @return height of observer B above A's horizon in meters (if this is negative, its hidden).
    */
    virtual double heightAboveHorizon(double dist, float hA, float hB);


    /*
    * Get slant distance (length of line of sight)
    * 
    * @param surfacedist surface distance between the two objects in km
    * @param hah  visible height of observed object above horizon in m (@see heightAboveHorizon()), must be corrected for own height!
    * @return double slant distance in km
    */
    virtual double getSlantDistance(double surfacedist, double hah);


    /*
    * Get vertical angle of visible height above horizon.
    * 
    * @param surfacedist surface distance between the two objects in km
    * @param hah  visible height of observed object above horizon in m (@see heightAboveHorizon()), must be corrected for own height!
    * @return float Degrees of the visible height
    */
    virtual double degreeAboveHorizon(double surfacedist, double hah);

    /*
    * Get angle of source
    * 
    * @param lat1  Latitude of observer object
    * @param lon1  Longitude of observer object
    * @param lat2  Latitude of target object
    * @param lon2  Longitude of target object
    * @return float Degrees of direction
    */
    virtual double getDirection(double lat1, double lon1, double lat2, double lon2);


    /*
    * Get distance (great circle) for two objects based on lat/lon
    * 
    * @param lat1  Latitude of object A
    * @param lon1  Longitude of object A
    * @param lat2  Latitude of object B
    * @param lon2  Longitude of object B
    * @return great circle distance in km (as the crow flies)
    */
    virtual double getSurfaceDistance(double lat1, double lon1, double lat2, double lon2);
    
    
    
    
    
    /******************************************************/
    /* Utility methods owned by the base model class      */
    /******************************************************/
    
    
    /*
    * Factory: Selects the correct radio model based on the frequency given
    * 
    * This is implemented in the radio_model.cpp file, when all available radio models are known.
    * 
    * @param  freq the frequency string
    * @return FGCom_radiowaveModel unique_ptr smart pointer to instance that handles the frequency stuff
    */
    static std::unique_ptr<FGCom_radiowaveModel> selectModel(std::string freq);
    
    
    /*
    * Extract numeric frequency from string and clean string from leading/trailing zeroes/spaces.
    * 
    * Note: "frequency" may be an arbitary string, so we are just allowed to treat numerical-only
    *       values as numerical frequency.
    *       The exception are certain special frequencies, like "RECORD_<tgtFrq>", where we must split
    *       into prefix and frequency.
    * 
    * Thus, the return may be:
    *   r.isNumerical == true:   numerical parsing was OK, optionally there may be a prefix set and r.frequency contains a numerical.
    *   r.isNumerical == false:  it was a string or no special frequency; r.frequency contains an arbitary string.
    * 
    * The returned frequency is just the raw split result and, aside of sanitizing/clearing, unaltered.
    * The string is cleared of:
    * - leading zeroes and spaces
    * - trailing spaces
    * 
    * @param frq the frequency string to inspect
    * @return fgcom_radiowave_freqConvRes; frequency key is always set, prefix only if parsed a special frequency.
    */
    static fgcom_radiowave_freqConvRes splitFreqString(std::string frq);
    
};




#endif
