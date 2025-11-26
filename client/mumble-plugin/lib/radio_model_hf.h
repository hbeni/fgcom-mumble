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

#ifndef RADIO_MODEL_HF_H
#define RADIO_MODEL_HF_H

#include <iostream> 
#include <cmath>
#include <regex>
#include "radio_model.h"
#include "audio/audio.h"
#include "propagation/weather/solar_data.h"
#include "power_management.h"

/**
 * A HF based radio model for the FGCom-mumble plugin
 *
 * The model implements high frequency propagation (between 3 and 30 MHz) with solar condition effects.
 * Includes day/night variations, solar flux effects, and geomagnetic activity impacts.
 * Transmissions behind the radio horizon travel via sky waves with solar-dependent characteristics.
 */
class FGCom_radiowaveModel_HF : public FGCom_radiowaveModel {
private:
    static FGCom_SolarDataProvider& getSolarProvider() {
        static FGCom_SolarDataProvider provider;
        return provider;
    }
    
protected:
    /*
    * Calculate the signal quality loss by power/distance model
    * 
    * Enhanced with power management integration
    * 
    * @param power in Watts
    * @param dist  slant distance in km
    * @return float with the signal quality for given power and distance
    */
    virtual float calcPowerDistance(float power, double slantDist);
    
    // Calculate skywave propagation effects
    float calcSkywavePropagation(double distance, const fgcom_solar_conditions& solar, double solar_zenith);
    
public:
    std::string getType();
    
    bool isCompatible(FGCom_radiowaveModel *otherModel);

    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power);

    std::string conv_chan2freq(std::string frq);

    std::string conv_freq2chan(std::string frq);

    float getFrqMatch(fgcom_radio r1, fgcom_radio r2);

    /*
     * Process audio samples
     */
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);
};

#endif // RADIO_MODEL_HF_H
