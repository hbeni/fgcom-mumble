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

#ifndef RADIO_MODEL_STRING_H
#define RADIO_MODEL_STRING_H

#include <iostream> 
#include <cmath>
#include <regex>
#include "radio_model.h"
#include "radio_model_vhf.h"
#include "audio.h"

/**
 * A string based radio model for the FGCom-mumble plugin
 *
 * The model implements basic string matching channels with worldwide range.
 */
class FGCom_radiowaveModel_String : public FGCom_radiowaveModel {
public:
    std::string getType();

    // radio signal is always perfect, worldwide.        
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power);

    // No conversions needed at this time.
    std::string conv_chan2freq(std::string frq);

    std::string conv_freq2chan(std::string frq);

    // frequencies match if the string is case-sensitively the same
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2);

    /*
     * Process audio samples
     */
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);
};

#endif // RADIO_MODEL_STRING_H
