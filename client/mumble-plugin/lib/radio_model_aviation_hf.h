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

#ifndef RADIO_MODEL_AVIATION_HF_H
#define RADIO_MODEL_AVIATION_HF_H

#include "radio_model.h"
#include "audio.h"
#include "solar_data.h"

/**
 * Aviation HF radio model for the FGCom-mumble plugin
 */
class FGCom_radiowaveModel_AviationHF : public FGCom_radiowaveModel {
private:
    float frequency_mhz;
    std::string frequency_name;
    
public:
    FGCom_radiowaveModel_AviationHF(float freq, const std::string& name);
    FGCom_radiowaveModel_AviationHF();
    
    std::string getType();
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power);
    std::string conv_chan2freq(std::string frq);
    std::string conv_freq2chan(std::string frq);
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2);
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz);
};

#endif // RADIO_MODEL_AVIATION_HF_H
