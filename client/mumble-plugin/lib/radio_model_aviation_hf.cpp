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

#include "radio_model_aviation_hf.h"
#include "audio/audio.h"
#include "propagation/weather/solar_data.h"

// Constructor with parameters
FGCom_radiowaveModel_AviationHF::FGCom_radiowaveModel_AviationHF(float freq, const std::string& name) 
    : frequency_mhz(freq), frequency_name(name) {
}

// Default constructor
FGCom_radiowaveModel_AviationHF::FGCom_radiowaveModel_AviationHF() : frequency_mhz(0.0f), frequency_name("") {
}

std::string FGCom_radiowaveModel_AviationHF::getType() { 
    return "AVIATION_HF"; 
}

fgcom_radiowave_signal FGCom_radiowaveModel_AviationHF::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0f;
    signal.direction = 0.0f;
    signal.verticalAngle = 0.0f;
    
    // Calculate distance
    double dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // Aviation HF propagation
    if (dist > 0.0) {
        // Aviation HF can work beyond line of sight
        signal.quality = std::min(1.0f, power / 100.0f);
        signal.direction = getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    }
    
    return signal;
}

std::string FGCom_radiowaveModel_AviationHF::conv_chan2freq(std::string frq) { 
    return frq; 
}

std::string FGCom_radiowaveModel_AviationHF::conv_freq2chan(std::string frq) { 
    return frq; 
}

float FGCom_radiowaveModel_AviationHF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) { 
    (void)r1; (void)r2; // Suppress unused parameter warnings
    return 1.0f; 
}

void FGCom_radiowaveModel_AviationHF::processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    (void)signalQuality; // Suppress unused parameter warning
    fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
    fgcom_audio_filter(300, 3000, outputPCM, sampleCount, channelCount, sampleRateHz);
    fgcom_audio_applyVolume(lclRadio.volume, outputPCM, sampleCount, channelCount);
}
