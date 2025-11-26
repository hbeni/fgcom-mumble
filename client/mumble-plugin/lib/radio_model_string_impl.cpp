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

#include "radio_model_string.h"
#include "radio_model_vhf.h"
#include "audio/audio.h"

// Constructor and destructor are defined in header

// Get type
std::string FGCom_radiowaveModel_String::getType() {
    return "STRING";
}

// Get signal - always perfect worldwide
fgcom_radiowave_signal FGCom_radiowaveModel_String::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    (void)lat1; (void)lon1; (void)alt1; (void)lat2; (void)lon2; (void)alt2; (void)power; // Suppress unused warnings
    float dist = getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // Landline always has perfect signal quality regardless of power or distance
    struct fgcom_radiowave_signal signal;
    signal.quality       = 1.0f;
    signal.direction     = getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = degreeAboveHorizon(dist, alt2-alt1);
    return signal;
}

// Convert channel to frequency
std::string FGCom_radiowaveModel_String::conv_chan2freq(std::string frq) {
    return frq; // Simplified
}

// Convert frequency to channel
std::string FGCom_radiowaveModel_String::conv_freq2chan(std::string frq) {
    return frq; // Simplified
}

// Get frequency match
float FGCom_radiowaveModel_String::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    (void)r1; (void)r2; // Suppress unused parameter warnings
    // String model always matches
    return 1.0f;
}

// Process audio samples
void FGCom_radiowaveModel_String::processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
    // Use VHF model for audio processing
    auto vhf_radio = std::make_unique<FGCom_radiowaveModel_VHF>();
    vhf_radio->processAudioSamples(lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
}
