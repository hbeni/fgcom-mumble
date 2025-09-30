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
        
    std::string getType() {  return "STRING";  }

    // radio signal is always perfect, worldwide.        
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        float dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // Use power parameter for signal strength calculation
        float power_factor = power / 100.0f; // Normalize power to 0-1 range
        if (power_factor > 1.0f) power_factor = 1.0f;
        if (power_factor < 0.1f) power_factor = 0.1f;
        
        struct fgcom_radiowave_signal signal;
        signal.quality       = 1.0 * power_factor;
        signal.direction     = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        return signal;
    }

    
    // No conversions needed at this time.
    std::string conv_chan2freq(std::string frq) {
        return frq;
    }

    std::string conv_freq2chan(std::string frq) {
        return frq;
    }

    // frequencies match if the string is case-sensitively the same
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        if (!r1.operable) return 0.0; // stop if radio is inoperable

        bool isLandline = r1.frequency.substr(0, 5) == "PHONE";
        bool isIntercom = r1.frequency.substr(0, 3) == "IC:";

        // If landline or intercom: full duplex
        if (isLandline || isIntercom) return (r1.frequency == r2.frequency)? 1.0 : 0.0 ;

        // if not: treat as half-duplex:
        return (!r1.ptt && r1.frequency == r2.frequency)? 1.0 : 0.0 ;
    }


    /*
     * Process audio samples
     */
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        /*
         * Check for landline, otherwise use VHF characteristics (for example to simulate private handheld PMR radio channel names)
         */
        if (lclRadio.frequency.substr(0, 5) == "PHONE") {
            // Telephone characteristics
            fgcom_audio_makeMono(outputPCM, sampleCount, channelCount);
            fgcom_audio_filter(300, 4000, outputPCM, sampleCount, channelCount, sampleRateHz);
            fgcom_audio_applyVolume(lclRadio.volume, outputPCM, sampleCount, channelCount);

        } else {
            // VHF characteristics
            std::unique_ptr<FGCom_radiowaveModel_VHF> vhf_radio = std::make_unique<FGCom_radiowaveModel_VHF>();
            vhf_radio->processAudioSamples(lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
        }
    }
};
