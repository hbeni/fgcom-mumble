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
#include "audio.h"

/**
 * A HF based radio model for the FGCom-mumble plugin
 *
 * The model implements basic high frequency propagation (between 3 and 30 MHz).
 * Currently this is a simple model that justs takes distance and wattage into account.
 * Transmissions behind the radio horizon travel via ground waves, we simulate this by applying some loss to the signal.
 * TODO: advanced stuff like influences of day/night, terminator, sun spots, etc are not modelled yet.
 */
class FGCom_radiowaveModel_HF : public FGCom_radiowaveModel {
protected:
    /*
    * Calculate the signal quality loss by power/distance model
    * 
    * TODO: use realistic numbers/formulas
    * 
    * @param power in Watts
    * @param dist  slant distance in km
    * @return float with the signal quality for given power and distance
    */
    virtual float calcPowerDistance(float power, double slantDist) {
        float wr = power * 1000; // gives maximum range in km for the supplied power
        float sq = (-1/wr*pow(slantDist,2)+100)/100;
        return sq;
    }
    
    
public:
        
    std::string getType() {  return "HF";  }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() != "STRING";
    }
    
    
    // Signal depends on HF characteristics.
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
        struct fgcom_radiowave_signal signal;
        signal.quality = 0.85; // Base signal quality; but we will degrade that using the model below
    
        // get distance to radio horizon (that is the both ranges combined)
        // double radiodist = this->getDistToHorizon(alt1) + this->getDistToHorizon(alt2);
        // note: not needed currently, as we use heightAboveHorizon() for the check below.
        
        // get surface distance
        double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
        
        // apply power/distance model
        signal.quality = this->calcPowerDistance(power, dist);
        if (signal.quality <= 0.0) signal.quality = 0.0; // in case signal strength got negative, that means we are out of range (too less tx-power)
        

        // Check if the target is behind the radio horizon
        double heightAboveHorizon = this->heightAboveHorizon(dist, alt1, alt2);
        if (heightAboveHorizon < 0) {
            // behind horizon: only skywaves reach the destination, so we degrade the signal a bit.
            signal.quality *= 0.70;
        }
        
        
        
        // prepare return struct
        signal.direction     = this->getDirection(lat1, lon1, lat2, lon2);
        signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
        return signal;
    }
    
    
    // no known channel names yet. Are there any where we need to convert to real frq?
    std::string conv_chan2freq(std::string frq) {
        return frq;
    }

    std::string conv_freq2chan(std::string frq) {
        return frq;
    }

    // Frequency match is done with a band method, ie. a match is there if the bands overlap
    float getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
        if (r1.ptt)       return 0.0; // Half-duplex!
        if (!r1.operable) return 0.0; // stop if radio is inoperable

        // channel definition
        // TODO: Note, i completely made up those numbers. I have no idea of tuning HF radios.
        // TODO: I have read somewhere about 3kHz width: https://onlinelibrary.wiley.com/doi/abs/10.1002/0471208051.fre015
        float width_kHz = r1.channelWidth;
        if (width_kHz <= 0) width_kHz = 3.00;
        float channel_core = 1.00;  // 1kHz = 0.5kHz to each side
        
        // see if we can it make more precise.
        // that is the case if we have numerical values (after ignoring prefixes).
        float filter = 0.0;
        try {
            fgcom_radiowave_freqConvRes frq1_p = FGCom_radiowaveModel::splitFreqString(r1.frequency);
            fgcom_radiowave_freqConvRes frq2_p = FGCom_radiowaveModel::splitFreqString(r2.frequency);
            if (frq1_p.isNumeric && frq2_p.isNumeric) {
                // numeric frequencies
                float frq1_f = std::stof(frq1_p.frequency);
                float frq2_f = std::stof(frq2_p.frequency);
                filter = this->getChannelAlignment(frq1_f, frq2_f, width_kHz, channel_core);
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

    
    /*
     * Process audio samples
     */
    void processAudioSamples(fgcom_radio lclRadio, float signalQuality, float *outputPCM, uint32_t sampleCount, uint16_t channelCount, uint32_t sampleRateHz) {
        // Audio processing is like VHF characteristics for now
        std::unique_ptr<FGCom_radiowaveModel_VHF> vhf_radio = std::make_unique<FGCom_radiowaveModel_VHF>();
        vhf_radio->processAudioSamples(lclRadio, signalQuality, outputPCM, sampleCount, channelCount, sampleRateHz);
    }
};
