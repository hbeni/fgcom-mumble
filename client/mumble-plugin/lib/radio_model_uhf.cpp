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
 * A UHF based radio model for the FGCom-mumble plugin.
 *
 * The model implements basic line-of-sight characteristics (between 300 and 3000 MHz).
 */
class FGCom_radiowaveModel_UHF : public FGCom_radiowaveModel_VHF {
protected:
    
    // like VHF-model, however shorter range per watt
    virtual float calcPowerDistance(float power, double slantDist) {
        float wr = power * 50 / 2; // gives maximum range in km for the supplied power
        float sq = (-1/wr*pow(slantDist,2)+100)/100;  // gives @10w: 50km=0.95 100km=0.8 150km=0.55 200km=0.2
        return sq;
    }
    
    
public:
        
    std::string getType() {  return "UHF";  }
    
    bool isCompatible(FGCom_radiowaveModel *otherModel) {
        return otherModel->getType() != "STRING";
    }
    
    
    // No channel names known so far. Are there any we must convert to real frequencies?
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
        // TODO: Note, i completely made up those numbers. I have no idea of tuning UHF radios.
        float width_kHz = r1.channelWidth;
        if (width_kHz <= 0) width_kHz = 500.00;
        float channel_core  = 250.0;
        
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
    
    // everything else is borrowed from VHF model...
    
};
