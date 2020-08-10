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

/**
 * A UHF based radio model for the FGCom-mumble plugin
 *
 * The model implements basic line-of-sight characteristics.
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
    
    
    // Frequency match is done with a band method, ie. a match is there if the bands overlap
    float getFrqMatch(std::string frq1_real, std::string frq2_real) {
        std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
        float filter = 0.0; // no match in case of errors
        
    //     std::cout << "FGCom_radiowaveModel_UHF::getFrqMatch('" << frq1_real.c_str() << "', '" <<frq2_real.c_str() << "')" << std::endl;
    //     std::cout << "FGCom_radiowaveModel_UHF::getFrqMatch() default string match=" << filter << std::endl;
        
        // see if we can it make more precise.
        // that is the case if we have numerical values (after ignoring prefixes).
        try {
            fgcom_radiowave_freqConvRes frq1_p = FGCom_radiowaveModel::splitFreqString(frq1_real);
            fgcom_radiowave_freqConvRes frq2_p = FGCom_radiowaveModel::splitFreqString(frq2_real);
            if (frq1_p.isNumeric && frq2_p.isNumeric) {
                // numeric frequencies
                float frq1_f = std::stof(frq1_p.frequency);
                float frq2_f = std::stof(frq2_p.frequency);
                
                // calculate absolute "off" tuning / tunable window
                // 1.25-2.5x => gives >1.0 at 0.1 (100kHz) difference, declining to 0.0. at 0.5 (500 kHz),
                //              yielding a tunable band of 1MHz around the channel center,
                //              where the range +-100kHz is perfect signal and 50% signal is at about +-300kHz off.
                // TODO: Note, i completely made up those numbers. I have no idea of tuning radios. I just wanted to make sure, that 25kHz radios will receive 8.33 channels with overlapping stepsize while keeping the 8.33 channels distinct and with a gap between windows...
                float diff = std::fabs(frq1_f - frq2_f);
    //             std::cout << "DBG CALC:" << std::endl;
    //             std::cout << "   frq1_p=" << frq1_p.frequency << std::endl;
    //             std::cout << "   frq1_f=" << frq1_f << std::endl;
    //             std::cout << "   frq2_p=" << frq2_p.frequency << std::endl;
    //             std::cout << "   frq2_f=" << frq1_f << std::endl;
                filter     = 1.25 - 2.5 * diff;
    //             std::cout << "   diff=" << diff << "; filter=" << filter << std::endl;
                if (filter > 1.0) filter = 1.0;
                if (filter < 0.0) filter = 0.0;
                
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
