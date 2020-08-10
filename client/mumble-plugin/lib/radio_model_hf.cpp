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
 * A HF based radio model for the FGCom-mumble plugin
 *
 * The model implements basic high frequency propagation.
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
        double radiodist = this->getDistToHorizon(alt1) + this->getDistToHorizon(alt2);
        
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


    // Frequency match is done with a band method, ie. a match is there if the bands overlap
    float getFrqMatch(std::string frq1_real, std::string frq2_real) {
        std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
        float filter = 0.0; // no match in case of errors
        
    //     std::cout << "FGCom_radiowaveModel_HF::getFrqMatch('" << frq1_real.c_str() << "', '" <<frq2_real.c_str() << "')" << std::endl;
    //     std::cout << "FGCom_radiowaveModel_HF::getFrqMatch() default string match=" << filter << std::endl;
        
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
                // 2-4000x   => gives >1.0 at 0.00025 (1/4kHz) difference, declining to 0.0. at 0.0005 (1/2 kHz),
                //              yielding a tunable band of 1kHz around the channel center,
                //              where the range +-1/4kHz is perfect signal and 50% signal is at about 1/8kHz off.
                // TODO: Note, i completely made up those numbers. I have no idea of tuning HF radios.
                float diff = std::fabs(frq1_f - frq2_f);
    //             std::cout << "DBG CALC:" << std::endl;
    //             std::cout << "   frq1_p=" << frq1_p.frequency << std::endl;
    //             std::cout << "   frq1_f=" << frq1_f << std::endl;
    //             std::cout << "   frq2_p=" << frq2_p.frequency << std::endl;
    //             std::cout << "   frq2_f=" << frq1_f << std::endl;
                filter     = 2 - 4000 * diff;
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
    
};
