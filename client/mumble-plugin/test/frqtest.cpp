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


// This is a simple test tool for frequency matching.
#include <stdio.h>
#include <cstring>
#include <string>     // std::string, std::stof
#include <iostream> 
#include <cmath>
#include "lib/radio_model.h"

using namespace std; 


int main (int argc, char **argv) {

    if (argc < 3) {
        cout << "Test tool for FGCom radio lib\n";
        cout << "The tool accepts two frequencies and prints informations about them.\n";
        cout << "\nUsage: " << argv[0] << " frq1 frq2 [ch_width]\n";
        cout << "\nExample: `" << argv[0] << " 118.030  118.035  8.33`\n";
        return 0;
    }
    
    std::string frq1    = argv[1];
    std::string frq2    = argv[2];
    
    std::unique_ptr<FGCom_radiowaveModel> frq1_model = FGCom_radiowaveModel::selectModel(frq1);
    std::unique_ptr<FGCom_radiowaveModel> frq2_model = FGCom_radiowaveModel::selectModel(frq2);
    
    fgcom_radiowave_freqConvRes frq1_p = FGCom_radiowaveModel::splitFreqString(frq1);
    std::string frq1_real = frq1_model->conv_chan2freq(frq1_p.frequency);
    printf("model[1]   = '%s' \n", frq1_model->getType().c_str());
    printf("prefix[1]  = '%s' \n", frq1_p.prefix.c_str());
    printf("pFrq[1]    = '%s' \n", frq1_p.frequency.c_str());
    printf("realFrq[1] = '%s' \n", frq1_real.c_str());
    printf("chan[1]    = '%s' \n", frq1_model->conv_freq2chan(frq1).c_str());
    
    fgcom_radiowave_freqConvRes frq2_p = FGCom_radiowaveModel::splitFreqString(frq2);
    std::string frq2_real = frq2_model->conv_chan2freq(frq2_p.frequency);
    printf("model[2]   = '%s' \n", frq2_model->getType().c_str());
    printf("prefix[2]  = '%s' \n", frq2_p.prefix.c_str());
    printf("pFrq[2]    = '%s' \n", frq2_p.frequency.c_str());
    printf("realFrq[2] = '%s' \n", frq2_real.c_str());
    printf("chan[2]    = '%s' \n", frq1_model->conv_freq2chan(frq2).c_str());
    
    if (frq1_model->isCompatible(frq2_model.get())) {
        fgcom_radio r1;
        r1.frequency = frq1_real;
        if (argc > 3) {
            r1.channelWidth = std::stof(argv[3]);
            printf("channelWidth = '%s' \n", argv[3]);
        }
        fgcom_radio r2;
        r2.frequency = frq2_real;
        printf("matchFilter = (%s==%s) %.5f \n", frq1_real.c_str(), frq2_real.c_str(), frq1_model->getFrqMatch(r1, r2));
    } else {
        printf("matchFilter = (%s==%s) models not compatible\n", frq1_real.c_str(), frq2_real.c_str());
    }
    
}
