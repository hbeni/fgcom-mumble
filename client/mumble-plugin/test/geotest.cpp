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


// This is a test tool for the radio lib.
// It receives two positions and prints out useful information on it.
// you can get distance, radio horizon range, if they can see each other
// and other useful stuff.

#include <stdio.h>
#include <cstring>
#include <string>     // std::string, std::stof
#include <iostream> 
#include <cmath>
#include "lib/radio_model.h"

using namespace std; 


int main (int argc, char **argv)
{ 
    /*double lat1 = 51.5007; 
    double lon1 = 0.1246; 
    double lat2 = 40.6892; 
    double lon2 = 74.0445; */
    
    if (argc < 7 || argc > 8) {
        cout << "Test tool for FGCom geolib\n";
        cout << "The tool accepts two x/y/z coordinates and prints informations about\n";
        cout << "the geoid like distance, visible horizont distance and if the points\n";
        cout << "can see each other or are hidden by earth.\n";
        cout << "\nUsage: " << argv[0] << " lat1 lon1 alt1 lat2 lon2 alt2 [freq]\n";
        cout << "  alt is in meter above surface. lat/lon is decimal format (45.01234).\n";
        cout << "\nExample: can you see the Pulverturm in Lindau from Konstanz? (no)\n";
        cout << "   call: `" << argv[0] << " 47.665953 9.218242 1.75   47.545780 9.675327 15`\n";
        return 0;
    }
    
    double lat1 = stod(argv[1]); 
    double lon1 = stod(argv[2]); 
    float  h1   = stof(argv[3]); 
    double lat2 = stod(argv[4]); 
    double lon2 = stod(argv[5]);
    float  h2   = stof(argv[6]); 
    
    cout << "  posA:  lat(" << lat1 << ") lon(" << lon1 << ") alt(" << h1 << ")" <<endl;
    cout << "  posB:  lat(" << lat2 << ") lon(" << lon2 << ") alt(" << h2 << ")" <<endl;
    
    std::unique_ptr<FGCom_radiowaveModel> radio_model_base = FGCom_radiowaveModel::selectModel("TEST");
    
    double dist = radio_model_base->getSurfaceDistance(lat1, lon1, lat2, lon2);
    printf("  posA <surface> posB = %.2fkm \n", dist);
    
    double horizA = radio_model_base->getDistToHorizon(h1);
    printf("  horizont A = %.2fkm \n", horizA);
    double horizB = radio_model_base->getDistToHorizon(h2);
    printf("  horizont B = %.2fkm \n", horizB);
    
    double heightAB = radio_model_base->heightAboveHorizon(dist, h1, h2);
    string visAB = (heightAB >=0)? "visible" : "hidden";
    printf("  heightAboveHorizon A->B = %.2fm (%s)\n", heightAB, visAB.c_str());
    
    double heightBA = radio_model_base->heightAboveHorizon(dist, h2, h1);
    string visBA = (heightBA >=0)? "visible" : "hidden";
    printf("  heightAboveHorizon B->A = %.2fm (%s)\n", heightBA, visBA.c_str());
    
    printf("  posA <slant> posB = %.2fkm \n", radio_model_base->getSlantDistance(dist, heightAB-h1));
    printf("  posB <slant> posA = %.2fkm \n", radio_model_base->getSlantDistance(dist, heightBA-h2));
    
    printf("  posA <direction> posB = %.2f° \n", radio_model_base->getDirection(lat1, lon1, lat2, lon2));
    printf("  posB <direction> posA = %.2f° \n", radio_model_base->getDirection(lat2, lon2, lat1, lon1));
    
    printf("  angle posA->posB = %.2f° \n", radio_model_base->degreeAboveHorizon(dist, heightAB-h1));
    printf("  angle posB->posA = %.2f° \n", radio_model_base->degreeAboveHorizon(dist, heightBA-h2));

    
    if (argc >= 8) {
        // Radio frequency model range test
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel(std::string(argv[7]));
        printf("  conducting radio range test for model '%s':\n", radio_model->getType().c_str());
        for (int pwr=0; pwr<=30; true) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, pwr);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1, pwr);
            printf("    signal posA->posB @%iw = %.0f%% \n", pwr, sigStrengthAB.quality*100);
            // its the same (it should at least) printf("  VHF signal posB->posA @%iw = %.0f% \n", pwr, sigStrengthBA.quality*100);
            if      (pwr <  5) { pwr++; }
            else if (pwr < 20) { pwr += 5; }
            else               { pwr += 10; }
        }
    }
    
    return 0;
} 
