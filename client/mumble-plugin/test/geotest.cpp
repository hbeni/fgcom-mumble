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
    
    if (argc != 7) {
        cout << "Test tool for FGCom geolib\n";
        cout << "The tool accepts two x/y/z coordinates and prints informations about\n";
        cout << "the geoid like distance, visible horizont distance and if the points\n";
        cout << "can see each other or are hidden by earth.\n";
        cout << "\nUsage: " << argv[0] << " lat1 lon1 alt1 lat2 lon2 alt2\n";
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
    
    double dist = fgcom_radiowave_getSurfaceDistance(lat1, lon1, lat2, lon2);
    printf("  posA <surface> posB = %.2fkm \n", dist);
    
    double horizA = fgcom_radiowave_getDistToHorizon(h1);
    printf("  horizont A = %.2fkm \n", horizA);
    double horizB = fgcom_radiowave_getDistToHorizon(h2);
    printf("  horizont B = %.2fkm \n", horizB);
    
    double heightAB = fgcom_radiowave_heightAboveHorizon(dist, h1, h2);
    string visAB = (heightAB >=0)? "visible" : "hidden";
    printf("  heightAboveHorizon A->B = %.2fm (%s)\n", heightAB, visAB.c_str());
    
    double heightBA = fgcom_radiowave_heightAboveHorizon(dist, h2, h1);
    string visBA = (heightBA >=0)? "visible" : "hidden";
    printf("  heightAboveHorizon B->A = %.2fm (%s)\n", heightBA, visBA.c_str());
    
    printf("  posA <slant> posB = %.2fkm \n", fgcom_radiowave_getSlantDistance(dist, heightAB-h1));
    printf("  posB <slant> posA = %.2fkm \n", fgcom_radiowave_getSlantDistance(dist, heightBA-h2));
    
    printf("  angle posA->posB = %.2f° \n", fgcom_radiowave_degreeAboveHorizon(dist, heightAB-h1));
    printf("  angle posB->posA = %.2f° \n", fgcom_radiowave_degreeAboveHorizon(dist, heightBA-h2));

    for (int pwr=0; pwr<=30; true) {
        float sigStrengthAB = fgcom_radiowave_getSignalStrength(lat1, lon1, h1, lat2, lon2, h2, pwr);
        float sigStrengthBA = fgcom_radiowave_getSignalStrength(lat2, lon2, h2, lat1, lon1, h1, pwr);
        printf("  VHF signal posA->posB @%iw = %.0f% \n", pwr, sigStrengthAB*100);
        // its the same (it should at least) printf("  VHF signal posB->posA @%iw = %.0f% \n", pwr, sigStrengthBA*100);
        if      (pwr <  5) { pwr++; }
        else if (pwr < 20) { pwr += 5; }
        else               { pwr += 10; }
    }
    
    return 0; 
} 