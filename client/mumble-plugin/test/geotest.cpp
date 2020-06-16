#include <stdio.h>
#include <cstring>
#include <string>     // std::string, std::stof
#include <iostream> 
#include <cmath>
#include "lib/radio_model.cpp"

using namespace std; 


int main (int argc, char **argv)
{ 
    /*double lat1 = 51.5007; 
    double lon1 = 0.1246; 
    double lat2 = 40.6892; 
    double lon2 = 74.0445; */
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

    
    return 0; 
} 
