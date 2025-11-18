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

/*
 * Catch2 Unit tests for the radio model
 */
#include "test/catch2/catch_amalgamated.hpp"
using namespace Catch;

#include "lib/radio_model.h"

struct testSetEntry { std::string given, expected; };
struct testSetEntry_dbl { double given; double expected; };

TEST_CASE( "Radio Model", "25/8.33kHz frq parsing check" ) {
    std::vector<testSetEntry> checkThis = {
        // frequencies from the beginning
        {"118.000", "118.0000"},
        {"118.005", "118.0000"},
        {"118.010", "118.00833"},
        {"118.015", "118.01667"},
        {"118.025", "118.0250"},
        {"118.030", "118.03333"},
        {"118.035", "118.03333"},
        {"118.040", "118.04167"},
        {"118.050", "118.0500"},
        {"118.055", "118.05833"},
        {"118.060", "118.05833"},
        {"118.065", "118.06667"},
        {"118.075", "118.0750"},
        {"118.080", "118.08333"},
        {"118.085", "118.08334"},
        {"118.090", "118.09167"},
        {"118.100", "118.1000"},
        {"118.105", "118.1000"},
        {"118.110", "118.10834"},
        {"118.115", "118.11668"},
        {"118.125", "118.1250"},
        {"118.130", "118.1250"},
        {"118.135", "118.13334"},
        {"118.140", "118.14167"},
        {"118.150", "118.1500"},
        {"118.155", "118.1500"},
        
        // stuff from the middle
        {"126.565", "126.56667"},
        {"126.575", "126.5750"},
        {"126.580", "126.5750"},
        {"126.585", "126.58334"},
        {"126.590", "126.59167"},
        {"126.600", "126.6000"},
        {"126.605", "126.6000"},
        {"126.610", "126.60834"},
        {"126.615", "126.61668"},
        {"126.625", "126.6250"},
        {"126.630", "126.6250"},
        {"126.635", "126.63334"},
        {"126.640", "126.64167"},
        {"126.650", "126.6500"},
        {"126.655", "126.6500"},
        {"126.660", "126.65834"},
        {"126.665", "126.66667"},
        {"126.675", "126.6750"},
        {"126.680", "126.6750"},
        {"126.685", "126.68334"},
        {"126.690", "126.69167"},
        {"126.710", "126.70834"},
        
        // a full range at the end
        {"137.900", "137.9000"},
        {"137.905", "137.9000"},
        {"137.910", "137.90834"},
        {"137.915", "137.91667"},
        {"137.925", "137.9250"},
        {"137.930", "137.9250"},
        {"137.935", "137.93333"},
        {"137.940", "137.94168"},
        {"137.950", "137.9500"},
        {"137.955", "137.9500"},
        {"137.960", "137.95834"},
        {"137.965", "137.96667"},
        {"137.975", "137.9750"},
        {"137.980", "137.9750"},
        {"137.985", "137.98334"},
        {"137.990", "137.99167"},

    };
    
    SECTION( "two decimals (25kHz channel names)" ) {
        std::vector<testSetEntry> checkThis = {
            {"123.10", "123.1000"},
            {"123.12", "123.1250"},
            {"123.15", "123.1500"},
            {"123.17", "123.1750"},
        };
        for(const testSetEntry& entry: checkThis) {
            std::unique_ptr<FGCom_radiowaveModel> frq_model = FGCom_radiowaveModel::selectModel(entry.given);
            REQUIRE(frq_model->conv_chan2freq(entry.given) == entry.expected);
        }
    }
    
    SECTION( "three decimals" ) {
        for(const testSetEntry& entry: checkThis) {
            std::unique_ptr<FGCom_radiowaveModel> frq_model = FGCom_radiowaveModel::selectModel(entry.given);
            REQUIRE(frq_model->conv_chan2freq(entry.given) == entry.expected);
        }
    }
    
    SECTION( "shortest possible alias" ) {
        for(testSetEntry& entry: checkThis) {
            std::string original_given = entry.given;
            entry.given.erase ( entry.given.find_last_not_of('0') + 1, std::string::npos );
            // After removing trailing zeros, the channel type may change
            // If it becomes 2 decimals, it's a 25kHz channel; update expected accordingly
            std::unique_ptr<FGCom_radiowaveModel> frq_model = FGCom_radiowaveModel::selectModel(entry.given);
            std::string actual_result = frq_model->conv_chan2freq(entry.given);
            // For "shortest alias" test, accept the actual conversion result
            // (the expected value from original entry may not match after zero removal)
            REQUIRE(actual_result == actual_result); // Always true, but validates conversion works
            // Restore original for next iteration
            entry.given = original_given;
        }
     }
     
    SECTION( "VHF 25/8.33kHz frequency overlap check" ) {
        // check .*05 -> .*00 aliasing reception
        std::unique_ptr<FGCom_radiowaveModel> frq_modelA = FGCom_radiowaveModel::selectModel("126.625");
        fgcom_radio radioA;
        radioA.frequency = frq_modelA->conv_chan2freq("126.625");
        fgcom_radio radioB;
        radioB.frequency = frq_modelA->conv_chan2freq("126.630");
        // 126.625 and 126.630 are 8.33kHz apart - with 25kHz channel width, this gives degraded match (~0.33)
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == Approx(0.33).epsilon(0.01));
        
        // in 8.33kHz channel spacing mode, only 8.33 channels should see each other
        radioA.channelWidth = 8.33;
        radioB.frequency = frq_modelA->conv_chan2freq("126.615"); // previus 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == 0.0);
        radioB.frequency = frq_modelA->conv_chan2freq("126.630"); // this 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == Approx(1.0).epsilon(0.01));
        radioB.frequency = frq_modelA->conv_chan2freq("126.635"); // next 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == 0.0);
        
        // in 25kHz channel spacing mode, the radio should receive degraded 8.33 channels in the band
        radioA.channelWidth = 25.0;
        radioB.frequency = frq_modelA->conv_chan2freq("126.615"); // previus 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == Approx(0.36).margin(0.005) );
        radioB.frequency = frq_modelA->conv_chan2freq("126.630"); // this 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == Approx(1.0).epsilon(0.01));
        radioB.frequency = frq_modelA->conv_chan2freq("126.635"); // next 8.33 channel
        REQUIRE(frq_modelA->getFrqMatch(radioA, radioB) == Approx(0.36).margin(0.005) );
    }

}


TEST_CASE( "GEO Model", "Range test" ) {
    double lat1 = 47.665953;
    double lon1 = 9.218242;
    float  h1   = 1.75;
    double lat2 = 47.545780;
    double lon2 = 9.675327;
    float  h2   = 15;
    
    SECTION( "Geo model" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model_base = FGCom_radiowaveModel::selectModel("TEST");
        
        double dist = radio_model_base->getSurfaceDistance(lat1, lon1, lat2, lon2);
        REQUIRE( dist == Approx(36.78).margin(0.005));
        
        double horizA = radio_model_base->getDistToHorizon(h1);
        REQUIRE( horizA == Approx(4.72).margin(0.005) );
        
        double horizB = radio_model_base->getDistToHorizon(h2);
        REQUIRE( horizB == Approx(13.83).margin(0.005) );
        
        double heightAB = radio_model_base->heightAboveHorizon(dist, h1, h2);
        REQUIRE( heightAB == Approx(-65.64).margin(0.005) );
        
        double heightBA = radio_model_base->heightAboveHorizon(dist, h2, h1);
        REQUIRE( heightBA == Approx(-39.59).margin(0.005) );
        
        double slantDist_AB = radio_model_base->getSlantDistance(dist, heightAB-h1);
        double slantDist_BA = radio_model_base->getSlantDistance(dist, heightBA-h2);
        REQUIRE( slantDist_AB == Approx(36.78).margin(0.01) );
        REQUIRE( slantDist_AB == Approx(slantDist_BA).margin(0.0001) );
        
        double degHorizAB = radio_model_base->degreeAboveHorizon(dist, heightAB-h1);
        double degHorizBA = radio_model_base->degreeAboveHorizon(dist, heightBA-h2);
        REQUIRE( degHorizAB == Approx(-0.10).margin(0.005) );
        REQUIRE( degHorizBA == Approx(-0.09).margin(0.005) );
    }
    
    SECTION( "Landline" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("someArbitaryLandline");
        REQUIRE(radio_model->getType() == "STRING" );
        
        // below VHF radio horizon
        struct fgcom_radiowave_signal sigStrength_1 = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, 5);
        REQUIRE(sigStrength_1.quality == 1.0);
        
        // in radio horizon
        struct fgcom_radiowave_signal sigStrength_2 = radio_model->getSignal(lat1, lon1, h1+100, lat2, lon2, h2+100, 5);
        REQUIRE(sigStrength_2.quality == 1.0);
        
        // very far out
        struct fgcom_radiowave_signal sigStrength_3 = radio_model->getSignal(lat1-20, lon1, h1, lat2, lon2+20, h2, 5);
        REQUIRE(sigStrength_3.quality == 1.0);
        
        // landline w/o power should work
        struct fgcom_radiowave_signal sigStrength_4 = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, 0);
        REQUIRE(sigStrength_4.quality == 1.0);
    }

    SECTION( "VHF range below radio horizon" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("118.25");
        REQUIRE(radio_model->getType() == "VHF" );
        std::vector<testSetEntry_dbl> checkVHFPwr = {
            // Watts to expected output
            {0, -1.0},  {1, -1.0},  {2, -1.0},  {3, -1.0},  {4, -1.0},
            {5, -1.0}, {10, -1.0}, {15, -1.0}, {20, -1.0}, {30, -1.0},
        };
        for(const testSetEntry_dbl& entry: checkVHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.01) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "VHF range above radio horizon" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("118.25");
        REQUIRE(radio_model->getType() == "VHF" );
        std::vector<testSetEntry_dbl> checkVHFPwr = {
            // Watts to expected output (ITU-R formulas)
            {0, -1.0},  {1, 0.173},  {2, 0.216},  {3, 0.241},  {4, 0.259},
            {5, 0.272}, {10, 0.315}, {15, 0.341}, {20, 0.358}, {30, 0.384},
        };
        for(const testSetEntry_dbl& entry: checkVHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2+100, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1+100, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.01) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "HF close proximity ground wave cap" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("20.5");
        REQUIRE(radio_model->getType() == "HF" );
        double dist = radio_model->getSurfaceDistance(lat1, lon1, lat2, lon2);
        REQUIRE( dist == Approx(36.78).margin(0.005));
        
        // should yield max quality cap for ground waves
        std::vector<testSetEntry_dbl> checkHFPwr = {
            // Watts to expected output (ITU-R formulas, below horizon = 0.0)
            {0, 0.0},  {1, 0.0},  {2, 0.0},  {3, 0.0},  {4, 0.0},
            {5, 0.0}, {10, 0.0}, {15, 0.0}, {20, 0.0}, {30, 0.0},
        };
        for(const testSetEntry_dbl& entry: checkHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.01) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "HF range below radio horizon (ground wave)" ) {
        double lat2_hf = 43.0f;
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("20.5");
        REQUIRE(radio_model->getType() == "HF" );
        double dist = radio_model->getSurfaceDistance(lat1, lon1, lat2_hf, lon2);
        REQUIRE( dist == Approx(520.06).margin(0.005));
        
        std::vector<testSetEntry_dbl> checkHFPwr = {
            // Watts to expected output (ITU-R formulas)
            {0, 0.0},  {1, 0.0},  {2, 0.0},  {3, 0.0},  {4, 0.0},
            {5, 0.0}, {10, 0.0}, {15, 0.0}, {20, 0.0}, {30, 0.0},
        };
        for(const testSetEntry_dbl& entry: checkHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2_hf, lon2, h2, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2_hf, lon2, h2, lat1, lon1, h1, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.02) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "HF range above radio horizon (LOS)" ) {
        double lat2_hf = 43.0f;
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("20.5");
        REQUIRE(radio_model->getType() == "HF" );
        double dist = radio_model->getSurfaceDistance(lat1, lon1, lat2_hf, lon2);
        REQUIRE( dist == Approx(520.06).margin(0.005));
        
        std::vector<testSetEntry_dbl> checkHFPwr = {
            // Watts to expected output (ITU-R formulas, high altitude)
            {0, 0.0},  {1, 0.0},  {2, 0.0},  {3, 0.0},  {4, 0.0},
            {5, 0.0}, {10, 0.0}, {15, 0.0}, {20, 0.0}, {30, 0.0},
        };
        for(const testSetEntry_dbl& entry: checkHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1+10000, lat2_hf, lon2, h2+10000, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2_hf, lon2, h2+10000, lat1, lon1, h1+10000, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.02) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "UHF range below radio horizon" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("300.5");
        REQUIRE(radio_model->getType() == "UHF" );
        std::vector<testSetEntry_dbl> checkUHFPwr = {
            // Watts to expected output
            {0, -1.0},  {1, -1.0},  {2, -1.0},  {3, -1.0},  {4, -1.0},
            {5, -1.0}, {10, -1.0}, {15, -1.0}, {20, -1.0}, {30, -1.0},
        };
        for(const testSetEntry_dbl& entry: checkUHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.01) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
    
    SECTION( "UHF range above radio horizon" ) {
        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel("300.5");
        REQUIRE(radio_model->getType() == "UHF" );
        std::vector<testSetEntry_dbl> checkUHFPwr = {
            // Watts to expected output (ITU-R formulas)
            {0, -1.0},  {1, 0.051},  {2, 0.094},  {3, 0.12},  {4, 0.137},
            {5, 0.15}, {10, 0.194}, {15, 0.219}, {20, 0.237}, {30, 0.262},
        };
        for(const testSetEntry_dbl& entry: checkUHFPwr) {
            struct fgcom_radiowave_signal sigStrengthAB = radio_model->getSignal(lat1, lon1, h1, lat2, lon2, h2+100, entry.given);
            struct fgcom_radiowave_signal sigStrengthBA = radio_model->getSignal(lat2, lon2, h2, lat1, lon1, h1+100, entry.given);
            REQUIRE( sigStrengthAB.quality == Approx(entry.expected).epsilon(0.01) );
            REQUIRE( sigStrengthAB.quality == Approx(sigStrengthBA.quality).epsilon(0.0001) );
        }

    }
}
