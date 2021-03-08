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
#include "test/catch2/catch.hpp"

#include "lib/radio_model.h"

struct testSetEntry { std::string given, expected; };

TEST_CASE( "Radio Model", "25/8.33kHz frq parsing check" ) {
    std::vector<testSetEntry> checkThis = {
        {"118.000", "118.0000"},
        {"118.005", "118.0000"},
        {"118.010", "118.00834"},
        {"118.015", "118.01667"},
        {"118.025", "118.0250"},
        {"118.030", "118.0250"},
        {"118.035", "118.03334"},
        {"118.040", "118.04167"},
        {"118.050", "118.0500"},
        {"118.055", "118.0500"},
        {"118.060", "118.05834"},
        {"118.065", "118.06667"},
        {"118.075", "118.0750"},
        {"118.080", "118.0750"},
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
        {"118.155", "118.1500"}
    };
    
    SECTION( "three decimals" ) {
        for(const testSetEntry& entry: checkThis) {
            std::unique_ptr<FGCom_radiowaveModel> frq_model = FGCom_radiowaveModel::selectModel(entry.given);
            REQUIRE(frq_model->conv_chan2freq(entry.given) == entry.expected);
        }
    }
    
    SECTION( "shortest possible alias" ) {
        for(testSetEntry& entry: checkThis) {
            entry.given.erase ( entry.given.find_last_not_of('0') + 1, std::string::npos );
            std::unique_ptr<FGCom_radiowaveModel> frq_model = FGCom_radiowaveModel::selectModel(entry.given);
            REQUIRE(frq_model->conv_chan2freq(entry.given) == entry.expected);
        }
     }

}

