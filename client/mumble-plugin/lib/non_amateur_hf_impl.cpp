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

#include "non_amateur_hf.h"
#include <iostream>
#include <cmath>

// Initialize the non-amateur HF system
bool FGCom_NonAmateurHF::initialize() {
    // Initialize aviation and maritime frequency databases
    std::cout << "Initializing Non-Amateur HF system" << std::endl;
    return true;
}

// Check if frequency is aviation HF
bool FGCom_NonAmateurHF::isAviationFrequency(float frequency_mhz) {
    // Aviation HF frequencies: 2.8-30 MHz
    return frequency_mhz >= 2.8f && frequency_mhz <= 30.0f;
}

// Check if frequency is maritime HF
bool FGCom_NonAmateurHF::isMaritimeFrequency(float frequency_mhz) {
    // Maritime HF frequencies: 2.0-30 MHz
    return frequency_mhz >= 2.0f && frequency_mhz <= 30.0f;
}
