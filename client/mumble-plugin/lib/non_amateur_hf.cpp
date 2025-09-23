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
#include "solar_data.h"
#include <iostream>
#include <cmath>
#include <algorithm>

// Static member definitions
std::vector<fgcom_aviation_hf_band> FGCom_NonAmateurHF::aviation_bands;
std::vector<fgcom_maritime_channel> FGCom_NonAmateurHF::maritime_channels;
std::vector<fgcom_mwara_frequency> FGCom_NonAmateurHF::mwara_frequencies;
bool FGCom_NonAmateurHF::initialized = false;

bool FGCom_NonAmateurHF::initialize() {
    if (initialized) return true;
    
    setupAviationBands();
    setupMaritimeChannels();
    setupMWARAFrequencies();
    loadUSCGMaritimeChannels();
    
    initialized = true;
    return true;
}

void FGCom_NonAmateurHF::setupAviationBands() {
    // Aviation HF bands based on actual ITU allocations from HFUnderground
    aviation_bands = {
        {"2.85MHz", 2850.0, 3155.0, "USB", 3.0, "AERONAUTICAL", "2850-3025 kHz civilian / 3025-3155 kHz military"},
        {"3.4MHz", 3400.0, 3500.0, "USB", 3.0, "AERONAUTICAL", "3400-3500 kHz civilian"},
        {"3.8MHz", 3800.0, 3950.0, "USB", 3.0, "AERONAUTICAL", "3800-3950 kHz civilian (shared with 75m amateur and broadcasting)"},
        {"4.65MHz", 4650.0, 4750.0, "USB", 3.0, "AERONAUTICAL", "4650-4700 kHz civilian / 4700-4750 kHz military"},
        {"5.45MHz", 5450.0, 5730.0, "USB", 3.0, "AERONAUTICAL", "5450-5680 kHz civilian / 5680-5730 kHz military"},
        {"6.525MHz", 6525.0, 6765.0, "USB", 3.0, "AERONAUTICAL", "6525-6685 kHz civilian / 6685-6765 kHz military"},
        {"8.815MHz", 8815.0, 9040.0, "USB", 3.0, "AERONAUTICAL", "8815-8965 kHz civilian / 8965-9040 kHz military"},
        {"10.005MHz", 10005.0, 10100.0, "USB", 3.0, "AERONAUTICAL", "10005-10100 kHz civilian"},
        {"11.175MHz", 11175.0, 11400.0, "USB", 3.0, "AERONAUTICAL", "11175-11275 military / 11275-11400 kHz military"},
        {"13.2MHz", 13200.0, 13360.0, "USB", 3.0, "AERONAUTICAL", "13200-13260 civilian / 13260-13360 kHz military"},
        {"15.01MHz", 15010.0, 15100.0, "USB", 3.0, "AERONAUTICAL", "15010-15100 kHz military"},
        {"17.9MHz", 17900.0, 18030.0, "USB", 3.0, "AERONAUTICAL", "17900-17970 civilian / 17970-18030 kHz military"},
        {"21.87MHz", 21870.0, 22000.0, "USB", 3.0, "AERONAUTICAL", "21870-22000 kHz civilian"},
        {"23.2MHz", 23200.0, 23350.0, "USB", 3.0, "AERONAUTICAL", "23200-23350 kHz civilian"}
    };
}

void FGCom_NonAmateurHF::setupMWARAFrequencies() {
    // MWARA frequencies based on HFUnderground data
    mwara_frequencies.clear();
    
    // North Atlantic (NAT) Communications Frequencies
    std::vector<std::pair<float, std::string>> nat_freqs = {
        {2872.0, "NAT Communications"},
        {2889.0, "NAT Communications"},
        {2962.0, "NAT Communications"},
        {2971.0, "NAT Communications"},
        {3016.0, "NAT Communications"},
        {3476.0, "NAT Communications"},
        {4675.0, "NAT Communications"},
        {5598.0, "NAT Communications"},
        {5616.0, "NAT Communications"},
        {5649.0, "NAT Communications"},
        {6622.0, "NAT Communications"},
        {6628.0, "NAT Communications"},
        {8825.0, "NAT Communications"},
        {8831.0, "NAT Communications"},
        {8864.0, "NAT Communications"},
        {8879.0, "NAT Communications"},
        {8891.0, "NAT Communications"},
        {8906.0, "NAT Communications"},
        {11279.0, "NAT Communications"},
        {11309.0, "NAT Communications"},
        {11336.0, "NAT Communications"},
        {13291.0, "NAT Communications"},
        {13306.0, "NAT Communications"},
        {17946.0, "NAT Communications"}
    };
    
    for (const auto& freq : nat_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "NAT";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // North Atlantic VOLMET Frequencies
    std::vector<std::pair<float, std::string>> nat_volmet = {
        {3485.0, "NAT VOLMET - Aviation Weather"},
        {6604.0, "NAT VOLMET - Aviation Weather"},
        {10051.0, "NAT VOLMET - Aviation Weather"},
        {13270.0, "NAT VOLMET - Aviation Weather"}
    };
    
    for (const auto& freq : nat_volmet) {
        fgcom_mwara_frequency mwara;
        mwara.region = "NAT";
        mwara.frequency = freq.first;
        mwara.service_type = "VOLMET";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // Caribbean (CAR) Communications Frequencies
    std::vector<std::pair<float, std::string>> car_freqs = {
        {2887.0, "CAR Communications"},
        {3455.0, "CAR Communications"},
        {5520.0, "CAR Communications"},
        {5550.0, "CAR Communications"},
        {6577.0, "CAR Communications"},
        {6586.0, "CAR Communications"},
        {8846.0, "CAR Communications"},
        {8918.0, "CAR Communications"},
        {11387.0, "CAR Communications"},
        {11396.0, "CAR Communications"},
        {13297.0, "CAR Communications"},
        {17907.0, "CAR Communications"}
    };
    
    for (const auto& freq : car_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "CAR";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // South Atlantic (SAT) Communications Frequencies
    std::vector<std::pair<float, std::string>> sat_freqs = {
        {2854.0, "SAT Communications"},
        {2935.0, "SAT Communications"},
        {3452.0, "SAT Communications"},
        {5565.0, "SAT Communications"},
        {6535.0, "SAT Communications"},
        {8861.0, "SAT Communications"},
        {11291.0, "SAT Communications"},
        {13315.0, "SAT Communications"},
        {13357.0, "SAT Communications"},
        {17955.0, "SAT Communications"}
    };
    
    for (const auto& freq : sat_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "SAT";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // South America (SAM) Communications Frequencies
    std::vector<std::pair<float, std::string>> sam_freqs = {
        {2944.0, "SAM Communications"},
        {3479.0, "SAM Communications"},
        {4669.0, "SAM Communications"},
        {5526.0, "SAM Communications"},
        {6649.0, "SAM Communications"},
        {8855.0, "SAM Communications"},
        {10096.0, "SAM Communications"},
        {11360.0, "SAM Communications"},
        {13297.0, "SAM Communications"},
        {17907.0, "SAM Communications"}
    };
    
    for (const auto& freq : sam_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "SAM";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // Europe (EUR) Communications Frequencies
    std::vector<std::pair<float, std::string>> eur_freqs = {
        {3479.0, "EUR Communications"},
        {5661.0, "EUR Communications"},
        {6598.0, "EUR Communications"},
        {10084.0, "EUR Communications"},
        {13288.0, "EUR Communications"},
        {17961.0, "EUR Communications"}
    };
    
    for (const auto& freq : eur_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "EUR";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // North Pacific (NP) Communications Frequencies
    std::vector<std::pair<float, std::string>> np_freqs = {
        {2932.0, "NP Communications"},
        {5628.0, "NP Communications"},
        {6655.0, "NP Communications"},
        {6661.0, "NP Communications"},
        {10048.0, "NP Communications"},
        {11330.0, "NP Communications"},
        {13300.0, "NP Communications"},
        {17904.0, "NP Communications"}
    };
    
    for (const auto& freq : np_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "NP";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // Central East Pacific (CEP) Communications Frequencies
    std::vector<std::pair<float, std::string>> cep_freqs = {
        {2869.0, "CEP Communications"},
        {3413.0, "CEP Communications"},
        {4657.0, "CEP Communications"},
        {5547.0, "CEP Communications"},
        {5574.0, "CEP Communications"},
        {6673.0, "CEP Communications"},
        {8843.0, "CEP Communications"},
        {10057.0, "CEP Communications"},
        {11282.0, "CEP Communications"},
        {13300.0, "CEP Communications"},
        {17904.0, "CEP Communications"}
    };
    
    for (const auto& freq : cep_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "CEP";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // South Pacific (SP) Communications Frequencies
    std::vector<std::pair<float, std::string>> sp_freqs = {
        {3467.0, "SP Communications"},
        {5559.0, "SP Communications"},
        {5643.0, "SP Communications"},
        {8867.0, "SP Communications"},
        {10084.0, "SP Communications"},
        {11327.0, "SP Communications"},
        {13300.0, "SP Communications"},
        {17904.0, "SP Communications"}
    };
    
    for (const auto& freq : sp_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "SP";
        mwara.frequency = freq.first;
        mwara.service_type = "MWARA";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
    
    // Worldwide Search and Rescue Frequencies
    std::vector<std::pair<float, std::string>> sar_freqs = {
        {2182.0, "International Aircraft Search and Rescue - Distress and calling"},
        {3023.0, "International Aircraft Search and Rescue"},
        {5680.0, "International Aircraft Search and Rescue"},
        {8364.0, "International Aircraft Search and Rescue"}
    };
    
    for (const auto& freq : sar_freqs) {
        fgcom_mwara_frequency mwara;
        mwara.region = "WORLDWIDE";
        mwara.frequency = freq.first;
        mwara.service_type = "SAR";
        mwara.notes = freq.second;
        mwara_frequencies.push_back(mwara);
    }
}

void FGCom_NonAmateurHF::setupMaritimeChannels() {
    // Initialize with basic maritime bands
    maritime_channels.clear();
    
    // 4 MHz Maritime Band (401-421)
    for (int i = 401; i <= 421; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "4MHz";
        channel.coast_freq = 4357.0 + (i - 401) * 3.0;
        channel.ship_freq = 4065.0 + (i - 401) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 421) {
            channel.notes = "Calling; distress & safety working on 4125 kHz simplex";
        } else if (i == 424) {
            channel.notes = "USCG Calling";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 6 MHz Maritime Band (601-607)
    for (int i = 601; i <= 607; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "6MHz";
        channel.coast_freq = 6501.0 + (i - 601) * 3.0;
        channel.ship_freq = 6200.0 + (i - 601) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 601) {
            channel.notes = "USCG Calling";
        } else if (i == 606) {
            channel.notes = "Calling; distress & safety working on 6215 kHz simplex";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 8 MHz Maritime Band (801-832)
    for (int i = 801; i <= 832; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "8MHz";
        channel.coast_freq = 8719.0 + (i - 801) * 3.0;
        channel.ship_freq = 8195.0 + (i - 801) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 816) {
            channel.notes = "USCG Calling";
        } else if (i == 821) {
            channel.notes = "Calling";
        } else if (i == 833) {
            channel.coast_freq = 8291.0;
            channel.ship_freq = 8291.0;
            channel.is_simplex = true;
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 12 MHz Maritime Band (1201-1239)
    for (int i = 1201; i <= 1239; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "12MHz";
        channel.coast_freq = 13077.0 + (i - 1201) * 3.0;
        channel.ship_freq = 12230.0 + (i - 1201) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 1205) {
            channel.notes = "USCG Calling";
        } else if (i == 1221) {
            channel.notes = "Calling";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 16 MHz Maritime Band (1601-1655)
    for (int i = 1601; i <= 1655; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "16MHz";
        channel.coast_freq = 17242.0 + (i - 1601) * 3.0;
        channel.ship_freq = 16360.0 + (i - 1601) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 1621) {
            channel.notes = "Calling";
        } else if (i == 1625) {
            channel.notes = "USCG Calling";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 18/19 MHz Maritime Band (1801-1815)
    for (int i = 1801; i <= 1815; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "18MHz";
        channel.coast_freq = 19755.0 + (i - 1801) * 3.0;
        channel.ship_freq = 18780.0 + (i - 1801) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 1806) {
            channel.notes = "Calling";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 22 MHz Maritime Band (2201-2253)
    for (int i = 2201; i <= 2253; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "22MHz";
        channel.coast_freq = 22696.0 + (i - 2201) * 3.0;
        channel.ship_freq = 22000.0 + (i - 2201) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 2221) {
            channel.notes = "Calling";
        }
        
        maritime_channels.push_back(channel);
    }
    
    // 25/26 MHz Maritime Band (2501-2510)
    for (int i = 2501; i <= 2510; i++) {
        fgcom_maritime_channel channel;
        channel.channel_number = i;
        channel.band = "25MHz";
        channel.coast_freq = 26145.0 + (i - 2501) * 3.0;
        channel.ship_freq = 25070.0 + (i - 2501) * 3.0;
        channel.service_type = "MARITIME";
        channel.is_simplex = false;
        
        if (i == 2510) {
            channel.notes = "Calling";
        }
        
        maritime_channels.push_back(channel);
    }
}

void FGCom_NonAmateurHF::loadUSCGMaritimeChannels() {
    // This would load additional channels from the USCG data
    // For now, we'll add some key simplex channels and distress frequencies
    
    // Distress and Safety Frequencies
    std::vector<std::pair<float, std::string>> distress_freqs = {
        {2182.0, "International distress and calling"},
        {4125.0, "Distress and safety working"},
        {6215.0, "Distress and safety working"},
        {8291.0, "Distress and safety working"},
        {12290.0, "Distress and safety working"},
        {16420.0, "Distress and safety working"}
    };
    
    for (const auto& freq : distress_freqs) {
        fgcom_maritime_channel channel;
        channel.channel_number = 0; // Special channel
        channel.band = "DISTRESS";
        channel.coast_freq = freq.first;
        channel.ship_freq = freq.first;
        channel.service_type = "MARITIME_DISTRESS";
        channel.is_simplex = true;
        channel.notes = freq.second;
        maritime_channels.push_back(channel);
    }
}

std::vector<fgcom_aviation_hf_band> FGCom_NonAmateurHF::getAviationBands() {
    if (!initialized) initialize();
    return aviation_bands;
}

fgcom_aviation_hf_band FGCom_NonAmateurHF::getAviationBand(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& band : aviation_bands) {
        if (frequency_khz >= band.start_freq && frequency_khz <= band.end_freq) {
            return band;
        }
    }
    
    return {}; // Return empty band if not found
}

bool FGCom_NonAmateurHF::isAviationFrequency(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& band : aviation_bands) {
        if (frequency_khz >= band.start_freq && frequency_khz <= band.end_freq) {
            return true;
        }
    }
    
    return false;
}

float FGCom_NonAmateurHF::calculateAviationPropagation(float frequency_khz, double distance_km, float altitude1_ft, float altitude2_ft) {
    float propagation_factor = 1.0;
    
    // High altitude effects
    float avg_altitude = (altitude1_ft + altitude2_ft) / 2.0;
    if (avg_altitude > 20000.0) {
        // Above 20,000 ft, reduced atmospheric absorption
        propagation_factor *= 1.2;
    }
    
    // Frequency-dependent effects
    if (frequency_khz < 5000.0) {
        // Lower frequencies have better ground wave propagation
        propagation_factor *= 1.1;
    } else if (frequency_khz > 20000.0) {
        // Higher frequencies more affected by ionosphere
        propagation_factor *= 0.9;
    }
    
    // Distance effects
    if (distance_km > 1000.0) {
        // Long distance, skywave propagation
        propagation_factor *= 0.8;
    }
    
    return std::max(0.3f, std::min(2.0f, propagation_factor));
}

float FGCom_NonAmateurHF::calculateWhipAntennaEfficiency(float frequency_khz, float altitude_ft) {
    // Whip antenna efficiency decreases with altitude due to reduced ground plane
    float base_efficiency = 0.7; // Base efficiency at sea level
    
    // Altitude effect (reduced ground plane)
    float altitude_factor = 1.0 - (altitude_ft / 50000.0) * 0.3;
    
    // Frequency effect (whip length vs wavelength)
    float wavelength_m = 300000.0 / frequency_khz; // Wavelength in meters
    float frequency_factor = 1.0;
    
    if (wavelength_m > 10.0) {
        // Very long wavelength, poor efficiency
        frequency_factor = 0.5;
    } else if (wavelength_m > 5.0) {
        // Long wavelength, reduced efficiency
        frequency_factor = 0.7;
    }
    
    return base_efficiency * altitude_factor * frequency_factor;
}

float FGCom_NonAmateurHF::calculateHighAltitudeEffects(float altitude_ft, double distance_km) {
    float effect = 1.0;
    
    // Reduced atmospheric absorption at high altitude
    if (altitude_ft > 30000.0) {
        effect *= 1.3; // 30% improvement above 30,000 ft
    } else if (altitude_ft > 20000.0) {
        effect *= 1.1; // 10% improvement above 20,000 ft
    }
    
    // Line-of-sight improvement at high altitude
    float horizon_distance = sqrt(2 * 6371000 * altitude_ft * 0.3048); // Earth radius in meters
    if (distance_km < horizon_distance / 1000.0) {
        effect *= 1.2; // Line-of-sight propagation
    }
    
    return std::max(0.5f, std::min(2.0f, effect));
}

std::vector<fgcom_maritime_channel> FGCom_NonAmateurHF::getMaritimeChannels() {
    if (!initialized) initialize();
    return maritime_channels;
}

fgcom_maritime_channel FGCom_NonAmateurHF::getMaritimeChannel(int channel_number) {
    if (!initialized) initialize();
    
    for (const auto& channel : maritime_channels) {
        if (channel.channel_number == channel_number) {
            return channel;
        }
    }
    
    return {}; // Return empty channel if not found
}

fgcom_maritime_channel FGCom_NonAmateurHF::getMaritimeChannelByFrequency(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& channel : maritime_channels) {
        if (std::abs(channel.coast_freq - frequency_khz) < 1.0 || 
            std::abs(channel.ship_freq - frequency_khz) < 1.0) {
            return channel;
        }
    }
    
    return {}; // Return empty channel if not found
}

bool FGCom_NonAmateurHF::isMaritimeFrequency(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& channel : maritime_channels) {
        if (std::abs(channel.coast_freq - frequency_khz) < 1.0 || 
            std::abs(channel.ship_freq - frequency_khz) < 1.0) {
            return true;
        }
    }
    
    return false;
}

float FGCom_NonAmateurHF::calculateMaritimePropagation(float frequency_khz, double distance_km, float altitude1_ft, float altitude2_ft) {
    float propagation_factor = 1.0;
    
    // Sea path effects
    propagation_factor *= calculateSeaPathEffects(distance_km, (altitude1_ft + altitude2_ft) / 2.0);
    
    // Frequency effects
    if (frequency_khz < 5000.0) {
        // Lower frequencies better for maritime
        propagation_factor *= 1.1;
    }
    
    // Distance effects
    if (distance_km > 500.0) {
        // Long distance maritime propagation
        propagation_factor *= 0.9;
    }
    
    return std::max(0.4f, std::min(1.8f, propagation_factor));
}

float FGCom_NonAmateurHF::calculateSeaPathEffects(double distance_km, float altitude_ft) {
    float effect = 1.0;
    
    // Sea reflection effects
    if (altitude_ft < 100.0) {
        // Low altitude, good sea reflection
        effect *= 1.1;
    }
    
    // Distance over water
    if (distance_km > 200.0) {
        // Long distance over water
        effect *= 0.95;
    }
    
    return effect;
}

std::string FGCom_NonAmateurHF::aviationFreqToChannel(float frequency_khz) {
    // Convert aviation frequency to channel designation
    if (frequency_khz >= 2000.0 && frequency_khz <= 3000.0) {
        return "2MHz_" + std::to_string((int)((frequency_khz - 2000.0) / 3.0));
    } else if (frequency_khz >= 4000.0 && frequency_khz <= 5000.0) {
        return "4MHz_" + std::to_string((int)((frequency_khz - 4000.0) / 3.0));
    } else if (frequency_khz >= 6000.0 && frequency_khz <= 7000.0) {
        return "6MHz_" + std::to_string((int)((frequency_khz - 6000.0) / 3.0));
    } else if (frequency_khz >= 8000.0 && frequency_khz <= 9000.0) {
        return "8MHz_" + std::to_string((int)((frequency_khz - 8000.0) / 3.0));
    } else if (frequency_khz >= 12000.0 && frequency_khz <= 13000.0) {
        return "12MHz_" + std::to_string((int)((frequency_khz - 12000.0) / 3.0));
    } else if (frequency_khz >= 16000.0 && frequency_khz <= 17000.0) {
        return "16MHz_" + std::to_string((int)((frequency_khz - 16000.0) / 3.0));
    } else if (frequency_khz >= 18000.0 && frequency_khz <= 19000.0) {
        return "18MHz_" + std::to_string((int)((frequency_khz - 18000.0) / 3.0));
    } else if (frequency_khz >= 22000.0 && frequency_khz <= 23000.0) {
        return "22MHz_" + std::to_string((int)((frequency_khz - 22000.0) / 3.0));
    } else if (frequency_khz >= 25000.0 && frequency_khz <= 26000.0) {
        return "25MHz_" + std::to_string((int)((frequency_khz - 25000.0) / 3.0));
    }
    
    return "UNKNOWN";
}

std::string FGCom_NonAmateurHF::maritimeFreqToChannel(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& channel : maritime_channels) {
        if (std::abs(channel.coast_freq - frequency_khz) < 1.0 || 
            std::abs(channel.ship_freq - frequency_khz) < 1.0) {
            return std::to_string(channel.channel_number);
        }
    }
    
    return "UNKNOWN";
}

float FGCom_NonAmateurHF::aviationChannelToFreq(const std::string& channel) {
    // Parse aviation channel to frequency
    if (channel.find("2MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(5));
        return 2000.0 + channel_num * 3.0;
    } else if (channel.find("4MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(5));
        return 4000.0 + channel_num * 3.0;
    } else if (channel.find("6MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(5));
        return 6000.0 + channel_num * 3.0;
    } else if (channel.find("8MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(5));
        return 8000.0 + channel_num * 3.0;
    } else if (channel.find("12MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(6));
        return 12000.0 + channel_num * 3.0;
    } else if (channel.find("16MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(6));
        return 16000.0 + channel_num * 3.0;
    } else if (channel.find("18MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(6));
        return 18000.0 + channel_num * 3.0;
    } else if (channel.find("22MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(6));
        return 22000.0 + channel_num * 3.0;
    } else if (channel.find("25MHz_") == 0) {
        int channel_num = std::stoi(channel.substr(6));
        return 25000.0 + channel_num * 3.0;
    }
    
    return 0.0;
}

float FGCom_NonAmateurHF::maritimeChannelToFreq(const std::string& channel) {
    if (!initialized) initialize();
    
    int channel_num = std::stoi(channel);
    fgcom_maritime_channel mar_channel = getMaritimeChannel(channel_num);
    
    if (mar_channel.channel_number != 0) {
        return mar_channel.coast_freq; // Return coast frequency by default
    }
    
    return 0.0;
}

std::vector<fgcom_mwara_frequency> FGCom_NonAmateurHF::getMWARAFrequencies() {
    if (!initialized) initialize();
    return mwara_frequencies;
}

std::vector<fgcom_mwara_frequency> FGCom_NonAmateurHF::getMWARAFrequenciesByRegion(const std::string& region) {
    if (!initialized) initialize();
    
    std::vector<fgcom_mwara_frequency> region_freqs;
    for (const auto& freq : mwara_frequencies) {
        if (freq.region == region) {
            region_freqs.push_back(freq);
        }
    }
    return region_freqs;
}

bool FGCom_NonAmateurHF::isMWARAFrequency(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& freq : mwara_frequencies) {
        if (std::abs(freq.frequency - frequency_khz) < 1.0) {
            return true;
        }
    }
    return false;
}

fgcom_mwara_frequency FGCom_NonAmateurHF::getMWARAFrequency(float frequency_khz) {
    if (!initialized) initialize();
    
    for (const auto& freq : mwara_frequencies) {
        if (std::abs(freq.frequency - frequency_khz) < 1.0) {
            return freq;
        }
    }
    return {}; // Return empty frequency if not found
}

std::vector<std::string> FGCom_NonAmateurHF::getMWARARegions() {
    if (!initialized) initialize();
    
    std::set<std::string> unique_regions;
    for (const auto& freq : mwara_frequencies) {
        unique_regions.insert(freq.region);
    }
    
    std::vector<std::string> regions;
    for (const auto& region : unique_regions) {
        regions.push_back(region);
    }
    return regions;
}

float FGCom_NonAmateurHF::getUSBBandwidth(float frequency_khz) {
    // USB bandwidth is typically 3kHz for aviation HF
    return 3.0;
}

float FGCom_NonAmateurHF::getSSBBandwidth(float frequency_khz) {
    // SSB bandwidth is typically 3kHz
    return 3.0;
}

std::string FGCom_NonAmateurHF::getModulationType(float frequency_khz) {
    if (isAviationFrequency(frequency_khz)) {
        return "USB"; // Aviation HF uses USB, not AM
    } else if (isMaritimeFrequency(frequency_khz)) {
        return "SSB";
    }
    
    return "UNKNOWN";
}

// Aviation HF Radio Model Implementation
FGCom_radiowaveModel_AviationHF::FGCom_radiowaveModel_AviationHF(float altitude_ft, const std::string& type) 
    : aircraft_altitude_ft(altitude_ft), aircraft_type(type) {
    FGCom_NonAmateurHF::initialize();
}

std::string FGCom_radiowaveModel_AviationHF::getType() {
    return "AVIATION_HF";
}

bool FGCom_radiowaveModel_AviationHF::isCompatible(FGCom_radiowaveModel *otherModel) {
    return otherModel->getType() == "AVIATION_HF" || otherModel->getType() == "HF";
}

fgcom_radiowave_signal FGCom_radiowaveModel_AviationHF::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    struct fgcom_radiowave_signal signal;
    signal.quality = 0.0;
    
    // Get surface distance
    double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // Calculate aviation-specific propagation
    float freq_khz = std::stof(this->conv_chan2freq(std::to_string(current_radio_frequency_in_MHz * 1000)));
    float aviation_factor = FGCom_NonAmateurHF::calculateAviationPropagation(freq_khz, dist, alt1, alt2);
    
    // Calculate whip antenna efficiency
    float antenna_efficiency = calculateWhipAntennaEfficiency(freq_khz);
    
    // Calculate high altitude effects
    float altitude_effect = FGCom_NonAmateurHF::calculateHighAltitudeEffects(aircraft_altitude_ft, dist);
    
    // Calculate USB modulation effects
    float usb_effect = calculateUSBModulationEffects(freq_khz);
    
    // Base signal calculation
    float base_signal = (power * 1000.0) / (dist * dist + 1.0);
    base_signal = std::max(0.0f, std::min(1.0f, base_signal / 100.0f));
    
    // Apply all effects
    signal.quality = base_signal * aviation_factor * antenna_efficiency * altitude_effect * usb_effect;
    signal.quality = std::max(0.0f, std::min(1.0f, signal.quality));
    
    // Calculate direction and vertical angle
    signal.direction = this->getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
    
    return signal;
}

std::string FGCom_radiowaveModel_AviationHF::conv_chan2freq(std::string frq) {
    return FGCom_NonAmateurHF::aviationChannelToFreq(frq) > 0.0 ? 
           std::to_string(FGCom_NonAmateurHF::aviationChannelToFreq(frq)) : frq;
}

std::string FGCom_radiowaveModel_AviationHF::conv_freq2chan(std::string frq) {
    float freq_khz = std::stof(frq);
    return FGCom_NonAmateurHF::aviationFreqToChannel(freq_khz);
}

float FGCom_radiowaveModel_AviationHF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    float freq1 = std::stof(r1.frequency);
    float freq2 = std::stof(r2.frequency);
    
    // Check if both are aviation frequencies
    if (FGCom_NonAmateurHF::isAviationFrequency(freq1) && 
        FGCom_NonAmateurHF::isAviationFrequency(freq2)) {
        
        float diff = std::abs(freq1 - freq2);
        if (diff < 0.1) {
            return 1.0f; // Perfect match
        } else if (diff < 3.0) {
            return 1.0f - (diff / 3.0f); // Gradual degradation
        }
    }
    
    return 0.0f;
}

float FGCom_radiowaveModel_AviationHF::calculateWhipAntennaEfficiency(float frequency_khz) {
    return FGCom_NonAmateurHF::calculateWhipAntennaEfficiency(frequency_khz, aircraft_altitude_ft);
}

float FGCom_radiowaveModel_AviationHF::calculateHighAltitudePropagation(double distance_km, float frequency_khz) {
    return FGCom_NonAmateurHF::calculateHighAltitudeEffects(aircraft_altitude_ft, distance_km);
}

float FGCom_radiowaveModel_AviationHF::calculateUSBModulationEffects(float frequency_khz) {
    // USB modulation characteristics for aviation HF
    float usb_factor = 1.0;
    
    // USB is more efficient than AM
    usb_factor *= 1.1;
    
    // USB has narrower bandwidth (3kHz vs 6kHz for AM)
    usb_factor *= 1.05;
    
    // Check if this is a MWARA frequency for additional effects
    if (FGCom_NonAmateurHF::isMWARAFrequency(frequency_khz)) {
        usb_factor *= 1.1; // MWARA frequencies are optimized for long-range
    }
    
    return usb_factor;
}

// Maritime HF Radio Model Implementation
FGCom_radiowaveModel_MaritimeHF::FGCom_radiowaveModel_MaritimeHF(const std::string& type, bool duplex) 
    : vessel_type(type), is_duplex_operation(duplex) {
    FGCom_NonAmateurHF::initialize();
}

std::string FGCom_radiowaveModel_MaritimeHF::getType() {
    return "MARITIME_HF";
}

bool FGCom_radiowaveModel_MaritimeHF::isCompatible(FGCom_radiowaveModel *otherModel) {
    return otherModel->getType() == "MARITIME_HF" || otherModel->getType() == "HF";
}

fgcom_radiowave_signal FGCom_radiowaveModel_MaritimeHF::getSignal(double lat1, double lon1, float alt1, double lat2, double lon2, float alt2, float power) {
    struct fgcom_radiowave_signal signal;
    signal.quality = 0.0;
    
    // Get surface distance
    double dist = this->getSurfaceDistance(lat1, lon1, lat2, lon2);
    
    // Calculate maritime-specific propagation
    float freq_khz = std::stof(this->conv_chan2freq(std::to_string(current_radio_frequency_in_MHz * 1000)));
    float maritime_factor = FGCom_NonAmateurHF::calculateMaritimePropagation(freq_khz, dist, alt1, alt2);
    
    // Calculate sea path effects
    float sea_effect = calculateSeaPathPropagation(dist, freq_khz);
    
    // Calculate channel effects
    fgcom_maritime_channel channel = FGCom_NonAmateurHF::getMaritimeChannelByFrequency(freq_khz);
    float channel_effect = calculateMaritimeChannelEffects(channel.channel_number);
    
    // Calculate duplex operation effects
    float duplex_effect = calculateDuplexOperationEffects(is_duplex_operation);
    
    // Base signal calculation
    float base_signal = (power * 1000.0) / (dist * dist + 1.0);
    base_signal = std::max(0.0f, std::min(1.0f, base_signal / 100.0f));
    
    // Apply all effects
    signal.quality = base_signal * maritime_factor * sea_effect * channel_effect * duplex_effect;
    signal.quality = std::max(0.0f, std::min(1.0f, signal.quality));
    
    // Calculate direction and vertical angle
    signal.direction = this->getDirection(lat1, lon1, lat2, lon2);
    signal.verticalAngle = this->degreeAboveHorizon(dist, alt2-alt1);
    
    return signal;
}

std::string FGCom_radiowaveModel_MaritimeHF::conv_chan2freq(std::string frq) {
    return FGCom_NonAmateurHF::maritimeChannelToFreq(frq) > 0.0 ? 
           std::to_string(FGCom_NonAmateurHF::maritimeChannelToFreq(frq)) : frq;
}

std::string FGCom_radiowaveModel_MaritimeHF::conv_freq2chan(std::string frq) {
    float freq_khz = std::stof(frq);
    return FGCom_NonAmateurHF::maritimeFreqToChannel(freq_khz);
}

float FGCom_radiowaveModel_MaritimeHF::getFrqMatch(fgcom_radio r1, fgcom_radio r2) {
    float freq1 = std::stof(r1.frequency);
    float freq2 = std::stof(r2.frequency);
    
    // Check if both are maritime frequencies
    if (FGCom_NonAmateurHF::isMaritimeFrequency(freq1) && 
        FGCom_NonAmateurHF::isMaritimeFrequency(freq2)) {
        
        fgcom_maritime_channel ch1 = FGCom_NonAmateurHF::getMaritimeChannelByFrequency(freq1);
        fgcom_maritime_channel ch2 = FGCom_NonAmateurHF::getMaritimeChannelByFrequency(freq2);
        
        if (ch1.channel_number == ch2.channel_number) {
            return 1.0f; // Same channel
        } else if (ch1.band == ch2.band) {
            return 0.8f; // Same band, different channel
        }
    }
    
    return 0.0f;
}

float FGCom_radiowaveModel_MaritimeHF::calculateSeaPathPropagation(double distance_km, float frequency_khz) {
    return FGCom_NonAmateurHF::calculateSeaPathEffects(distance_km, 0.0); // Assume sea level
}

float FGCom_radiowaveModel_MaritimeHF::calculateMaritimeChannelEffects(int channel_number) {
    // Different channels may have different propagation characteristics
    float effect = 1.0;
    
    if (channel_number >= 400 && channel_number <= 430) {
        // 4MHz band - good for regional
        effect = 1.0;
    } else if (channel_number >= 600 && channel_number <= 610) {
        // 6MHz band - good for medium range
        effect = 0.95;
    } else if (channel_number >= 800 && channel_number <= 840) {
        // 8MHz band - good for long range
        effect = 0.9;
    } else if (channel_number >= 1200 && channel_number <= 1240) {
        // 12MHz band - excellent for long range
        effect = 1.1;
    } else if (channel_number >= 1600 && channel_number <= 1660) {
        // 16MHz band - excellent for long range
        effect = 1.1;
    } else if (channel_number >= 1800 && channel_number <= 1820) {
        // 18MHz band - good for long range
        effect = 1.0;
    } else if (channel_number >= 2200 && channel_number <= 2260) {
        // 22MHz band - good for long range
        effect = 1.0;
    } else if (channel_number >= 2500 && channel_number <= 2510) {
        // 25MHz band - good for long range
        effect = 1.0;
    }
    
    return effect;
}

float FGCom_radiowaveModel_MaritimeHF::calculateDuplexOperationEffects(bool is_duplex) {
    if (is_duplex) {
        return 1.0; // Normal duplex operation
    } else {
        return 0.9; // Simplex operation may have slightly reduced efficiency
    }
}
