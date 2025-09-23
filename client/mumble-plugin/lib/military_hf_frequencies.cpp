#include "military_hf_frequencies.h"
#include <algorithm>
#include <iostream>

namespace FGCom_MilitaryHF {

    // NATO Military HF Frequencies Implementation
    
    // NATO Bookshelf Network Frequencies (kHz)
    const std::vector<double> NATO_HF_Frequencies::BOOKSHELF_NETWORK = {
        3178.0,    // NATO Bookshelf Network
        4519.0,    // NATO Bookshelf Network
        5218.0,    // NATO Bookshelf Network
        5763.5,    // NATO Bookshelf Network
        6865.0,    // NATO Bookshelf Network
        6932.5,    // NATO Bookshelf Network
        8046.0,    // NATO Bookshelf Network
        8087.0,    // NATO Bookshelf Network
        9118.5,    // NATO Bookshelf Network
        9260.0,    // NATO Bookshelf Network
        11173.0,   // NATO Bookshelf Network
        15048.0    // NATO Bookshelf Network
    };
    
    // NATO E-3 AWACS Network Frequencies (kHz)
    const std::vector<double> NATO_HF_Frequencies::AWACS_NETWORK = {
        3900.0     // NATO E-3 AWACS Network
    };
    
    // NATO Naval Command Network Frequencies (kHz)
    const std::vector<double> NATO_HF_Frequencies::NAVAL_COMMAND = {
        10315.0    // NATO Naval Command Network
    };
    
    // NATO Naval Hotel Tracking Network Frequencies (kHz)
    const std::vector<double> NATO_HF_Frequencies::NAVAL_TRACKING = {
        16442.4    // NATO Naval Hotel Tracking Network
    };
    
    // U.S. Air Force HFGCS Frequencies (kHz)
    const std::vector<double> NATO_HF_Frequencies::HFGCS_FREQUENCIES = {
        4724.0,    // HFGCS Nighttime Primary
        6739.0,    // HFGCS
        8992.0,    // HFGCS
        11175.0,   // HFGCS Daytime Primary
        13200.0,   // HFGCS
        15016.0    // HFGCS
    };
    
    // NATO Tactical HF Bands (kHz) - start and end frequencies
    const std::vector<std::pair<double, double>> NATO_HF_Frequencies::TACTICAL_BANDS = {
        {2000.0, 3000.0},   // 2-3 MHz tactical band
        {3000.0, 4000.0},   // 3-4 MHz tactical band
        {4000.0, 5000.0},   // 4-5 MHz tactical band
        {5000.0, 6000.0},   // 5-6 MHz tactical band
        {6000.0, 7000.0},   // 6-7 MHz tactical band
        {7000.0, 8000.0},   // 7-8 MHz tactical band
        {8000.0, 9000.0},   // 8-9 MHz tactical band
        {9000.0, 10000.0},  // 9-10 MHz tactical band
        {10000.0, 12000.0}, // 10-12 MHz tactical band
        {12000.0, 15000.0}, // 12-15 MHz tactical band
        {15000.0, 20000.0}, // 15-20 MHz tactical band
        {20000.0, 30000.0}  // 20-30 MHz tactical band
    };

    // Eastern Bloc/Soviet Military HF Frequencies Implementation
    
    // Soviet Military HF Bands (kHz) - based on R-832, R-855 radio systems
    const std::vector<std::pair<double, double>> EasternBloc_HF_Frequencies::SOVIET_TACTICAL_BANDS = {
        {2000.0, 3000.0},   // 2-3 MHz Soviet tactical
        {3000.0, 4000.0},   // 3-4 MHz Soviet tactical
        {4000.0, 5000.0},   // 4-5 MHz Soviet tactical
        {5000.0, 6000.0},   // 5-6 MHz Soviet tactical
        {6000.0, 7000.0},   // 6-7 MHz Soviet tactical
        {7000.0, 8000.0},   // 7-8 MHz Soviet tactical
        {8000.0, 9000.0},   // 8-9 MHz Soviet tactical
        {9000.0, 10000.0},  // 9-10 MHz Soviet tactical
        {10000.0, 12000.0}, // 10-12 MHz Soviet tactical
        {12000.0, 15000.0}, // 12-15 MHz Soviet tactical
        {15000.0, 18000.0}  // 15-18 MHz Soviet tactical (R-832 limit)
    };
    
    // Warsaw Pact HF Frequencies (kHz) - commonly monitored frequencies
    const std::vector<double> EasternBloc_HF_Frequencies::WARSAW_PACT_FREQUENCIES = {
        3000.0,    // Warsaw Pact tactical
        4000.0,    // Warsaw Pact tactical
        5000.0,    // Warsaw Pact tactical
        6000.0,    // Warsaw Pact tactical
        7000.0,    // Warsaw Pact tactical
        8000.0,    // Warsaw Pact tactical
        9000.0,    // Warsaw Pact tactical
        10000.0,   // Warsaw Pact tactical
        11000.0,   // Warsaw Pact tactical
        12000.0,   // Warsaw Pact tactical
        13000.0,   // Warsaw Pact tactical
        14000.0,   // Warsaw Pact tactical
        15000.0,   // Warsaw Pact tactical
        16000.0,   // Warsaw Pact tactical
        17000.0    // Warsaw Pact tactical
    };
    
    // Soviet Naval HF Frequencies (kHz)
    const std::vector<double> EasternBloc_HF_Frequencies::SOVIET_NAVAL_FREQUENCIES = {
        4000.0,    // Soviet naval tactical
        6000.0,    // Soviet naval tactical
        8000.0,    // Soviet naval tactical
        10000.0,   // Soviet naval tactical
        12000.0,   // Soviet naval tactical
        14000.0,   // Soviet naval tactical
        16000.0    // Soviet naval tactical
    };
    
    // Soviet Air Force HF Frequencies (kHz)
    const std::vector<double> EasternBloc_HF_Frequencies::SOVIET_AIR_FORCE_FREQUENCIES = {
        3000.0,    // Soviet air force tactical
        5000.0,    // Soviet air force tactical
        7000.0,    // Soviet air force tactical
        9000.0,    // Soviet air force tactical
        11000.0,   // Soviet air force tactical
        13000.0,   // Soviet air force tactical
        15000.0    // Soviet air force tactical
    };

    // Military Radio Systems Implementation
    
    // NATO Radio Systems
    const std::string MilitaryRadioSystems::NATO_Radios::AN_ARC_190 = "AN/ARC-190";
    const std::string MilitaryRadioSystems::NATO_Radios::AN_ARC_131 = "AN/ARC-131";
    const std::string MilitaryRadioSystems::NATO_Radios::AN_ARC_186 = "AN/ARC-186";
    const std::string MilitaryRadioSystems::NATO_Radios::AN_ARC_164 = "AN/ARC-164";
    const std::string MilitaryRadioSystems::NATO_Radios::SINCGARS = "SINCGARS";
    
    // Soviet/Eastern Bloc Radio Systems
    const std::string MilitaryRadioSystems::Soviet_Radios::R_832 = "R-832";
    const std::string MilitaryRadioSystems::Soviet_Radios::R_855 = "R-855";
    const std::string MilitaryRadioSystems::Soviet_Radios::R_123M = "R-123M";
    const std::string MilitaryRadioSystems::Soviet_Radios::R_860 = "R-860";
    const std::string MilitaryRadioSystems::Soviet_Radios::SPU_7 = "SPU-7";

    // MilitaryHFAnalyzer Implementation
    
    std::vector<double> MilitaryHFAnalyzer::getAllNATOFrequencies() {
        std::vector<double> all_frequencies;
        
        // Add all NATO frequency lists
        all_frequencies.insert(all_frequencies.end(), 
                              NATO_HF_Frequencies::BOOKSHELF_NETWORK.begin(),
                              NATO_HF_Frequencies::BOOKSHELF_NETWORK.end());
        all_frequencies.insert(all_frequencies.end(),
                              NATO_HF_Frequencies::AWACS_NETWORK.begin(),
                              NATO_HF_Frequencies::AWACS_NETWORK.end());
        all_frequencies.insert(all_frequencies.end(),
                              NATO_HF_Frequencies::NAVAL_COMMAND.begin(),
                              NATO_HF_Frequencies::NAVAL_COMMAND.end());
        all_frequencies.insert(all_frequencies.end(),
                              NATO_HF_Frequencies::NAVAL_TRACKING.begin(),
                              NATO_HF_Frequencies::NAVAL_TRACKING.end());
        all_frequencies.insert(all_frequencies.end(),
                              NATO_HF_Frequencies::HFGCS_FREQUENCIES.begin(),
                              NATO_HF_Frequencies::HFGCS_FREQUENCIES.end());
        
        // Sort and remove duplicates
        std::sort(all_frequencies.begin(), all_frequencies.end());
        all_frequencies.erase(std::unique(all_frequencies.begin(), all_frequencies.end()),
                             all_frequencies.end());
        
        return all_frequencies;
    }
    
    std::vector<double> MilitaryHFAnalyzer::getAllEasternBlocFrequencies() {
        std::vector<double> all_frequencies;
        
        // Add all Eastern Bloc frequency lists
        all_frequencies.insert(all_frequencies.end(),
                              EasternBloc_HF_Frequencies::WARSAW_PACT_FREQUENCIES.begin(),
                              EasternBloc_HF_Frequencies::WARSAW_PACT_FREQUENCIES.end());
        all_frequencies.insert(all_frequencies.end(),
                              EasternBloc_HF_Frequencies::SOVIET_NAVAL_FREQUENCIES.begin(),
                              EasternBloc_HF_Frequencies::SOVIET_NAVAL_FREQUENCIES.end());
        all_frequencies.insert(all_frequencies.end(),
                              EasternBloc_HF_Frequencies::SOVIET_AIR_FORCE_FREQUENCIES.begin(),
                              EasternBloc_HF_Frequencies::SOVIET_AIR_FORCE_FREQUENCIES.end());
        
        // Sort and remove duplicates
        std::sort(all_frequencies.begin(), all_frequencies.end());
        all_frequencies.erase(std::unique(all_frequencies.begin(), all_frequencies.end()),
                             all_frequencies.end());
        
        return all_frequencies;
    }
    
    std::vector<std::pair<double, double>> MilitaryHFAnalyzer::getFrequencyBands(const std::string& system) {
        if (system == "NATO") {
            return NATO_HF_Frequencies::TACTICAL_BANDS;
        } else if (system == "Soviet" || system == "EasternBloc") {
            return EasternBloc_HF_Frequencies::SOVIET_TACTICAL_BANDS;
        }
        return {};
    }
    
    bool MilitaryHFAnalyzer::isNATOFrequency(double frequency_khz) {
        auto frequencies = getAllNATOFrequencies();
        return std::find(frequencies.begin(), frequencies.end(), frequency_khz) != frequencies.end();
    }
    
    bool MilitaryHFAnalyzer::isEasternBlocFrequency(double frequency_khz) {
        auto frequencies = getAllEasternBlocFrequencies();
        return std::find(frequencies.begin(), frequencies.end(), frequency_khz) != frequencies.end();
    }
    
    double MilitaryHFAnalyzer::getPrimaryFrequency(const std::string& role, const std::string& alliance) {
        if (alliance == "NATO") {
            if (role == "tactical") return 8000.0;      // 8 MHz NATO tactical
            if (role == "strategic") return 11175.0;    // 11.175 MHz HFGCS
            if (role == "naval") return 10315.0;        // 10.315 MHz NATO naval
            if (role == "awacs") return 3900.0;         // 3.9 MHz AWACS
        } else if (alliance == "Soviet" || alliance == "EasternBloc") {
            if (role == "tactical") return 7000.0;      // 7 MHz Soviet tactical
            if (role == "strategic") return 12000.0;    // 12 MHz Soviet strategic
            if (role == "naval") return 8000.0;         // 8 MHz Soviet naval
            if (role == "air_force") return 9000.0;     // 9 MHz Soviet air force
        }
        return 0.0;
    }
    
    std::vector<double> MilitaryHFAnalyzer::getPatternAnalysisFrequencies(const std::string& vehicle_type, const std::string& alliance) {
        std::vector<double> frequencies;
        
        if (alliance == "NATO") {
            if (vehicle_type == "aircraft") {
                frequencies = {3900.0, 8000.0, 11175.0, 15016.0}; // AWACS, tactical, HFGCS, strategic
            } else if (vehicle_type == "ground_vehicle") {
                frequencies = {6000.0, 8000.0, 10000.0}; // Tactical ground frequencies
            } else if (vehicle_type == "naval") {
                frequencies = {8000.0, 10315.0, 16442.4}; // Naval command and tracking
            }
        } else if (alliance == "Soviet" || alliance == "EasternBloc") {
            if (vehicle_type == "aircraft") {
                frequencies = {5000.0, 7000.0, 9000.0, 11000.0}; // Soviet air force frequencies
            } else if (vehicle_type == "ground_vehicle") {
                frequencies = {4000.0, 6000.0, 8000.0}; // Soviet ground tactical
            } else if (vehicle_type == "naval") {
                frequencies = {6000.0, 8000.0, 12000.0}; // Soviet naval frequencies
            }
        }
        
        return frequencies;
    }
    
    double MilitaryHFAnalyzer::getChannelSpacing(double frequency_khz, const std::string& alliance) {
        if (alliance == "NATO") {
            return Constants::NATO_CHANNEL_SPACING; // 3 kHz
        } else if (alliance == "Soviet" || alliance == "EasternBloc") {
            return Constants::SOVIET_CHANNEL_SPACING; // 1 kHz
        }
        return 3.0; // Default 3 kHz
    }
    
    std::string MilitaryHFAnalyzer::getModulationType(double frequency_khz, const std::string& alliance) {
        // Most military HF uses USB (Upper Sideband)
        if (frequency_khz < 10000.0) {
            return "USB"; // Lower HF bands typically USB
        } else {
            return "USB"; // Higher HF bands also USB
        }
    }
    
    double MilitaryHFAnalyzer::getTypicalPowerWatts(double frequency_khz, const std::string& alliance) {
        if (alliance == "NATO") {
            if (frequency_khz < 10000.0) {
                return Constants::NATO_TACTICAL_POWER; // 400W tactical
            } else {
                return Constants::NATO_STRATEGIC_POWER; // 1kW strategic
            }
        } else if (alliance == "Soviet" || alliance == "EasternBloc") {
            if (frequency_khz < 10000.0) {
                return Constants::SOVIET_TACTICAL_POWER; // 300W tactical
            } else {
                return Constants::SOVIET_STRATEGIC_POWER; // 800W strategic
            }
        }
        return 400.0; // Default 400W
    }

    // Vehicle Frequency Assignments Implementation
    
    // NATO Aircraft frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::Aircraft::NATO_AIRCRAFT = {
        {"C-130_Hercules", {6000.0, 8000.0, 10000.0, 12000.0}},
        {"B-737", {8000.0, 11175.0, 15016.0}},
        {"UH-1_Huey", {3000.0, 5000.0, 7000.0, 9000.0}},
        {"F-16", {4000.0, 6000.0, 8000.0, 10000.0}},
        {"E-3_AWACS", {3900.0, 6000.0, 8000.0}}
    };
    
    // Soviet Aircraft frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::Aircraft::SOVIET_AIRCRAFT = {
        {"Tu-95_Bear", {5000.0, 7000.0, 9000.0, 11000.0, 13000.0}},
        {"Mi-4_Hound", {3000.0, 5000.0, 7000.0, 9000.0}},
        {"MiG-21", {4000.0, 6000.0, 8000.0, 10000.0}},
        {"Su-27", {5000.0, 7000.0, 9000.0, 11000.0}}
    };
    
    // NATO Ground Vehicles frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::GroundVehicles::NATO_GROUND = {
        {"NATO_Jeep", {3000.0, 5000.0, 7000.0, 9000.0}},
        {"M1_Abrams", {4000.0, 6000.0, 8000.0, 10000.0}},
        {"Bradley", {3000.0, 5000.0, 7000.0, 9000.0}}
    };
    
    // Soviet Ground Vehicles frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::GroundVehicles::SOVIET_GROUND = {
        {"UAZ-469", {3000.0, 5000.0, 7000.0, 9000.0}},
        {"T-72", {4000.0, 6000.0, 8000.0, 10000.0}},
        {"BMP", {3000.0, 5000.0, 7000.0, 9000.0}}
    };
    
    // NATO Naval frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::Naval::NATO_NAVAL = {
        {"Destroyer", {8000.0, 10315.0, 12000.0, 15000.0}},
        {"Frigate", {6000.0, 8000.0, 10000.0, 12000.0}},
        {"Submarine", {4000.0, 6000.0, 8000.0, 10000.0}}
    };
    
    // Soviet Naval frequency assignments
    const std::map<std::string, std::vector<double>> VehicleFrequencyAssignments::Naval::SOVIET_NAVAL = {
        {"Destroyer", {6000.0, 8000.0, 10000.0, 12000.0}},
        {"Frigate", {4000.0, 6000.0, 8000.0, 10000.0}},
        {"Submarine", {3000.0, 5000.0, 7000.0, 9000.0}}
    };

    // Military Roles Implementation
    
    // Command and Control frequencies
    const std::vector<double> MilitaryRoles::COMMAND_CONTROL_NATO = {
        3900.0,    // AWACS
        8000.0,    // Tactical command
        11175.0,   // HFGCS
        15016.0    // Strategic command
    };
    
    const std::vector<double> MilitaryRoles::COMMAND_CONTROL_SOVIET = {
        5000.0,    // Soviet command
        7000.0,    // Soviet tactical command
        9000.0,    // Soviet air command
        12000.0    // Soviet strategic command
    };
    
    // Tactical frequencies
    const std::vector<double> MilitaryRoles::TACTICAL_NATO = {
        6000.0,    // NATO tactical
        8000.0,    // NATO tactical
        10000.0    // NATO tactical
    };
    
    const std::vector<double> MilitaryRoles::TACTICAL_SOVIET = {
        4000.0,    // Soviet tactical
        6000.0,    // Soviet tactical
        8000.0     // Soviet tactical
    };
    
    // Emergency frequencies
    const std::vector<double> MilitaryRoles::EMERGENCY_NATO = {
        4724.0,    // HFGCS emergency
        11175.0    // HFGCS emergency
    };
    
    const std::vector<double> MilitaryRoles::EMERGENCY_SOVIET = {
        5000.0,    // Soviet emergency
        7000.0     // Soviet emergency
    };
    
    // Strategic frequencies
    const std::vector<double> MilitaryRoles::STRATEGIC_NATO = {
        11175.0,   // HFGCS strategic
        15016.0,   // HFGCS strategic
        16442.4    // NATO naval strategic
    };
    
    const std::vector<double> MilitaryRoles::STRATEGIC_SOVIET = {
        10000.0,   // Soviet strategic
        12000.0,   // Soviet strategic
        15000.0    // Soviet strategic
    };

} // namespace FGCom_MilitaryHF
