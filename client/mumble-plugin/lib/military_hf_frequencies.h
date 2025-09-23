#ifndef FGCOM_MILITARY_HF_FREQUENCIES_H
#define FGCOM_MILITARY_HF_FREQUENCIES_H

#include <vector>
#include <string>
#include <map>

// Military HF frequency bands and specific frequencies for antenna pattern analysis
namespace FGCom_MilitaryHF {

    // NATO Military HF Frequencies
    struct NATO_HF_Frequencies {
        // NATO Bookshelf Network Frequencies (kHz)
        static const std::vector<double> BOOKSHELF_NETWORK;
        
        // NATO E-3 AWACS Network Frequencies (kHz)
        static const std::vector<double> AWACS_NETWORK;
        
        // NATO Naval Command Network Frequencies (kHz)
        static const std::vector<double> NAVAL_COMMAND;
        
        // NATO Naval Hotel Tracking Network Frequencies (kHz)
        static const std::vector<double> NAVAL_TRACKING;
        
        // U.S. Air Force HFGCS (High Frequency Global Communications System) Frequencies (kHz)
        static const std::vector<double> HFGCS_FREQUENCIES;
        
        // NATO Tactical HF Bands (kHz)
        static const std::vector<std::pair<double, double>> TACTICAL_BANDS;
    };

    // Eastern Bloc/Soviet Military HF Frequencies
    struct EasternBloc_HF_Frequencies {
        // Soviet Military HF Bands (kHz) - based on R-832, R-855 radio systems
        static const std::vector<std::pair<double, double>> SOVIET_TACTICAL_BANDS;
        
        // Warsaw Pact HF Frequencies (kHz) - commonly monitored frequencies
        static const std::vector<double> WARSAW_PACT_FREQUENCIES;
        
        // Soviet Naval HF Frequencies (kHz)
        static const std::vector<double> SOVIET_NAVAL_FREQUENCIES;
        
        // Soviet Air Force HF Frequencies (kHz)
        static const std::vector<double> SOVIET_AIR_FORCE_FREQUENCIES;
    };

    // Military HF Radio Systems
    struct MilitaryRadioSystems {
        // NATO Radio Systems
        struct NATO_Radios {
            static const std::string AN_ARC_190;      // HF transceiver (2-30 MHz)
            static const std::string AN_ARC_131;      // VHF-FM tactical (30-88 MHz)
            static const std::string AN_ARC_186;      // VHF-AM aviation (118-156 MHz)
            static const std::string AN_ARC_164;      // UHF military (225-400 MHz)
            static const std::string SINCGARS;        // Advanced VHF with frequency hopping
        };
        
        // Soviet/Eastern Bloc Radio Systems
        struct Soviet_Radios {
            static const std::string R_832;           // HF transceiver (2-18 MHz)
            static const std::string R_855;           // Long-range HF communications
            static const std::string R_123M;          // VHF-FM communications (20-52 MHz)
            static const std::string R_860;           // VHF-FM tactical radio (30-48 MHz)
            static const std::string SPU_7;           // Intercom system
        };
    };

    // Utility functions for military HF frequency analysis
    class MilitaryHFAnalyzer {
    public:
        // Get all NATO HF frequencies for pattern analysis
        static std::vector<double> getAllNATOFrequencies();
        
        // Get all Eastern Bloc HF frequencies for pattern analysis
        static std::vector<double> getAllEasternBlocFrequencies();
        
        // Get frequency bands for specific military system
        static std::vector<std::pair<double, double>> getFrequencyBands(const std::string& system);
        
        // Check if frequency is in NATO military band
        static bool isNATOFrequency(double frequency_khz);
        
        // Check if frequency is in Eastern Bloc military band
        static bool isEasternBlocFrequency(double frequency_khz);
        
        // Get primary frequency for specific military role
        static double getPrimaryFrequency(const std::string& role, const std::string& alliance);
        
        // Get frequency list for antenna pattern generation
        static std::vector<double> getPatternAnalysisFrequencies(const std::string& vehicle_type, const std::string& alliance);
        
        // Get frequency spacing for military bands
        static double getChannelSpacing(double frequency_khz, const std::string& alliance);
        
        // Get modulation type for military frequency
        static std::string getModulationType(double frequency_khz, const std::string& alliance);
        
        // Get power levels for military frequency
        static double getTypicalPowerWatts(double frequency_khz, const std::string& alliance);
    };

    // Military HF frequency constants
    namespace Constants {
        // NATO HF Bands (kHz)
        const double NATO_HF_MIN = 2000.0;      // 2 MHz
        const double NATO_HF_MAX = 30000.0;     // 30 MHz
        
        // Soviet HF Bands (kHz) - typically 2-18 MHz
        const double SOVIET_HF_MIN = 2000.0;    // 2 MHz
        const double SOVIET_HF_MAX = 18000.0;   // 18 MHz
        
        // Channel spacing
        const double NATO_CHANNEL_SPACING = 3.0;    // 3 kHz
        const double SOVIET_CHANNEL_SPACING = 1.0;  // 1 kHz
        
        // Typical power levels (Watts)
        const double NATO_TACTICAL_POWER = 400.0;   // 400W typical
        const double SOVIET_TACTICAL_POWER = 300.0; // 300W typical
        const double NATO_STRATEGIC_POWER = 1000.0; // 1kW strategic
        const double SOVIET_STRATEGIC_POWER = 800.0; // 800W strategic
    }

    // Military vehicle frequency assignments
    struct VehicleFrequencyAssignments {
        // Aircraft frequency assignments
        struct Aircraft {
            // NATO Aircraft
            static const std::map<std::string, std::vector<double>> NATO_AIRCRAFT;
            
            // Soviet Aircraft
            static const std::map<std::string, std::vector<double>> SOVIET_AIRCRAFT;
        };
        
        // Ground vehicle frequency assignments
        struct GroundVehicles {
            // NATO Ground Vehicles
            static const std::map<std::string, std::vector<double>> NATO_GROUND;
            
            // Soviet Ground Vehicles
            static const std::map<std::string, std::vector<double>> SOVIET_GROUND;
        };
        
        // Naval frequency assignments
        struct Naval {
            // NATO Naval
            static const std::map<std::string, std::vector<double>> NATO_NAVAL;
            
            // Soviet Naval
            static const std::map<std::string, std::vector<double>> SOVIET_NAVAL;
        };
    };

    // Frequency allocation by military role
    struct MilitaryRoles {
        // Command and Control frequencies
        static const std::vector<double> COMMAND_CONTROL_NATO;
        static const std::vector<double> COMMAND_CONTROL_SOVIET;
        
        // Tactical frequencies
        static const std::vector<double> TACTICAL_NATO;
        static const std::vector<double> TACTICAL_SOVIET;
        
        // Emergency frequencies
        static const std::vector<double> EMERGENCY_NATO;
        static const std::vector<double> EMERGENCY_SOVIET;
        
        // Strategic frequencies
        static const std::vector<double> STRATEGIC_NATO;
        static const std::vector<double> STRATEGIC_SOVIET;
    };

} // namespace FGCom_MilitaryHF

#endif // FGCOM_MILITARY_HF_FREQUENCIES_H
