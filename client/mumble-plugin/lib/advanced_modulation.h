#ifndef FGCOM_ADVANCED_MODULATION_H
#define FGCOM_ADVANCED_MODULATION_H

#include <string>
#include <vector>
#include <map>

/**
 * Advanced Modulation Modes for FGCom-mumble
 * 
 * This header defines support for advanced modulation modes including:
 * - DSB (Double Sideband)
 * - ISB (Independent Sideband) 
 * - VSB (Vestigial Sideband)
 */

// Modulation mode enumeration
enum class AdvancedModulationMode {
    DSB,    // Double Sideband
    ISB,    // Independent Sideband
    VSB,    // Vestigial Sideband
    NFM     // Narrow FM
};

// DSB (Double Sideband) configuration
struct DSBConfig {
    double bandwidth_hz = 6000.0;        // 6 kHz bandwidth
    bool carrier_suppressed = true;      // No carrier transmitted
    double sideband_power_ratio = 1.0; // Equal power in both sidebands
    std::string application = "AMATEUR"; // Primary application
};

// ISB (Independent Sideband) configuration
struct ISBConfig {
    double upper_bandwidth_hz = 3000.0; // Upper sideband bandwidth
    double lower_bandwidth_hz = 3000.0; // Lower sideband bandwidth
    bool independent_control = true;     // Independent sideband control
    std::string upper_application = "VOICE"; // Upper sideband use
    std::string lower_application = "DATA"; // Lower sideband use
};

// VSB (Vestigial Sideband) configuration
struct VSBConfig {
    double bandwidth_hz = 4000.0;        // 4 kHz bandwidth (compromise)
    double vestigial_bandwidth_hz = 1000.0; // Vestigial sideband width
    bool carrier_present = true;         // Carrier typically present
    std::string application = "BROADCAST"; // Primary application
};

// NFM (Narrow FM) configuration
struct NFMConfig {
    double bandwidth_hz = 12500.0;       // 12.5 kHz bandwidth
    double deviation_hz = 2500.0;        // 2.5 kHz deviation
    bool preemphasis = true;            // Preemphasis enabled
    std::string application = "MARITIME"; // Primary application
    bool squelch_required = true;        // Squelch required for operation
};

// Advanced modulation manager class
class FGCom_AdvancedModulation {
private:
    static bool initialized;
    static std::map<std::string, DSBConfig> dsb_configs;
    static std::map<std::string, ISBConfig> isb_configs;
    static std::map<std::string, VSBConfig> vsb_configs;
    static std::map<std::string, NFMConfig> nfm_configs;
    
public:
    // Initialize advanced modulation systems
    static bool initialize();
    
    // DSB (Double Sideband) functions
    static bool isDSBFrequency(double frequency_khz);
    static DSBConfig getDSBConfig(const std::string& application);
    static double calculateDSBBandwidth(double frequency_khz);
    static double calculateDSBPowerEfficiency(double frequency_khz);
    
    // ISB (Independent Sideband) functions
    static bool isISBFrequency(double frequency_khz);
    static ISBConfig getISBConfig(const std::string& application);
    static double calculateISBBandwidth(double frequency_khz);
    static bool validateISBConfiguration(const ISBConfig& config);
    
    // VSB (Vestigial Sideband) functions
    static bool isVSBFrequency(double frequency_khz);
    static VSBConfig getVSBConfig(const std::string& application);
    static double calculateVSBBandwidth(double frequency_khz);
    static double calculateVSBVestigialWidth(double frequency_khz);
    
    // NFM (Narrow FM) functions
    static bool isNFMFrequency(double frequency_khz);
    static NFMConfig getNFMConfig(const std::string& application);
    static double calculateNFMBandwidth(double frequency_khz);
    static double calculateNFMDeviation(double frequency_khz);
    
    // General advanced modulation functions
    static std::string getModulationType(double frequency_khz);
    static double calculateChannelSpacing(const std::string& mode);
    static bool validateModulationMode(const std::string& mode);
    static std::vector<std::string> getSupportedModes();
    
    // Signal processing functions
    static double calculateModulationIndex(const std::string& mode, double frequency_khz);
    static double calculateSidebandSuppression(const std::string& mode);
    static double calculateCarrierSuppression(const std::string& mode);
    
    // Frequency band validation
    static bool isAdvancedModulationBand(double frequency_khz);
    static std::string getBandForFrequency(double frequency_khz);
    
    // Power and efficiency calculations
    static double calculatePowerEfficiency(const std::string& mode, double frequency_khz);
    static double calculateBandwidthEfficiency(const std::string& mode);
    
    // Cleanup
    static void shutdown();
};

// DSB signal processing functions
class FGCom_DSBProcessor {
public:
    static double processDSBSignal(double input_signal, const DSBConfig& config);
    static double calculateDSBNoiseFloor(double frequency_khz);
    static double calculateDSBSignalToNoiseRatio(double signal_power, double noise_power);
    static bool validateDSBParameters(const DSBConfig& config);
};

// ISB signal processing functions
class FGCom_ISBProcessor {
public:
    static double processISBUpperSignal(double input_signal, const ISBConfig& config);
    static double processISBLowerSignal(double input_signal, const ISBConfig& config);
    static double calculateISBInterference(const ISBConfig& config);
    static bool validateISBParameters(const ISBConfig& config);
};

// VSB signal processing functions
class FGCom_VSBProcessor {
public:
    static double processVSBSignal(double input_signal, const VSBConfig& config);
    static double calculateVSBVestigialSuppression(const VSBConfig& config);
    static double calculateVSBChannelCapacity(const VSBConfig& config);
    static bool validateVSBParameters(const VSBConfig& config);
};

// NFM signal processing functions
class FGCom_NFMProcessor {
public:
    static double processNFMSignal(double input_signal, const NFMConfig& config);
    static double calculateNFMSignalToNoiseRatio(double signal_power, double noise_power);
    static double calculateNFMSquelchThreshold(const NFMConfig& config);
    static bool validateNFMParameters(const NFMConfig& config);
};

#endif // FGCOM_ADVANCED_MODULATION_H
