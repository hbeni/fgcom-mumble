#include "advanced_modulation.h"
#include <algorithm>
#include <cmath>
#include <iostream>

// Static member initialization
bool FGCom_AdvancedModulation::initialized = false;
std::map<std::string, DSBConfig> FGCom_AdvancedModulation::dsb_configs;
std::map<std::string, ISBConfig> FGCom_AdvancedModulation::isb_configs;
std::map<std::string, VSBConfig> FGCom_AdvancedModulation::vsb_configs;
std::map<std::string, NFMConfig> FGCom_AdvancedModulation::nfm_configs;

bool FGCom_AdvancedModulation::initialize() {
    if (initialized) return true;
    
    // Initialize DSB configurations
    DSBConfig amateur_dsb;
    amateur_dsb.bandwidth_hz = 6000.0;
    amateur_dsb.carrier_suppressed = true;
    amateur_dsb.sideband_power_ratio = 1.0;
    amateur_dsb.application = "AMATEUR";
    dsb_configs["AMATEUR"] = amateur_dsb;
    
    DSBConfig maritime_dsb;
    maritime_dsb.bandwidth_hz = 6000.0;
    maritime_dsb.carrier_suppressed = true;
    maritime_dsb.sideband_power_ratio = 1.0;
    maritime_dsb.application = "MARITIME";
    dsb_configs["MARITIME"] = maritime_dsb;
    
    // Initialize ISB configurations
    ISBConfig amateur_isb;
    amateur_isb.upper_bandwidth_hz = 3000.0;
    amateur_isb.lower_bandwidth_hz = 3000.0;
    amateur_isb.independent_control = true;
    amateur_isb.upper_application = "VOICE";
    amateur_isb.lower_application = "DATA";
    isb_configs["AMATEUR"] = amateur_isb;
    
    ISBConfig military_isb;
    military_isb.upper_bandwidth_hz = 3000.0;
    military_isb.lower_bandwidth_hz = 3000.0;
    military_isb.independent_control = true;
    military_isb.upper_application = "VOICE";
    military_isb.lower_application = "TELEMETRY";
    isb_configs["MILITARY"] = military_isb;
    
    // Initialize VSB configurations
    VSBConfig broadcast_vsb;
    broadcast_vsb.bandwidth_hz = 4000.0;
    broadcast_vsb.vestigial_bandwidth_hz = 1000.0;
    broadcast_vsb.carrier_present = true;
    broadcast_vsb.application = "BROADCAST";
    vsb_configs["BROADCAST"] = broadcast_vsb;
    
    VSBConfig amateur_vsb;
    amateur_vsb.bandwidth_hz = 4000.0;
    amateur_vsb.vestigial_bandwidth_hz = 1000.0;
    amateur_vsb.carrier_present = true;
    amateur_vsb.application = "AMATEUR";
    vsb_configs["AMATEUR"] = amateur_vsb;
    
    // Initialize NFM configurations
    NFMConfig maritime_nfm;
    maritime_nfm.bandwidth_hz = 12500.0;
    maritime_nfm.deviation_hz = 2500.0;
    maritime_nfm.preemphasis = true;
    maritime_nfm.application = "MARITIME";
    maritime_nfm.squelch_required = true;
    nfm_configs["MARITIME"] = maritime_nfm;
    
    NFMConfig aviation_nfm;
    aviation_nfm.bandwidth_hz = 12500.0;
    aviation_nfm.deviation_hz = 2500.0;
    aviation_nfm.preemphasis = true;
    aviation_nfm.application = "AVIATION";
    aviation_nfm.squelch_required = true;
    nfm_configs["AVIATION"] = aviation_nfm;
    
    NFMConfig amateur_nfm;
    amateur_nfm.bandwidth_hz = 12500.0;
    amateur_nfm.deviation_hz = 2500.0;
    amateur_nfm.preemphasis = true;
    amateur_nfm.application = "AMATEUR";
    amateur_nfm.squelch_required = true;
    nfm_configs["AMATEUR"] = amateur_nfm;
    
    initialized = true;
    return true;
}

// DSB (Double Sideband) functions
bool FGCom_AdvancedModulation::isDSBFrequency(double frequency_khz) {
    if (!initialized) initialize();
    
    // DSB is typically used in HF bands (1.6-30 MHz)
    // and some VHF applications
    return (frequency_khz >= 1600.0 && frequency_khz <= 30000.0) ||
           (frequency_khz >= 30000.0 && frequency_khz <= 150000.0);
}

DSBConfig FGCom_AdvancedModulation::getDSBConfig(const std::string& application) {
    if (!initialized) initialize();
    
    auto it = dsb_configs.find(application);
    if (it != dsb_configs.end()) {
        return it->second;
    }
    
    // Return default amateur configuration
    return dsb_configs["AMATEUR"];
}

double FGCom_AdvancedModulation::calculateDSBBandwidth(double frequency_khz) {
    if (!initialized) initialize();
    
    // DSB bandwidth is typically 6 kHz
    // May vary slightly with frequency
    if (frequency_khz < 10000.0) {
        return 6000.0; // 6 kHz for lower HF
    } else {
        return 6000.0; // 6 kHz for higher HF
    }
}

double FGCom_AdvancedModulation::calculateDSBPowerEfficiency(double frequency_khz) {
    // DSB is more efficient than AM but less than SSB
    // Efficiency depends on carrier suppression
    return 0.75; // 75% efficiency (compared to 50% for AM, 100% for SSB)
}

// ISB (Independent Sideband) functions
bool FGCom_AdvancedModulation::isISBFrequency(double frequency_khz) {
    if (!initialized) initialize();
    
    // ISB is used in HF bands, typically 3-30 MHz
    return frequency_khz >= 3000.0 && frequency_khz <= 30000.0;
}

ISBConfig FGCom_AdvancedModulation::getISBConfig(const std::string& application) {
    if (!initialized) initialize();
    
    auto it = isb_configs.find(application);
    if (it != isb_configs.end()) {
        return it->second;
    }
    
    // Return default amateur configuration
    return isb_configs["AMATEUR"];
}

double FGCom_AdvancedModulation::calculateISBBandwidth(double frequency_khz) {
    if (!initialized) initialize();
    
    // ISB total bandwidth is sum of both sidebands
    return 6000.0; // 3 kHz upper + 3 kHz lower = 6 kHz total
}

bool FGCom_AdvancedModulation::validateISBConfiguration(const ISBConfig& config) {
    // Validate ISB configuration parameters
    return config.upper_bandwidth_hz > 0.0 &&
           config.lower_bandwidth_hz > 0.0 &&
           config.upper_bandwidth_hz <= 5000.0 &&
           config.lower_bandwidth_hz <= 5000.0;
}

// VSB (Vestigial Sideband) functions
bool FGCom_AdvancedModulation::isVSBFrequency(double frequency_khz) {
    if (!initialized) initialize();
    
    // VSB is used in broadcast applications
    // Typically in HF and VHF bands
    return (frequency_khz >= 3000.0 && frequency_khz <= 30000.0) ||
           (frequency_khz >= 30000.0 && frequency_khz <= 300000.0);
}

VSBConfig FGCom_AdvancedModulation::getVSBConfig(const std::string& application) {
    if (!initialized) initialize();
    
    auto it = vsb_configs.find(application);
    if (it != vsb_configs.end()) {
        return it->second;
    }
    
    // Return default broadcast configuration
    return vsb_configs["BROADCAST"];
}

double FGCom_AdvancedModulation::calculateVSBBandwidth(double frequency_khz) {
    if (!initialized) initialize();
    
    // VSB bandwidth is typically 4 kHz
    return 4000.0;
}

double FGCom_AdvancedModulation::calculateVSBVestigialWidth(double frequency_khz) {
    if (!initialized) initialize();
    
    // Vestigial sideband is typically 1 kHz
    return 1000.0;
}

// General advanced modulation functions
std::string FGCom_AdvancedModulation::getModulationType(double frequency_khz) {
    if (!initialized) initialize();
    
    if (isDSBFrequency(frequency_khz)) return "DSB";
    if (isISBFrequency(frequency_khz)) return "ISB";
    if (isVSBFrequency(frequency_khz)) return "VSB";
    if (isNFMFrequency(frequency_khz)) return "NFM";
    
    return "UNKNOWN";
}

double FGCom_AdvancedModulation::calculateChannelSpacing(const std::string& mode) {
    if (!initialized) initialize();
    
    if (mode == "DSB") return 6.0; // 6 kHz spacing
    if (mode == "ISB") return 6.0; // 6 kHz spacing
    if (mode == "VSB") return 4.0; // 4 kHz spacing
    if (mode == "NFM") return 12.5; // 12.5 kHz spacing
    
    return 3.0; // Default SSB spacing
}

bool FGCom_AdvancedModulation::validateModulationMode(const std::string& mode) {
    std::vector<std::string> valid_modes = {"CW", "LSB", "USB", "NFM", "AM", "DSB", "ISB", "VSB"};
    return std::find(valid_modes.begin(), valid_modes.end(), mode) != valid_modes.end();
}

std::vector<std::string> FGCom_AdvancedModulation::getSupportedModes() {
    return {"CW", "LSB", "USB", "NFM", "AM", "DSB", "ISB", "VSB"};
}

// Signal processing functions
double FGCom_AdvancedModulation::calculateModulationIndex(const std::string& mode, double frequency_khz) {
    // Amateur radio modes
    if (mode == "CW") return 1.0; // Full modulation for CW
    if (mode == "LSB") return 1.0; // Full modulation for LSB
    if (mode == "USB") return 1.0; // Full modulation for USB
    if (mode == "NFM") return 0.9; // FM modulation index
    if (mode == "AM") return 0.8; // AM modulation index
    
    // Advanced modulation modes
    if (mode == "DSB") return 1.0; // Full modulation
    if (mode == "ISB") return 1.0; // Full modulation
    if (mode == "VSB") return 0.8; // Reduced modulation due to vestigial
    
    return 1.0;
}

double FGCom_AdvancedModulation::calculateSidebandSuppression(const std::string& mode) {
    // Amateur radio modes
    if (mode == "CW") return 0.0; // No sideband suppression for CW
    if (mode == "LSB") return 40.0; // 40 dB upper sideband suppression
    if (mode == "USB") return 40.0; // 40 dB lower sideband suppression
    if (mode == "NFM") return 0.0; // No sideband suppression for FM
    if (mode == "AM") return 0.0; // No sideband suppression for AM
    
    // Advanced modulation modes
    if (mode == "DSB") return 0.0; // No sideband suppression
    if (mode == "ISB") return 0.0; // No sideband suppression
    if (mode == "VSB") return 20.0; // 20 dB vestigial suppression
    
    return 0.0;
}

double FGCom_AdvancedModulation::calculateCarrierSuppression(const std::string& mode) {
    // Amateur radio modes
    if (mode == "CW") return 0.0; // No carrier suppression for CW
    if (mode == "LSB") return 40.0; // 40 dB carrier suppression for LSB
    if (mode == "USB") return 40.0; // 40 dB carrier suppression for USB
    if (mode == "NFM") return 0.0; // No carrier suppression for FM
    if (mode == "AM") return 0.0; // No carrier suppression for AM
    
    // Advanced modulation modes
    if (mode == "DSB") return 40.0; // 40 dB carrier suppression
    if (mode == "ISB") return 40.0; // 40 dB carrier suppression
    if (mode == "VSB") return 0.0; // No carrier suppression
    
    return 0.0;
}

// Frequency band validation
bool FGCom_AdvancedModulation::isAdvancedModulationBand(double frequency_khz) {
    return isDSBFrequency(frequency_khz) || 
           isISBFrequency(frequency_khz) || 
           isVSBFrequency(frequency_khz) ||
           isNFMFrequency(frequency_khz);
}

std::string FGCom_AdvancedModulation::getBandForFrequency(double frequency_khz) {
    if (frequency_khz >= 1600.0 && frequency_khz <= 2000.0) return "160m";
    if (frequency_khz >= 3500.0 && frequency_khz <= 4000.0) return "80m";
    if (frequency_khz >= 7000.0 && frequency_khz <= 7300.0) return "40m";
    if (frequency_khz >= 14000.0 && frequency_khz <= 14350.0) return "20m";
    if (frequency_khz >= 21000.0 && frequency_khz <= 21450.0) return "15m";
    if (frequency_khz >= 28000.0 && frequency_khz <= 29700.0) return "10m";
    
    return "UNKNOWN";
}

// Power and efficiency calculations
double FGCom_AdvancedModulation::calculatePowerEfficiency(const std::string& mode, double frequency_khz) {
    if (mode == "DSB") return 0.75; // 75% efficiency
    if (mode == "ISB") return 0.85; // 85% efficiency
    if (mode == "VSB") return 0.70; // 70% efficiency
    if (mode == "NFM") return 0.60; // 60% efficiency
    
    return 0.50; // Default AM efficiency
}

double FGCom_AdvancedModulation::calculateBandwidthEfficiency(const std::string& mode) {
    if (mode == "DSB") return 0.50; // 50% bandwidth efficiency
    if (mode == "ISB") return 0.50; // 50% bandwidth efficiency
    if (mode == "VSB") return 0.67; // 67% bandwidth efficiency
    if (mode == "NFM") return 0.40; // 40% bandwidth efficiency
    
    return 0.50; // Default efficiency
}

void FGCom_AdvancedModulation::shutdown() {
    dsb_configs.clear();
    isb_configs.clear();
    vsb_configs.clear();
    nfm_configs.clear();
    initialized = false;
}

// DSB signal processing functions
double FGCom_DSBProcessor::processDSBSignal(double input_signal, const DSBConfig& config) {
    // DSB signal processing simulation
    // In real implementation, this would handle actual signal processing
    return input_signal * config.sideband_power_ratio;
}

double FGCom_DSBProcessor::calculateDSBNoiseFloor(double frequency_khz) {
    // Calculate noise floor for DSB
    // Higher noise floor than SSB due to wider bandwidth
    return -120.0 + 10.0 * log10(frequency_khz / 1000.0);
}

double FGCom_DSBProcessor::calculateDSBSignalToNoiseRatio(double signal_power, double noise_power) {
    if (noise_power <= 0.0) return 100.0; // Very high SNR
    return 10.0 * log10(signal_power / noise_power);
}

bool FGCom_DSBProcessor::validateDSBParameters(const DSBConfig& config) {
    return config.bandwidth_hz > 0.0 && 
           config.bandwidth_hz <= 10000.0 &&
           config.sideband_power_ratio >= 0.0 &&
           config.sideband_power_ratio <= 2.0;
}

// ISB signal processing functions
double FGCom_ISBProcessor::processISBUpperSignal(double input_signal, const ISBConfig& config) {
    // Process upper sideband independently
    return input_signal * 0.5; // Half power for upper sideband
}

double FGCom_ISBProcessor::processISBLowerSignal(double input_signal, const ISBConfig& config) {
    // Process lower sideband independently
    return input_signal * 0.5; // Half power for lower sideband
}

double FGCom_ISBProcessor::calculateISBInterference(const ISBConfig& config) {
    // Calculate potential interference between sidebands
    return -30.0; // 30 dB isolation between sidebands
}

bool FGCom_ISBProcessor::validateISBParameters(const ISBConfig& config) {
    return config.upper_bandwidth_hz > 0.0 &&
           config.lower_bandwidth_hz > 0.0 &&
           config.upper_bandwidth_hz <= 5000.0 &&
           config.lower_bandwidth_hz <= 5000.0;
}

// VSB signal processing functions
double FGCom_VSBProcessor::processVSBSignal(double input_signal, const VSBConfig& config) {
    // Process VSB signal with vestigial sideband
    return input_signal * 0.8; // Reduced power due to vestigial
}

double FGCom_VSBProcessor::calculateVSBVestigialSuppression(const VSBConfig& config) {
    // Calculate vestigial sideband suppression
    return 20.0; // 20 dB suppression
}

double FGCom_VSBProcessor::calculateVSBChannelCapacity(const VSBConfig& config) {
    // Calculate channel capacity for VSB
    return config.bandwidth_hz * 0.8; // 80% of bandwidth usable
}

bool FGCom_VSBProcessor::validateVSBParameters(const VSBConfig& config) {
    return config.bandwidth_hz > 0.0 &&
           config.vestigial_bandwidth_hz > 0.0 &&
           config.bandwidth_hz <= 10000.0 &&
           config.vestigial_bandwidth_hz <= config.bandwidth_hz;
}

// NFM (Narrow FM) functions
bool FGCom_AdvancedModulation::isNFMFrequency(double frequency_khz) {
    if (!initialized) initialize();
    
    // NFM is used in VHF/UHF bands, typically 30-1000 MHz
    return frequency_khz >= 30000.0 && frequency_khz <= 1000000.0;
}

NFMConfig FGCom_AdvancedModulation::getNFMConfig(const std::string& application) {
    if (!initialized) initialize();
    
    auto it = nfm_configs.find(application);
    if (it != nfm_configs.end()) {
        return it->second;
    }
    
    // Return default maritime configuration
    return nfm_configs["MARITIME"];
}

double FGCom_AdvancedModulation::calculateNFMBandwidth(double frequency_khz) {
    if (!initialized) initialize();
    
    // NFM bandwidth is typically 12.5 kHz
    return 12500.0;
}

double FGCom_AdvancedModulation::calculateNFMDeviation(double frequency_khz) {
    if (!initialized) initialize();
    
    // NFM deviation is typically 2.5 kHz
    return 2500.0;
}

// NFM signal processing functions
double FGCom_NFMProcessor::processNFMSignal(double input_signal, const NFMConfig& config) {
    // NFM signal processing simulation
    // In real implementation, this would handle FM demodulation
    return input_signal * 0.9; // Slight reduction due to FM processing
}

double FGCom_NFMProcessor::calculateNFMSignalToNoiseRatio(double signal_power, double noise_power) {
    if (noise_power <= 0.0) return 100.0; // Very high SNR
    return 10.0 * log10(signal_power / noise_power);
}

double FGCom_NFMProcessor::calculateNFMSquelchThreshold(const NFMConfig& config) {
    // Calculate squelch threshold for NFM
    // Typically -100 dBm to -120 dBm depending on application
    if (config.application == "MARITIME") {
        return -110.0; // -110 dBm for maritime
    } else if (config.application == "AVIATION") {
        return -105.0; // -105 dBm for aviation
    } else {
        return -115.0; // -115 dBm for amateur
    }
}

bool FGCom_NFMProcessor::validateNFMParameters(const NFMConfig& config) {
    return config.bandwidth_hz > 0.0 &&
           config.deviation_hz > 0.0 &&
           config.bandwidth_hz <= 25000.0 &&
           config.deviation_hz <= 5000.0;
}
