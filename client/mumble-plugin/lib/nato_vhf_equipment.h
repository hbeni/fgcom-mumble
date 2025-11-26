#ifndef FGCOM_NATO_VHF_EQUIPMENT_H
#define FGCOM_NATO_VHF_EQUIPMENT_H

#include <string>
#include <vector>
#include <map>
#include <cmath>

// NATO VHF Equipment Specifications
namespace NATO_VHF {

// AN/PRC-77 (Legacy VHF Radio)
struct AN_PRC77_Specs {
    static constexpr double FREQ_START_MHZ = 30.0;
    static constexpr double FREQ_END_MHZ = 87.975;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 2319;
    static constexpr double PORTABLE_POWER_WATTS = 2.0;
    static constexpr double VEHICLE_POWER_WATTS = 20.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
    static const std::string COUNTRY;
    static const std::string ALLIANCE;
};

// AN/PRC-148 (Multiband Inter/Intra Team Radio - MBITR)
struct AN_PRC148_Specs {
    static constexpr double FREQ_START_MHZ = 30.0;
    static constexpr double FREQ_END_MHZ = 87.975;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 2319;
    static constexpr double PORTABLE_POWER_WATTS = 2.0;
    static constexpr double VEHICLE_POWER_WATTS = 20.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
    static const std::string COUNTRY;
    static const std::string ALLIANCE;
    static constexpr bool ENCRYPTION_CAPABLE = true;
    static constexpr bool GPS_CAPABLE = true;
    static constexpr bool DATA_CAPABLE = true;
};

// AN/PRC-152 (Multiband Inter/Intra Team Radio - MBITR II)
struct AN_PRC152_Specs {
    static constexpr double FREQ_START_MHZ = 30.0;
    static constexpr double FREQ_END_MHZ = 87.975;
    static constexpr double CHANNEL_SPACING_KHZ = 12.5;  // Newer 12.5 kHz spacing
    static constexpr int TOTAL_CHANNELS = 4638;
    static constexpr int PRESET_CHANNELS = 99;  // 99 preset channels
    static constexpr double PORTABLE_POWER_WATTS = 2.0;
    static constexpr double VEHICLE_POWER_WATTS = 20.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
    static const std::string COUNTRY;
    static const std::string ALLIANCE;
    static constexpr bool ENCRYPTION_CAPABLE = true;
    static constexpr bool GPS_CAPABLE = true;
    static constexpr bool DATA_CAPABLE = true;
    static constexpr bool ADVANCED_ENCRYPTION = true;
    static constexpr bool NETWORK_CAPABLE = true;
};

// NATO Channel Calculator
class NATOChannelCalculator {
public:
    // Calculate frequency for a given channel number
    static double calculateFrequency(int channel, double startFreq, double channelSpacing) {
        if (channel < 1) return startFreq;
        return startFreq + ((channel - 1) * channelSpacing / 1000.0);
    }
    
    // Calculate channel number for a given frequency
    static int calculateChannel(double frequency, double startFreq, double channelSpacing) {
        if (frequency < startFreq) return 0;
        return static_cast<int>(((frequency - startFreq) * 1000.0 / channelSpacing) + 1);
    }
    
    // Get all channels for a radio model
    static std::vector<double> getAllChannels(double startFreq, double endFreq, double channelSpacing) {
        std::vector<double> channels;
        double currentFreq = startFreq;
        
        while (currentFreq <= endFreq) {
            channels.push_back(currentFreq);
            currentFreq += channelSpacing / 1000.0;
        }
        
        return channels;
    }
    
    // Validate frequency is within radio range
    static bool isValidFrequency(double frequency, double startFreq, double endFreq) {
        return frequency >= startFreq && frequency <= endFreq;
    }
    
    // Get channel spacing for different NATO standards
    static double getNATOChannelSpacing(const std::string& standard) {
        if (standard == "NATO_25kHz") return 25.0;
        if (standard == "NATO_12.5kHz") return 12.5;
        if (standard == "US_MIL_25kHz") return 25.0;
        if (standard == "US_MIL_12.5kHz") return 12.5;
        return 25.0; // Default NATO standard
    }
};

// AN/PRC-77 Radio
class AN_PRC77_Radio {
private:
    int currentChannel;
    double currentPower;
    bool isPortable;
    bool isOperational;
    bool encryptionEnabled;
    
public:
    AN_PRC77_Radio(bool portable = true) : currentChannel(1), isPortable(portable), isOperational(true), encryptionEnabled(false) {
        currentPower = isPortable ? AN_PRC77_Specs::PORTABLE_POWER_WATTS : AN_PRC77_Specs::VEHICLE_POWER_WATTS;
    }
    
    // Channel operations
    bool setChannel(int channel) {
        if (channel < 1 || channel > AN_PRC77_Specs::TOTAL_CHANNELS) return false;
        currentChannel = channel;
        return true;
    }
    
    int getCurrentChannel() const { return currentChannel; }
    
    double getCurrentFrequency() const {
        return NATOChannelCalculator::calculateFrequency(
            currentChannel, AN_PRC77_Specs::FREQ_START_MHZ, AN_PRC77_Specs::CHANNEL_SPACING_KHZ);
    }
    
    // Power operations
    void setPortableMode(bool portable) {
        isPortable = portable;
        currentPower = portable ? AN_PRC77_Specs::PORTABLE_POWER_WATTS : AN_PRC77_Specs::VEHICLE_POWER_WATTS;
    }
    
    double getCurrentPower() const { return currentPower; }
    bool isPortableMode() const { return isPortable; }
    
    // Operational status
    void setOperational(bool operational) { isOperational = operational; }
    bool isRadioOperational() const { return isOperational; }
    
    // Encryption (basic for legacy radio)
    void setEncryption(bool enabled) { encryptionEnabled = enabled; }
    bool isEncryptionEnabled() const { return encryptionEnabled; }
    
    // Get specifications
    static std::string getModelName() { return AN_PRC77_Specs::MODEL_NAME; }
    static int getTotalChannels() { return AN_PRC77_Specs::TOTAL_CHANNELS; }
    static double getFrequencyRange() { return AN_PRC77_Specs::FREQ_END_MHZ - AN_PRC77_Specs::FREQ_START_MHZ; }
    static std::string getEra() { return AN_PRC77_Specs::ERA; }
    static std::string getUsage() { return AN_PRC77_Specs::USAGE; }
    static std::string getCountry() { return AN_PRC77_Specs::COUNTRY; }
    static std::string getAlliance() { return AN_PRC77_Specs::ALLIANCE; }
};

// AN/PRC-148 Radio
class AN_PRC148_Radio {
private:
    int currentChannel;
    double currentPower;
    bool isPortable;
    bool isOperational;
    bool encryptionEnabled;
    bool gpsEnabled;
    bool dataEnabled;
    
public:
    AN_PRC148_Radio(bool portable = true) : currentChannel(1), isPortable(portable), isOperational(true), 
                                           encryptionEnabled(false), gpsEnabled(false), dataEnabled(false) {
        currentPower = isPortable ? AN_PRC148_Specs::PORTABLE_POWER_WATTS : AN_PRC148_Specs::VEHICLE_POWER_WATTS;
    }
    
    // Channel operations
    bool setChannel(int channel) {
        if (channel < 1 || channel > AN_PRC148_Specs::TOTAL_CHANNELS) return false;
        currentChannel = channel;
        return true;
    }
    
    int getCurrentChannel() const { return currentChannel; }
    
    double getCurrentFrequency() const {
        return NATOChannelCalculator::calculateFrequency(
            currentChannel, AN_PRC148_Specs::FREQ_START_MHZ, AN_PRC148_Specs::CHANNEL_SPACING_KHZ);
    }
    
    // Power operations
    void setPortableMode(bool portable) {
        isPortable = portable;
        currentPower = portable ? AN_PRC148_Specs::PORTABLE_POWER_WATTS : AN_PRC148_Specs::VEHICLE_POWER_WATTS;
    }
    
    double getCurrentPower() const { return currentPower; }
    bool isPortableMode() const { return isPortable; }
    
    // Operational status
    void setOperational(bool operational) { isOperational = operational; }
    bool isRadioOperational() const { return isOperational; }
    
    // Advanced features
    void setEncryption(bool enabled) { encryptionEnabled = enabled; }
    bool isEncryptionEnabled() const { return encryptionEnabled; }
    
    void setGPS(bool enabled) { gpsEnabled = enabled; }
    bool isGPSEnabled() const { return gpsEnabled; }
    
    void setDataMode(bool enabled) { dataEnabled = enabled; }
    bool isDataModeEnabled() const { return dataEnabled; }
    
    // Get specifications
    static std::string getModelName() { return AN_PRC148_Specs::MODEL_NAME; }
    static int getTotalChannels() { return AN_PRC148_Specs::TOTAL_CHANNELS; }
    static double getFrequencyRange() { return AN_PRC148_Specs::FREQ_END_MHZ - AN_PRC148_Specs::FREQ_START_MHZ; }
    static std::string getEra() { return AN_PRC148_Specs::ERA; }
    static std::string getUsage() { return AN_PRC148_Specs::USAGE; }
    static std::string getCountry() { return AN_PRC148_Specs::COUNTRY; }
    static std::string getAlliance() { return AN_PRC148_Specs::ALLIANCE; }
    static bool isEncryptionCapable() { return AN_PRC148_Specs::ENCRYPTION_CAPABLE; }
    static bool isGPSCapable() { return AN_PRC148_Specs::GPS_CAPABLE; }
    static bool isDataCapable() { return AN_PRC148_Specs::DATA_CAPABLE; }
};

// AN/PRC-152 Radio
class AN_PRC152_Radio {
private:
    int currentChannel;
    double currentPower;
    bool isPortable;
    bool isOperational;
    bool encryptionEnabled;
    bool gpsEnabled;
    bool dataEnabled;
    bool advancedEncryption;
    bool networkEnabled;
    int presetChannels[99];  // 99 preset channels
    
public:
    AN_PRC152_Radio(bool portable = true) : currentChannel(1), isPortable(portable), isOperational(true), 
                                           encryptionEnabled(false), gpsEnabled(false), dataEnabled(false),
                                           advancedEncryption(false), networkEnabled(false) {
        currentPower = isPortable ? AN_PRC152_Specs::PORTABLE_POWER_WATTS : AN_PRC152_Specs::VEHICLE_POWER_WATTS;
        
        // Initialize preset channels with default values
        for (int i = 0; i < 99; i++) {
            presetChannels[i] = i + 1;  // Default to channels 1-99
        }
    }
    
    // Channel operations
    bool setChannel(int channel) {
        if (channel < 1 || channel > AN_PRC152_Specs::TOTAL_CHANNELS) return false;
        currentChannel = channel;
        return true;
    }
    
    int getCurrentChannel() const { return currentChannel; }
    
    double getCurrentFrequency() const {
        return NATOChannelCalculator::calculateFrequency(
            currentChannel, AN_PRC152_Specs::FREQ_START_MHZ, AN_PRC152_Specs::CHANNEL_SPACING_KHZ);
    }
    
    // Power operations
    void setPortableMode(bool portable) {
        isPortable = portable;
        currentPower = portable ? AN_PRC152_Specs::PORTABLE_POWER_WATTS : AN_PRC152_Specs::VEHICLE_POWER_WATTS;
    }
    
    double getCurrentPower() const { return currentPower; }
    bool isPortableMode() const { return isPortable; }
    
    // Operational status
    void setOperational(bool operational) { isOperational = operational; }
    bool isRadioOperational() const { return isOperational; }
    
    // Advanced features
    void setEncryption(bool enabled) { encryptionEnabled = enabled; }
    bool isEncryptionEnabled() const { return encryptionEnabled; }
    
    void setGPS(bool enabled) { gpsEnabled = enabled; }
    bool isGPSEnabled() const { return gpsEnabled; }
    
    void setDataMode(bool enabled) { dataEnabled = enabled; }
    bool isDataModeEnabled() const { return dataEnabled; }
    
    void setAdvancedEncryption(bool enabled) { advancedEncryption = enabled; }
    bool isAdvancedEncryptionEnabled() const { return advancedEncryption; }
    
    void setNetworkMode(bool enabled) { networkEnabled = enabled; }
    bool isNetworkModeEnabled() const { return networkEnabled; }
    
    // Preset channel operations
    bool setPresetChannel(int preset, int channel) {
        if (preset < 0 || preset >= AN_PRC152_Specs::PRESET_CHANNELS) return false;
        if (channel < 1 || channel > AN_PRC152_Specs::TOTAL_CHANNELS) return false;
        presetChannels[preset] = channel;
        return true;
    }
    
    int getPresetChannel(int preset) const {
        if (preset < 0 || preset >= AN_PRC152_Specs::PRESET_CHANNELS) return 0;
        return presetChannels[preset];
    }
    
    bool selectPresetChannel(int preset) {
        if (preset < 0 || preset >= AN_PRC152_Specs::PRESET_CHANNELS) return false;
        currentChannel = presetChannels[preset];
        return true;
    }
    
    int getPresetChannelCount() const {
        return AN_PRC152_Specs::PRESET_CHANNELS;
    }
    
    // Get all preset channels
    std::vector<int> getAllPresetChannels() const {
        std::vector<int> presets;
        for (int i = 0; i < AN_PRC152_Specs::PRESET_CHANNELS; i++) {
            presets.push_back(presetChannels[i]);
        }
        return presets;
    }
    
    // Get preset channel frequencies
    std::vector<double> getAllPresetFrequencies() const {
        std::vector<double> frequencies;
        for (int i = 0; i < AN_PRC152_Specs::PRESET_CHANNELS; i++) {
            double freq = NATOChannelCalculator::calculateFrequency(
                presetChannels[i], AN_PRC152_Specs::FREQ_START_MHZ, AN_PRC152_Specs::CHANNEL_SPACING_KHZ);
            frequencies.push_back(freq);
        }
        return frequencies;
    }
    
    // Get specifications
    static std::string getModelName() { return AN_PRC152_Specs::MODEL_NAME; }
    static int getTotalChannels() { return AN_PRC152_Specs::TOTAL_CHANNELS; }
    static int getPresetChannels() { return AN_PRC152_Specs::PRESET_CHANNELS; }
    static double getFrequencyRange() { return AN_PRC152_Specs::FREQ_END_MHZ - AN_PRC152_Specs::FREQ_START_MHZ; }
    static std::string getEra() { return AN_PRC152_Specs::ERA; }
    static std::string getUsage() { return AN_PRC152_Specs::USAGE; }
    static std::string getCountry() { return AN_PRC152_Specs::COUNTRY; }
    static std::string getAlliance() { return AN_PRC152_Specs::ALLIANCE; }
    static bool isEncryptionCapable() { return AN_PRC152_Specs::ENCRYPTION_CAPABLE; }
    static bool isGPSCapable() { return AN_PRC152_Specs::GPS_CAPABLE; }
    static bool isDataCapable() { return AN_PRC152_Specs::DATA_CAPABLE; }
    static bool isAdvancedEncryptionCapable() { return AN_PRC152_Specs::ADVANCED_ENCRYPTION; }
    static bool isNetworkCapable() { return AN_PRC152_Specs::NETWORK_CAPABLE; }
};

} // namespace NATO_VHF

#endif // FGCOM_NATO_VHF_EQUIPMENT_H
