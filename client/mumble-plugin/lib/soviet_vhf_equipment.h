#ifndef SOVIET_VHF_EQUIPMENT_H
#define SOVIET_VHF_EQUIPMENT_H

#include <string>
#include <vector>
#include <map>

namespace SovietVHF {

// R-105M Specifications
struct R105M_Specs {
    static constexpr double FREQ_START_MHZ = 36.0;
    static constexpr double FREQ_END_MHZ = 46.1;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 404;
    static constexpr double PORTABLE_POWER_WATTS = 1.5;
    static constexpr double VEHICLE_POWER_WATTS = 20.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
};

// R-105D Specifications (Earlier version)
struct R105D_Specs {
    static constexpr double FREQ_START_MHZ = 20.0;
    static constexpr double FREQ_END_MHZ = 35.9;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 636;
    static constexpr double PORTABLE_POWER_WATTS = 1.5;
    static constexpr double VEHICLE_POWER_WATTS = 20.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
};

// R-107 Specifications (Operational VHF)
struct R107_Specs {
    static constexpr double FREQ_START_MHZ = 20.0;
    static constexpr double FREQ_END_MHZ = 52.0;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 1280;
    static constexpr double PORTABLE_POWER_WATTS = 2.0;
    static constexpr double VEHICLE_POWER_WATTS = 25.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
    static constexpr bool FM_CAPABLE = true;
    static constexpr bool CW_CAPABLE = true;
    static constexpr bool BROADBAND = true;
};

// R-123 Magnolia Specifications (Tank Radio)
struct R123_Specs {
    static constexpr double FREQ_START_MHZ = 20.0;
    static constexpr double FREQ_END_MHZ = 51.5;
    static constexpr double CHANNEL_SPACING_KHZ = 25.0;
    static constexpr int TOTAL_CHANNELS = 1260;
    static constexpr int PRESET_CHANNELS = 4;
    static constexpr double TANK_POWER_WATTS = 15.0;
    static const std::string MODEL_NAME;
    static const std::string ERA;
    static const std::string USAGE;
    static constexpr bool FM_SUPERHETERODYNE = true;
    static constexpr bool MANUAL_TUNING = true;
};

// Channel calculation utilities
class SovietVHFChannelCalculator {
public:
    static double calculateFrequency(int channel, double startFreq, double channelSpacing);
    static int calculateChannel(double frequency, double startFreq, double channelSpacing);
    static std::vector<double> getAllChannels(double startFreq, double endFreq, double channelSpacing);
    static bool isValidFrequency(double frequency, double startFreq, double endFreq);
};

// R-105M Radio Class
class R105M_Radio {
private:
    int currentChannel;
    bool isPortable;
    bool isOperational;
    double currentPower;

public:
    R105M_Radio(bool portable = true);
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    void setPortableMode(bool portable);
    double getCurrentPower() const;
    bool isPortableMode() const;
    void setOperational(bool operational);
    bool isRadioOperational() const;
    static std::string getModelName();
    static int getTotalChannels();
    static double getFrequencyRange();
};

// R-105D Radio Class
class R105D_Radio {
private:
    int currentChannel;
    bool isPortable;
    bool isOperational;
    double currentPower;

public:
    R105D_Radio(bool portable = true);
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    void setPortableMode(bool portable);
    double getCurrentPower() const;
    bool isPortableMode() const;
    void setOperational(bool operational);
    bool isRadioOperational() const;
    static std::string getModelName();
    static int getTotalChannels();
    static double getFrequencyRange();
};

// R-107 Radio Class
class R107_Radio {
private:
    int currentChannel;
    bool isOperational;
    bool fmMode;
    bool cwMode;
    double currentPower;

public:
    R107_Radio();
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    void setFMMode(bool fm);
    void setCWMode(bool cw);
    bool isFMMode() const;
    bool isCWMode() const;
    void setPower(double power);
    double getCurrentPower() const;
    void setOperational(bool operational);
    bool isRadioOperational() const;
    static std::string getModelName();
    static int getTotalChannels();
    static double getFrequencyRange();
    static bool isBroadband();
};

// R-123 Magnolia Radio Class
class R123_Magnolia_Radio {
private:
    int currentChannel;
    bool isOperational;
    bool manualTuning;
    double currentPower;
    std::map<int, int> presetChannels; // preset number -> channel number

public:
    R123_Magnolia_Radio();
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    bool setPresetChannel(int preset, int channel);
    int getPresetChannel(int preset) const;
    bool selectPresetChannel(int preset);
    void setManualTuning(bool manual);
    bool isManualTuning() const;
    void setPower(double power);
    double getCurrentPower() const;
    void setOperational(bool operational);
    bool isRadioOperational() const;
    static std::string getModelName();
    static int getTotalChannels();
    static int getPresetChannels();
    static double getFrequencyRange();
    static bool isSuperheterodyne();
};

// Soviet VHF Equipment Manager
class SovietVHFEquipment {
private:
    static SovietVHFEquipment* instance;
    std::map<std::string, void*> radioConfigs;

    SovietVHFEquipment();
    ~SovietVHFEquipment();

public:
    static SovietVHFEquipment& getInstance();
    bool initialize();
    void* getRadioConfig(const std::string& modelName);
    std::vector<std::string> getAvailableModels();
    bool isModelAvailable(const std::string& modelName);
};

} // namespace SovietVHF

#endif // SOVIET_VHF_EQUIPMENT_H
