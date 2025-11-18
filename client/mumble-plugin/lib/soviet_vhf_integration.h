#ifndef FGCOM_SOVIET_VHF_INTEGRATION_H
#define FGCOM_SOVIET_VHF_INTEGRATION_H

#include "soviet_vhf_equipment.h"
#include "radio_model.h"
#include <memory>
#include <string>
#include <map>

// Integration of Soviet VHF equipment with FGCom-mumble system
namespace SovietVHFIntegration {

// Soviet VHF radio model for FGCom integration
class FGCom_SovietVHFModel : public FGCom_radiowaveModel {
private:
    std::string radioType;
    std::unique_ptr<SovietVHF::R105M_Radio> r105m_radio;
    std::unique_ptr<SovietVHF::R105D_Radio> r105d_radio;
    std::unique_ptr<SovietVHF::R107_Radio> r107_radio;
    std::unique_ptr<SovietVHF::R123_Magnolia_Radio> r123_radio;
    
public:
    FGCom_SovietVHFModel(const std::string& type);
    ~FGCom_SovietVHFModel() = default;
    
    // FGCom_radiowaveModel interface
    std::string getType() const override;
    fgcom_radiowave_signal getSignal(double lat1, double lon1, float alt1, 
                                   double lat2, double lon2, float alt2, float power) override;
    void processAudioSamples(fgcom_radio& radio, float signalQuality, 
                            float* outputPCM, uint32_t sampleCount, 
                            uint16_t channelCount, uint32_t sampleRate) override;
    
    // Soviet VHF specific methods
    bool setChannel(int channel);
    int getCurrentChannel() const;
    double getCurrentFrequency() const;
    bool setPortableMode(bool portable);
    bool isPortableMode() const;
    double getCurrentPower() const;
    void setPower(double power);
    bool setOperational(bool operational);
    bool isRadioOperational() const;
    
    // R-107 specific methods
    bool setFMMode(bool fm);
    bool setCWMode(bool cw);
    bool isFMMode() const;
    bool isCWMode() const;
    
    // R-123 specific methods
    bool setPresetChannel(int preset, int channel);
    int getPresetChannel(int preset) const;
    bool selectPresetChannel(int preset);
    void setManualTuning(bool manual);
    bool isManualTuning() const;
    
    // Channel validation
    bool isValidChannel(int channel) const;
    bool isValidFrequency(double frequency) const;
    std::vector<double> getAllChannels() const;
    
    // Specifications
    std::string getModelName() const;
    int getTotalChannels() const;
    double getFrequencyRange() const;
    std::string getEra() const;
    std::string getUsage() const;
};

// Soviet VHF radio factory
class SovietVHFFactory {
public:
    static std::unique_ptr<FGCom_SovietVHFModel> createRadio(const std::string& type);
    static std::vector<std::string> getAvailableRadios();
    static std::map<std::string, std::string> getRadioSpecifications(const std::string& type);
};

// Soviet VHF frequency database
class SovietVHFFrequencyDB {
private:
    static std::map<std::string, std::vector<double>> frequencyDatabase;
    
public:
    static void initializeDatabase();
    static std::vector<double> getFrequencies(const std::string& radioType);
    static bool isFrequencyValid(const std::string& radioType, double frequency);
    static int getChannelForFrequency(const std::string& radioType, double frequency);
    static double getFrequencyForChannel(const std::string& radioType, int channel);
    
    // Predefined frequency sets for different scenarios
    static std::vector<double> getTacticalFrequencies();
    static std::vector<double> getOperationalFrequencies();
    static std::vector<double> getTankFrequencies();
    static std::vector<double> getEmergencyFrequencies();
};

// Soviet VHF configuration
struct SovietVHFConfig {
    std::string radioType;
    bool enableSovietVHF;
    bool enablePortableMode;
    bool enableVehicleMode;
    bool enableTankMode;
    double defaultPower;
    bool enableFMMode;
    bool enableCWMode;
    bool enableManualTuning;
    bool enablePresetChannels;
    int defaultPresetChannels[4];
    bool enableFrequencyValidation;
    bool enableChannelSpacing;
    double channelSpacing;
    bool enablePowerControl;
    bool enableOperationalStatus;
    bool enableEraSpecificFeatures;
    std::string defaultEra;
    bool enableUsageSpecificFeatures;
    std::string defaultUsage;
};

// Soviet VHF configuration manager
class SovietVHFConfigManager {
private:
    static SovietVHFConfig config;
    
public:
    static void loadConfig(const std::string& configFile);
    static void saveConfig(const std::string& configFile);
    static SovietVHFConfig getConfig();
    static void setConfig(const SovietVHFConfig& newConfig);
    static void setDefaultConfig();
    static bool validateConfig(const SovietVHFConfig& config);
    static std::string getConfigSummary();
};

// Soviet VHF audio processing
class SovietVHFAudioProcessor {
private:
    std::string radioType;
    bool fmMode;
    bool cwMode;
    double currentPower;
    bool isOperational;
    
public:
    SovietVHFAudioProcessor(const std::string& type);
    
    void processAudio(float* audioBuffer, uint32_t sampleCount, 
                     uint16_t channelCount, uint32_t sampleRate,
                     float signalQuality, double power);
    
    void setFMMode(bool fm);
    void setCWMode(bool cw);
    void setPower(double power);
    void setOperational(bool operational);
    
    bool isFMMode() const;
    bool isCWMode() const;
    double getCurrentPower() const;
    bool isOperational() const;
    
    // Audio effects specific to Soviet VHF equipment
    void applyFMEffects(float* audioBuffer, uint32_t sampleCount, uint32_t sampleRate);
    void applyCWEffects(float* audioBuffer, uint32_t sampleCount, uint32_t sampleRate);
    void applyPowerEffects(float* audioBuffer, uint32_t sampleCount, double power);
    void applyOperationalEffects(float* audioBuffer, uint32_t sampleCount, bool operational);
    void applyEraEffects(float* audioBuffer, uint32_t sampleCount, const std::string& era);
    void applyUsageEffects(float* audioBuffer, uint32_t sampleCount, const std::string& usage);
};

// Soviet VHF signal processing
class SovietVHFSignalProcessor {
private:
    std::string radioType;
    double frequency;
    double power;
    bool isOperational;
    
public:
    SovietVHFSignalProcessor(const std::string& type);
    
    fgcom_radiowave_signal processSignal(double lat1, double lon1, float alt1,
                                       double lat2, double lon2, float alt2,
                                       double frequency, double power);
    
    void setFrequency(double freq);
    void setPower(double pwr);
    void setOperational(bool operational);
    
    double getFrequency() const;
    double getPower() const;
    bool isOperational() const;
    
    // Signal processing specific to Soviet VHF equipment
    double calculateSignalStrength(double distance, double power, double frequency);
    double calculatePropagationLoss(double distance, double frequency);
    double calculateAtmosphericLoss(double frequency, double altitude);
    double calculateTerrainLoss(double distance, double altitude1, double altitude2);
    double calculateAntennaGain(double frequency, double altitude);
    double calculateNoiseFloor(double frequency, double altitude);
    double calculateSNR(double signalStrength, double noiseFloor);
    double calculateQuality(double snr, double signalStrength);
};

} // namespace SovietVHFIntegration

#endif // FGCOM_SOVIET_VHF_INTEGRATION_H
