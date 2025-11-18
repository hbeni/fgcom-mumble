#include "soviet_vhf_integration.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>

namespace SovietVHFIntegration {

// FGCom_SovietVHFModel Implementation
FGCom_SovietVHFModel::FGCom_SovietVHFModel(const std::string& type) : radioType(type) {
    if (type == "R-105M") {
        r105m_radio = std::make_unique<SovietVHF::R105M_Radio>(true);
    } else if (type == "R-105D") {
        r105d_radio = std::make_unique<SovietVHF::R105D_Radio>(true);
    } else if (type == "R-107") {
        r107_radio = std::make_unique<SovietVHF::R107_Radio>();
    } else if (type == "R-123") {
        r123_radio = std::make_unique<SovietVHF::R123_Magnolia_Radio>();
    }
}

std::string FGCom_SovietVHFModel::getType() const {
    return radioType;
}

fgcom_radiowave_signal FGCom_SovietVHFModel::getSignal(double lat1, double lon1, float alt1, 
                                                     double lat2, double lon2, float alt2, float power) {
    fgcom_radiowave_signal signal;
    signal.quality = 0.0;
    signal.distance = 0.0;
    signal.direction = 0.0;
    signal.verticalAngle = 0.0;
    
    if (!isRadioOperational()) {
        return signal;
    }
    
    // Calculate distance
    double distance = calculateDistance(lat1, lon1, lat2, lon2);
    signal.distance = distance;
    
    // Calculate direction
    signal.direction = calculateBearing(lat1, lon1, lat2, lon2);
    
    // Calculate vertical angle
    signal.verticalAngle = calculateVerticalAngle(distance, alt1, alt2);
    
    // Calculate signal quality based on Soviet VHF characteristics
    double signalStrength = calculateSignalStrength(distance, power, getCurrentFrequency());
    double noiseFloor = calculateNoiseFloor(getCurrentFrequency(), alt1);
    double snr = signalStrength - noiseFloor;
    
    // Soviet VHF equipment has different characteristics
    if (radioType == "R-105M" || radioType == "R-105D") {
        // Tactical VHF - shorter range, more reliable
        signal.quality = std::max(0.0, std::min(1.0, (snr + 20.0) / 40.0));
    } else if (radioType == "R-107") {
        // Operational VHF - broader range, more flexible
        signal.quality = std::max(0.0, std::min(1.0, (snr + 15.0) / 35.0));
    } else if (radioType == "R-123") {
        // Tank VHF - armored vehicle characteristics
        signal.quality = std::max(0.0, std::min(1.0, (snr + 25.0) / 45.0));
    }
    
    return signal;
}

void FGCom_SovietVHFModel::processAudioSamples(fgcom_radio& radio, float signalQuality, 
                                              float* outputPCM, uint32_t sampleCount, 
                                              uint16_t channelCount, uint32_t sampleRate) {
    if (!isRadioOperational() || signalQuality <= 0.0) {
        // Mute audio if radio is not operational or no signal
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            outputPCM[i] = 0.0f;
        }
        return;
    }
    
    // Apply Soviet VHF specific audio processing
    SovietVHFAudioProcessor processor(radioType);
    processor.setPower(getCurrentPower());
    processor.setOperational(isRadioOperational());
    
    if (radioType == "R-107") {
        processor.setFMMode(isFMMode());
        processor.setCWMode(isCWMode());
    }
    
    processor.processAudio(outputPCM, sampleCount, channelCount, sampleRate, signalQuality, getCurrentPower());
}

bool FGCom_SovietVHFModel::setChannel(int channel) {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->setChannel(channel);
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->setChannel(channel);
    } else if (radioType == "R-107" && r107_radio) {
        return r107_radio->setChannel(channel);
    } else if (radioType == "R-123" && r123_radio) {
        return r123_radio->setChannel(channel);
    }
    return false;
}

int FGCom_SovietVHFModel::getCurrentChannel() const {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->getCurrentChannel();
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->getCurrentChannel();
    } else if (radioType == "R-107" && r107_radio) {
        return r107_radio->getCurrentChannel();
    } else if (radioType == "R-123" && r123_radio) {
        return r123_radio->getCurrentChannel();
    }
    return 0;
}

double FGCom_SovietVHFModel::getCurrentFrequency() const {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->getCurrentFrequency();
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->getCurrentFrequency();
    } else if (radioType == "R-107" && r107_radio) {
        return r107_radio->getCurrentFrequency();
    } else if (radioType == "R-123" && r123_radio) {
        return r123_radio->getCurrentFrequency();
    }
    return 0.0;
}

bool FGCom_SovietVHFModel::setPortableMode(bool portable) {
    if (radioType == "R-105M" && r105m_radio) {
        r105m_radio->setPortableMode(portable);
        return true;
    } else if (radioType == "R-105D" && r105d_radio) {
        r105d_radio->setPortableMode(portable);
        return true;
    }
    return false;
}

bool FGCom_SovietVHFModel::isPortableMode() const {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->isPortableMode();
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->isPortableMode();
    }
    return false;
}

double FGCom_SovietVHFModel::getCurrentPower() const {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->getCurrentPower();
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->getCurrentPower();
    } else if (radioType == "R-107" && r107_radio) {
        return r107_radio->getCurrentPower();
    } else if (radioType == "R-123" && r123_radio) {
        return r123_radio->getCurrentPower();
    }
    return 0.0;
}

void FGCom_SovietVHFModel::setPower(double power) {
    if (radioType == "R-107" && r107_radio) {
        r107_radio->setPower(power);
    } else if (radioType == "R-123" && r123_radio) {
        r123_radio->setPower(power);
    }
}

bool FGCom_SovietVHFModel::setOperational(bool operational) {
    if (radioType == "R-105M" && r105m_radio) {
        r105m_radio->setOperational(operational);
        return true;
    } else if (radioType == "R-105D" && r105d_radio) {
        r105d_radio->setOperational(operational);
        return true;
    } else if (radioType == "R-107" && r107_radio) {
        r107_radio->setOperational(operational);
        return true;
    } else if (radioType == "R-123" && r123_radio) {
        r123_radio->setOperational(operational);
        return true;
    }
    return false;
}

bool FGCom_SovietVHFModel::isRadioOperational() const {
    if (radioType == "R-105M" && r105m_radio) {
        return r105m_radio->isRadioOperational();
    } else if (radioType == "R-105D" && r105d_radio) {
        return r105d_radio->isRadioOperational();
    } else if (radioType == "R-107" && r107_radio) {
        return r107_radio->isRadioOperational();
    } else if (radioType == "R-123" && r123_radio) {
        return r123_radio->isRadioOperational();
    }
    return false;
}

// R-107 specific methods
bool FGCom_SovietVHFModel::setFMMode(bool fm) {
    if (radioType == "R-107" && r107_radio) {
        r107_radio->setFMMode(fm);
        return true;
    }
    return false;
}

bool FGCom_SovietVHFModel::setCWMode(bool cw) {
    if (radioType == "R-107" && r107_radio) {
        r107_radio->setCWMode(cw);
        return true;
    }
    return false;
}

bool FGCom_SovietVHFModel::isFMMode() const {
    if (radioType == "R-107" && r107_radio) {
        return r107_radio->isFMMode();
    }
    return false;
}

bool FGCom_SovietVHFModel::isCWMode() const {
    if (radioType == "R-107" && r107_radio) {
        return r107_radio->isCWMode();
    }
    return false;
}

// R-123 specific methods
bool FGCom_SovietVHFModel::setPresetChannel(int preset, int channel) {
    if (radioType == "R-123" && r123_radio) {
        return r123_radio->setPresetChannel(preset, channel);
    }
    return false;
}

int FGCom_SovietVHFModel::getPresetChannel(int preset) const {
    if (radioType == "R-123" && r123_radio) {
        return r123_radio->getPresetChannel(preset);
    }
    return 0;
}

bool FGCom_SovietVHFModel::selectPresetChannel(int preset) {
    if (radioType == "R-123" && r123_radio) {
        return r123_radio->selectPresetChannel(preset);
    }
    return false;
}

void FGCom_SovietVHFModel::setManualTuning(bool manual) {
    if (radioType == "R-123" && r123_radio) {
        r123_radio->setManualTuning(manual);
    }
}

bool FGCom_SovietVHFModel::isManualTuning() const {
    if (radioType == "R-123" && r123_radio) {
        return r123_radio->isManualTuning();
    }
    return false;
}

// Channel validation
bool FGCom_SovietVHFModel::isValidChannel(int channel) const {
    if (radioType == "R-105M") {
        return channel >= 1 && channel <= 404;
    } else if (radioType == "R-105D") {
        return channel >= 1 && channel <= 636;
    } else if (radioType == "R-107") {
        return channel >= 1 && channel <= 1280;
    } else if (radioType == "R-123") {
        return channel >= 1 && channel <= 1260;
    }
    return false;
}

bool FGCom_SovietVHFModel::isValidFrequency(double frequency) const {
    if (radioType == "R-105M") {
        return SovietVHF::SovietVHFChannelCalculator::isValidFrequency(frequency, 36.0, 46.1);
    } else if (radioType == "R-105D") {
        return SovietVHF::SovietVHFChannelCalculator::isValidFrequency(frequency, 20.0, 35.9);
    } else if (radioType == "R-107") {
        return SovietVHF::SovietVHFChannelCalculator::isValidFrequency(frequency, 20.0, 52.0);
    } else if (radioType == "R-123") {
        return SovietVHF::SovietVHFChannelCalculator::isValidFrequency(frequency, 20.0, 51.5);
    }
    return false;
}

std::vector<double> FGCom_SovietVHFModel::getAllChannels() const {
    if (radioType == "R-105M") {
        return SovietVHF::SovietVHFChannelCalculator::getAllChannels(36.0, 46.1, 25.0);
    } else if (radioType == "R-105D") {
        return SovietVHF::SovietVHFChannelCalculator::getAllChannels(20.0, 35.9, 25.0);
    } else if (radioType == "R-107") {
        return SovietVHF::SovietVHFChannelCalculator::getAllChannels(20.0, 52.0, 25.0);
    } else if (radioType == "R-123") {
        return SovietVHF::SovietVHFChannelCalculator::getAllChannels(20.0, 51.5, 25.0);
    }
    return std::vector<double>();
}

// Specifications
std::string FGCom_SovietVHFModel::getModelName() const {
    if (radioType == "R-105M") {
        return SovietVHF::R105M_Radio::getModelName();
    } else if (radioType == "R-105D") {
        return SovietVHF::R105D_Radio::getModelName();
    } else if (radioType == "R-107") {
        return SovietVHF::R107_Radio::getModelName();
    } else if (radioType == "R-123") {
        return SovietVHF::R123_Magnolia_Radio::getModelName();
    }
    return "Unknown";
}

int FGCom_SovietVHFModel::getTotalChannels() const {
    if (radioType == "R-105M") {
        return SovietVHF::R105M_Radio::getTotalChannels();
    } else if (radioType == "R-105D") {
        return SovietVHF::R105D_Radio::getTotalChannels();
    } else if (radioType == "R-107") {
        return SovietVHF::R107_Radio::getTotalChannels();
    } else if (radioType == "R-123") {
        return SovietVHF::R123_Magnolia_Radio::getTotalChannels();
    }
    return 0;
}

double FGCom_SovietVHFModel::getFrequencyRange() const {
    if (radioType == "R-105M") {
        return SovietVHF::R105M_Radio::getFrequencyRange();
    } else if (radioType == "R-105D") {
        return SovietVHF::R105D_Radio::getFrequencyRange();
    } else if (radioType == "R-107") {
        return SovietVHF::R107_Radio::getFrequencyRange();
    } else if (radioType == "R-123") {
        return SovietVHF::R123_Magnolia_Radio::getFrequencyRange();
    }
    return 0.0;
}

std::string FGCom_SovietVHFModel::getEra() const {
    return "Cold War";
}

std::string FGCom_SovietVHFModel::getUsage() const {
    if (radioType == "R-105M" || radioType == "R-105D") {
        return "Tactical VHF";
    } else if (radioType == "R-107") {
        return "Operational VHF (Civil Defense/Special Forces)";
    } else if (radioType == "R-123") {
        return "Tank and Armored Vehicle Radio";
    }
    return "Unknown";
}

// Soviet VHF Factory Implementation
std::unique_ptr<FGCom_SovietVHFModel> SovietVHFFactory::createRadio(const std::string& type) {
    if (type == "R-105M" || type == "R-105D" || type == "R-107" || type == "R-123") {
        return std::make_unique<FGCom_SovietVHFModel>(type);
    }
    return nullptr;
}

std::vector<std::string> SovietVHFFactory::getAvailableRadios() {
    return {"R-105M", "R-105D", "R-107", "R-123"};
}

std::map<std::string, std::string> SovietVHFFactory::getRadioSpecifications(const std::string& type) {
    std::map<std::string, std::string> specs;
    
    if (type == "R-105M") {
        specs["Model"] = "R-105M";
        specs["Frequency Range"] = "36.0-46.1 MHz";
        specs["Channels"] = "404";
        specs["Channel Spacing"] = "25 kHz";
        specs["Power"] = "1-2W portable, up to 20W vehicle-mounted";
        specs["Era"] = "Cold War";
        specs["Usage"] = "Tactical VHF";
    } else if (type == "R-105D") {
        specs["Model"] = "R-105D";
        specs["Frequency Range"] = "20.0-35.9 MHz";
        specs["Channels"] = "636";
        specs["Channel Spacing"] = "25 kHz";
        specs["Power"] = "1-2W portable, up to 20W vehicle-mounted";
        specs["Era"] = "Cold War";
        specs["Usage"] = "Tactical VHF (Earlier version)";
    } else if (type == "R-107") {
        specs["Model"] = "R-107";
        specs["Frequency Range"] = "20.0-52.0 MHz";
        specs["Channels"] = "1280";
        specs["Channel Spacing"] = "25 kHz";
        specs["Power"] = "2W portable, up to 25W vehicle-mounted";
        specs["Era"] = "Cold War";
        specs["Usage"] = "Operational VHF (Civil Defense/Special Forces)";
        specs["Modes"] = "FM and CW capable";
        specs["Type"] = "Broadband coverage";
    } else if (type == "R-123") {
        specs["Model"] = "R-123 Magnolia";
        specs["Frequency Range"] = "20.0-51.5 MHz";
        specs["Channels"] = "1260";
        specs["Channel Spacing"] = "25 kHz";
        specs["Power"] = "15W tank-mounted";
        specs["Era"] = "Cold War";
        specs["Usage"] = "Tank and Armored Vehicle Radio";
        specs["Features"] = "4 preset channels + manual tuning";
        specs["Type"] = "FM superheterodyne";
    }
    
    return specs;
}

// Soviet VHF Audio Processor Implementation
SovietVHFAudioProcessor::SovietVHFAudioProcessor(const std::string& type) 
    : radioType(type), fmMode(true), cwMode(false), currentPower(1.5), isOperational(true) {
}

void SovietVHFAudioProcessor::processAudio(float* audioBuffer, uint32_t sampleCount, 
                                         uint16_t channelCount, uint32_t sampleRate,
                                         float signalQuality, double power) {
    if (!isOperational || signalQuality <= 0.0) {
        // Mute audio if not operational or no signal
        for (uint32_t i = 0; i < sampleCount * channelCount; i++) {
            audioBuffer[i] = 0.0f;
        }
        return;
    }
    
    // Apply Soviet VHF specific audio effects
    applyFMEffects(audioBuffer, sampleCount, sampleRate);
    applyCWEffects(audioBuffer, sampleCount, sampleRate);
    applyPowerEffects(audioBuffer, sampleCount, power);
    applyOperationalEffects(audioBuffer, sampleCount, isOperational);
    applyEraEffects(audioBuffer, sampleCount, "Cold War");
    applyUsageEffects(audioBuffer, sampleCount, getUsageForRadioType());
}

void SovietVHFAudioProcessor::applyFMEffects(float* audioBuffer, uint32_t sampleCount, uint32_t sampleRate) {
    if (!fmMode) return;
    
    // Apply FM-specific audio effects (simplified)
    for (uint32_t i = 0; i < sampleCount; i++) {
        // Add slight frequency modulation artifacts
        float modulation = 0.1f * sin(2.0f * M_PI * 0.5f * i / sampleRate);
        audioBuffer[i] *= (1.0f + modulation);
    }
}

void SovietVHFAudioProcessor::applyCWEffects(float* audioBuffer, uint32_t sampleCount, uint32_t sampleRate) {
    if (!cwMode) return;
    
    // Apply CW-specific audio effects (simplified)
    for (uint32_t i = 0; i < sampleCount; i++) {
        // Add CW keying artifacts
        float keying = 0.2f * sin(2.0f * M_PI * 0.1f * i / sampleRate);
        audioBuffer[i] *= (1.0f + keying);
    }
}

void SovietVHFAudioProcessor::applyPowerEffects(float* audioBuffer, uint32_t sampleCount, double power) {
    // Apply power-based audio effects
    float powerFactor = static_cast<float>(power / 20.0); // Normalize to 20W
    powerFactor = std::max(0.1f, std::min(1.0f, powerFactor));
    
    for (uint32_t i = 0; i < sampleCount; i++) {
        audioBuffer[i] *= powerFactor;
    }
}

void SovietVHFAudioProcessor::applyOperationalEffects(float* audioBuffer, uint32_t sampleCount, bool operational) {
    if (!operational) {
        // Mute audio if not operational
        for (uint32_t i = 0; i < sampleCount; i++) {
            audioBuffer[i] = 0.0f;
        }
    }
}

void SovietVHFAudioProcessor::applyEraEffects(float* audioBuffer, uint32_t sampleCount, const std::string& era) {
    if (era == "Cold War") {
        // Apply Cold War era audio characteristics
        for (uint32_t i = 0; i < sampleCount; i++) {
            // Add period-appropriate audio artifacts
            float eraArtifact = 0.05f * sin(2.0f * M_PI * 0.3f * i / 48000.0f);
            audioBuffer[i] *= (1.0f + eraArtifact);
        }
    }
}

void SovietVHFAudioProcessor::applyUsageEffects(float* audioBuffer, uint32_t sampleCount, const std::string& usage) {
    if (usage == "Tactical VHF") {
        // Apply tactical radio characteristics
        for (uint32_t i = 0; i < sampleCount; i++) {
            // Add tactical radio artifacts
            float tacticalArtifact = 0.03f * sin(2.0f * M_PI * 0.2f * i / 48000.0f);
            audioBuffer[i] *= (1.0f + tacticalArtifact);
        }
    } else if (usage == "Tank and Armored Vehicle Radio") {
        // Apply tank radio characteristics
        for (uint32_t i = 0; i < sampleCount; i++) {
            // Add tank radio artifacts
            float tankArtifact = 0.04f * sin(2.0f * M_PI * 0.15f * i / 48000.0f);
            audioBuffer[i] *= (1.0f + tankArtifact);
        }
    }
}

std::string SovietVHFAudioProcessor::getUsageForRadioType() const {
    if (radioType == "R-105M" || radioType == "R-105D") {
        return "Tactical VHF";
    } else if (radioType == "R-107") {
        return "Operational VHF";
    } else if (radioType == "R-123") {
        return "Tank and Armored Vehicle Radio";
    }
    return "Unknown";
}

// Helper methods for signal processing
double FGCom_SovietVHFModel::calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    // Haversine formula for distance calculation
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dlat/2) * sin(dlat/2) + cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) * sin(dlon/2) * sin(dlon/2);
    double c = 2 * atan2(sqrt(a), sqrt(1-a));
    return 6371000 * c; // Earth radius in meters
}

double FGCom_SovietVHFModel::calculateBearing(double lat1, double lon1, double lat2, double lon2) {
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double lat1_rad = lat1 * M_PI / 180.0;
    double lat2_rad = lat2 * M_PI / 180.0;
    double y = sin(dlon) * cos(lat2_rad);
    double x = cos(lat1_rad) * sin(lat2_rad) - sin(lat1_rad) * cos(lat2_rad) * cos(dlon);
    return atan2(y, x) * 180.0 / M_PI;
}

double FGCom_SovietVHFModel::calculateVerticalAngle(double distance, float alt1, float alt2) {
    if (distance == 0) return 0;
    return atan2(alt2 - alt1, distance) * 180.0 / M_PI;
}

double FGCom_SovietVHFModel::calculateSignalStrength(double distance, double power, double frequency) {
    // Simplified signal strength calculation
    double pathLoss = 20 * log10(distance) + 20 * log10(frequency) + 32.45;
    return power - pathLoss;
}

double FGCom_SovietVHFModel::calculateNoiseFloor(double frequency, float altitude) {
    // Simplified noise floor calculation
    return -174 + 10 * log10(frequency * 1e6) + 6; // Thermal noise + 6dB margin
}

} // namespace SovietVHFIntegration
