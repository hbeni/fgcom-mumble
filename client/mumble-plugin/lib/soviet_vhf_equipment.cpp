#include "soviet_vhf_equipment.h"
#include <iostream>
#include <algorithm>

namespace SovietVHF {

// Static string definitions
const std::string R105M_Specs::MODEL_NAME = "R-105M";
const std::string R105M_Specs::ERA = "Cold War";
const std::string R105M_Specs::USAGE = "Tactical VHF";

const std::string R105D_Specs::MODEL_NAME = "R-105D";
const std::string R105D_Specs::ERA = "Cold War";
const std::string R105D_Specs::USAGE = "Tactical VHF (Earlier version)";

const std::string R107_Specs::MODEL_NAME = "R-107";
const std::string R107_Specs::ERA = "Cold War";
const std::string R107_Specs::USAGE = "Operational VHF (Civil Defense/Special Forces)";

const std::string R123_Specs::MODEL_NAME = "R-123 Magnolia";
const std::string R123_Specs::ERA = "Cold War";
const std::string R123_Specs::USAGE = "Tank and Armored Vehicle Radio";

// SovietVHFChannelCalculator Implementation
double SovietVHFChannelCalculator::calculateFrequency(int channel, double startFreq, double channelSpacing) {
    if (channel < 1) return 0.0;
    return startFreq + (channel - 1) * (channelSpacing / 1000.0);
}

int SovietVHFChannelCalculator::calculateChannel(double frequency, double startFreq, double channelSpacing) {
    if (frequency < startFreq) return 0;
    return static_cast<int>((frequency - startFreq) / (channelSpacing / 1000.0)) + 1;
}

std::vector<double> SovietVHFChannelCalculator::getAllChannels(double startFreq, double endFreq, double channelSpacing) {
    std::vector<double> channels;
    double currentFreq = startFreq;
    double spacing = channelSpacing / 1000.0;
    
    while (currentFreq <= endFreq) {
        channels.push_back(currentFreq);
        currentFreq += spacing;
    }
    
    return channels;
}

bool SovietVHFChannelCalculator::isValidFrequency(double frequency, double startFreq, double endFreq) {
    return frequency >= startFreq && frequency <= endFreq;
}

// R105M_Radio Implementation
R105M_Radio::R105M_Radio(bool portable) : currentChannel(1), isPortable(portable), isOperational(true) {
    currentPower = portable ? R105M_Specs::PORTABLE_POWER_WATTS : R105M_Specs::VEHICLE_POWER_WATTS;
}

bool R105M_Radio::setChannel(int channel) {
    if (channel < 1 || channel > R105M_Specs::TOTAL_CHANNELS) return false;
    currentChannel = channel;
    return true;
}

int R105M_Radio::getCurrentChannel() const {
    return currentChannel;
}

double R105M_Radio::getCurrentFrequency() const {
    return SovietVHFChannelCalculator::calculateFrequency(
        currentChannel, R105M_Specs::FREQ_START_MHZ, R105M_Specs::CHANNEL_SPACING_KHZ);
}

void R105M_Radio::setPortableMode(bool portable) {
    isPortable = portable;
    currentPower = portable ? R105M_Specs::PORTABLE_POWER_WATTS : R105M_Specs::VEHICLE_POWER_WATTS;
}

double R105M_Radio::getCurrentPower() const {
    return currentPower;
}

bool R105M_Radio::isPortableMode() const {
    return isPortable;
}

void R105M_Radio::setOperational(bool operational) {
    isOperational = operational;
}

bool R105M_Radio::isRadioOperational() const {
    return isOperational;
}

std::string R105M_Radio::getModelName() {
    return R105M_Specs::MODEL_NAME;
}

int R105M_Radio::getTotalChannels() {
    return R105M_Specs::TOTAL_CHANNELS;
}

double R105M_Radio::getFrequencyRange() {
    return R105M_Specs::FREQ_END_MHZ - R105M_Specs::FREQ_START_MHZ;
}

// R105D_Radio Implementation
R105D_Radio::R105D_Radio(bool portable) : currentChannel(1), isPortable(portable), isOperational(true) {
    currentPower = portable ? R105D_Specs::PORTABLE_POWER_WATTS : R105D_Specs::VEHICLE_POWER_WATTS;
}

bool R105D_Radio::setChannel(int channel) {
    if (channel < 1 || channel > R105D_Specs::TOTAL_CHANNELS) return false;
    currentChannel = channel;
    return true;
}

int R105D_Radio::getCurrentChannel() const {
    return currentChannel;
}

double R105D_Radio::getCurrentFrequency() const {
    return SovietVHFChannelCalculator::calculateFrequency(
        currentChannel, R105D_Specs::FREQ_START_MHZ, R105D_Specs::CHANNEL_SPACING_KHZ);
}

void R105D_Radio::setPortableMode(bool portable) {
    isPortable = portable;
    currentPower = portable ? R105D_Specs::PORTABLE_POWER_WATTS : R105D_Specs::VEHICLE_POWER_WATTS;
}

double R105D_Radio::getCurrentPower() const {
    return currentPower;
}

bool R105D_Radio::isPortableMode() const {
    return isPortable;
}

void R105D_Radio::setOperational(bool operational) {
    isOperational = operational;
}

bool R105D_Radio::isRadioOperational() const {
    return isOperational;
}

std::string R105D_Radio::getModelName() {
    return R105D_Specs::MODEL_NAME;
}

int R105D_Radio::getTotalChannels() {
    return R105D_Specs::TOTAL_CHANNELS;
}

double R105D_Radio::getFrequencyRange() {
    return R105D_Specs::FREQ_END_MHZ - R105D_Specs::FREQ_START_MHZ;
}

// R107_Radio Implementation
R107_Radio::R107_Radio() : currentChannel(1), isOperational(true), fmMode(true), cwMode(false) {
    currentPower = R107_Specs::PORTABLE_POWER_WATTS;
}

bool R107_Radio::setChannel(int channel) {
    if (channel < 1 || channel > R107_Specs::TOTAL_CHANNELS) return false;
    currentChannel = channel;
    return true;
}

int R107_Radio::getCurrentChannel() const {
    return currentChannel;
}

double R107_Radio::getCurrentFrequency() const {
    return SovietVHFChannelCalculator::calculateFrequency(
        currentChannel, R107_Specs::FREQ_START_MHZ, R107_Specs::CHANNEL_SPACING_KHZ);
}

void R107_Radio::setFMMode(bool fm) {
    fmMode = fm;
}

void R107_Radio::setCWMode(bool cw) {
    cwMode = cw;
}

bool R107_Radio::isFMMode() const {
    return fmMode;
}

bool R107_Radio::isCWMode() const {
    return cwMode;
}

void R107_Radio::setPower(double power) {
    currentPower = power;
}

double R107_Radio::getCurrentPower() const {
    return currentPower;
}

void R107_Radio::setOperational(bool operational) {
    isOperational = operational;
}

bool R107_Radio::isRadioOperational() const {
    return isOperational;
}

std::string R107_Radio::getModelName() {
    return R107_Specs::MODEL_NAME;
}

int R107_Radio::getTotalChannels() {
    return R107_Specs::TOTAL_CHANNELS;
}

double R107_Radio::getFrequencyRange() {
    return R107_Specs::FREQ_END_MHZ - R107_Specs::FREQ_START_MHZ;
}

bool R107_Radio::isBroadband() {
    return R107_Specs::BROADBAND;
}

// R123_Magnolia_Radio Implementation
R123_Magnolia_Radio::R123_Magnolia_Radio() : currentChannel(1), isOperational(true), manualTuning(false) {
    currentPower = R123_Specs::TANK_POWER_WATTS;
    // Initialize preset channels
    for (int i = 1; i <= R123_Specs::PRESET_CHANNELS; ++i) {
        presetChannels[i] = i * 100; // Default preset channels
    }
}

bool R123_Magnolia_Radio::setChannel(int channel) {
    if (channel < 1 || channel > R123_Specs::TOTAL_CHANNELS) return false;
    currentChannel = channel;
    return true;
}

int R123_Magnolia_Radio::getCurrentChannel() const {
    return currentChannel;
}

double R123_Magnolia_Radio::getCurrentFrequency() const {
    return SovietVHFChannelCalculator::calculateFrequency(
        currentChannel, R123_Specs::FREQ_START_MHZ, R123_Specs::CHANNEL_SPACING_KHZ);
}

bool R123_Magnolia_Radio::setPresetChannel(int preset, int channel) {
    if (preset < 1 || preset > R123_Specs::PRESET_CHANNELS) return false;
    if (channel < 1 || channel > R123_Specs::TOTAL_CHANNELS) return false;
    presetChannels[preset] = channel;
    return true;
}

int R123_Magnolia_Radio::getPresetChannel(int preset) const {
    if (preset < 1 || preset > R123_Specs::PRESET_CHANNELS) return 0;
    return presetChannels.at(preset);
}

bool R123_Magnolia_Radio::selectPresetChannel(int preset) {
    if (preset < 1 || preset > R123_Specs::PRESET_CHANNELS) return false;
    currentChannel = presetChannels.at(preset);
    return true;
}

void R123_Magnolia_Radio::setManualTuning(bool manual) {
    manualTuning = manual;
}

bool R123_Magnolia_Radio::isManualTuning() const {
    return manualTuning;
}

void R123_Magnolia_Radio::setPower(double power) {
    currentPower = power;
}

double R123_Magnolia_Radio::getCurrentPower() const {
    return currentPower;
}

void R123_Magnolia_Radio::setOperational(bool operational) {
    isOperational = operational;
}

bool R123_Magnolia_Radio::isRadioOperational() const {
    return isOperational;
}

std::string R123_Magnolia_Radio::getModelName() {
    return R123_Specs::MODEL_NAME;
}

int R123_Magnolia_Radio::getTotalChannels() {
    return R123_Specs::TOTAL_CHANNELS;
}

int R123_Magnolia_Radio::getPresetChannels() {
    return R123_Specs::PRESET_CHANNELS;
}

double R123_Magnolia_Radio::getFrequencyRange() {
    return R123_Specs::FREQ_END_MHZ - R123_Specs::FREQ_START_MHZ;
}

bool R123_Magnolia_Radio::isSuperheterodyne() {
    return R123_Specs::FM_SUPERHETERODYNE;
}

// SovietVHFEquipment Implementation
SovietVHFEquipment* SovietVHFEquipment::instance = nullptr;

SovietVHFEquipment::SovietVHFEquipment() {
}

SovietVHFEquipment::~SovietVHFEquipment() {
}

SovietVHFEquipment& SovietVHFEquipment::getInstance() {
    if (instance == nullptr) {
        instance = new SovietVHFEquipment();
    }
    return *instance;
}

bool SovietVHFEquipment::initialize() {
    // Initialize radio configurations
    radioConfigs["R-105M"] = new R105M_Radio();
    radioConfigs["R-105D"] = new R105D_Radio();
    radioConfigs["R-107"] = new R107_Radio();
    radioConfigs["R-123"] = new R123_Magnolia_Radio();
    return true;
}

void* SovietVHFEquipment::getRadioConfig(const std::string& modelName) {
    auto it = radioConfigs.find(modelName);
    if (it != radioConfigs.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> SovietVHFEquipment::getAvailableModels() {
    std::vector<std::string> models;
    for (const auto& pair : radioConfigs) {
        models.push_back(pair.first);
    }
    return models;
}

bool SovietVHFEquipment::isModelAvailable(const std::string& modelName) {
    return radioConfigs.find(modelName) != radioConfigs.end();
}

} // namespace SovietVHF
