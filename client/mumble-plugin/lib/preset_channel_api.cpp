#include "preset_channel_api.h"
#include <iostream>
#include <sstream>

namespace PresetChannelAPI {

// Static member initialization
std::map<std::string, std::vector<PresetChannelInfo>> PresetChannelManager::radioPresets;
bool PresetChannelManager::isInitialized = false;

// PresetChannelManager Implementation
void PresetChannelManager::initialize() {
    isInitialized = true;
}

bool PresetChannelManager::isAPIRunning() {
    return isInitialized;
}

void PresetChannelManager::shutdown() {
    isInitialized = false;
}

bool PresetChannelManager::setPresetChannel(const std::string& radioModel, int presetNumber, int channelNumber, 
                                           const std::string& label, const std::string& description) {
    if (!isInitialized) return false;
    
    PresetChannelInfo preset;
    preset.presetNumber = presetNumber;
    preset.channelNumber = channelNumber;
    preset.frequency = 0.0; // Will be calculated based on radio model
    preset.label = label;
    preset.description = description;
    preset.isActive = true;
    
    // Find or create radio model entry
    auto& presets = radioPresets[radioModel];
    
    // Check if preset already exists
    for (auto& existingPreset : presets) {
        if (existingPreset.presetNumber == presetNumber) {
            existingPreset = preset;
            return true;
        }
    }
    
    // Add new preset
    presets.push_back(preset);
    return true;
}

bool PresetChannelManager::setPresetFrequency(const std::string& radioModel, int presetNumber, double frequency, 
                                             const std::string& label, const std::string& description) {
    if (!isInitialized) return false;
    
    PresetChannelInfo preset;
    preset.presetNumber = presetNumber;
    preset.channelNumber = 0; // Will be calculated based on frequency
    preset.frequency = frequency;
    preset.label = label;
    preset.description = description;
    preset.isActive = true;
    
    // Find or create radio model entry
    auto& presets = radioPresets[radioModel];
    
    // Check if preset already exists
    for (auto& existingPreset : presets) {
        if (existingPreset.presetNumber == presetNumber) {
            existingPreset = preset;
            return true;
        }
    }
    
    // Add new preset
    presets.push_back(preset);
    return true;
}

PresetChannelInfo PresetChannelManager::getPresetChannel(const std::string& radioModel, int presetNumber) {
    if (!isInitialized) return PresetChannelInfo();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return PresetChannelInfo();
    
    for (const auto& preset : it->second) {
        if (preset.presetNumber == presetNumber) {
            return preset;
        }
    }
    
    return PresetChannelInfo();
}

std::vector<PresetChannelInfo> PresetChannelManager::getAllPresetChannels(const std::string& radioModel) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    return it->second;
}

bool PresetChannelManager::deletePresetChannel(const std::string& radioModel, int presetNumber) {
    if (!isInitialized) return false;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return false;
    
    auto& presets = it->second;
    for (auto presetIt = presets.begin(); presetIt != presets.end(); ++presetIt) {
        if (presetIt->presetNumber == presetNumber) {
            presets.erase(presetIt);
            return true;
        }
    }
    
    return false;
}

bool PresetChannelManager::clearAllPresets(const std::string& radioModel) {
    if (!isInitialized) return false;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return false;
    
    it->second.clear();
    return true;
}

bool PresetChannelManager::selectPresetChannel(const std::string& radioModel, int presetNumber) {
    if (!isInitialized) return false;
    
    auto preset = getPresetChannel(radioModel, presetNumber);
    return preset.presetNumber != 0;
}

bool PresetChannelManager::isPresetActive(const std::string& radioModel, int presetNumber) {
    if (!isInitialized) return false;
    
    auto preset = getPresetChannel(radioModel, presetNumber);
    return preset.isActive;
}

bool PresetChannelManager::setPresetLabel(const std::string& radioModel, int presetNumber, const std::string& label) {
    if (!isInitialized) return false;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return false;
    
    for (auto& preset : it->second) {
        if (preset.presetNumber == presetNumber) {
            preset.label = label;
            return true;
        }
    }
    
    return false;
}

bool PresetChannelManager::setPresetDescription(const std::string& radioModel, int presetNumber, const std::string& description) {
    if (!isInitialized) return false;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return false;
    
    for (auto& preset : it->second) {
        if (preset.presetNumber == presetNumber) {
            preset.description = description;
            return true;
        }
    }
    
    return false;
}

bool PresetChannelManager::setPresetActive(const std::string& radioModel, int presetNumber, bool active) {
    if (!isInitialized) return false;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return false;
    
    for (auto& preset : it->second) {
        if (preset.presetNumber == presetNumber) {
            preset.isActive = active;
            return true;
        }
    }
    
    return false;
}

bool PresetChannelManager::validatePresetChannel(const std::string& radioModel, int presetNumber, int channelNumber) {
    if (!isInitialized) return false;
    
    // Basic validation - can be extended based on radio model specifications
    return presetNumber > 0 && presetNumber <= 99 && channelNumber > 0;
}

bool PresetChannelManager::validatePresetFrequency(const std::string& radioModel, int presetNumber, double frequency) {
    if (!isInitialized) return false;
    
    // Basic validation - can be extended based on radio model specifications
    return presetNumber > 0 && presetNumber <= 99 && frequency > 0.0;
}

std::vector<std::string> PresetChannelManager::getPresetValidationErrors(const std::string& radioModel, int presetNumber) {
    std::vector<std::string> errors;
    
    if (presetNumber < 1 || presetNumber > 99) {
        errors.push_back("Preset number must be between 1 and 99");
    }
    
    return errors;
}

std::vector<PresetChannelInfo> PresetChannelManager::searchPresets(const std::string& radioModel, const std::string& query) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    std::vector<PresetChannelInfo> results;
    for (const auto& preset : it->second) {
        if (preset.label.find(query) != std::string::npos || 
            preset.description.find(query) != std::string::npos) {
            results.push_back(preset);
        }
    }
    
    return results;
}

std::vector<PresetChannelInfo> PresetChannelManager::getPresetsByFrequency(const std::string& radioModel, double frequency, double tolerance) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    std::vector<PresetChannelInfo> results;
    for (const auto& preset : it->second) {
        if (std::abs(preset.frequency - frequency) <= tolerance) {
            results.push_back(preset);
        }
    }
    
    return results;
}

std::vector<PresetChannelInfo> PresetChannelManager::getPresetsByChannel(const std::string& radioModel, int channelNumber) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    std::vector<PresetChannelInfo> results;
    for (const auto& preset : it->second) {
        if (preset.channelNumber == channelNumber) {
            results.push_back(preset);
        }
    }
    
    return results;
}

std::vector<PresetChannelInfo> PresetChannelManager::getActivePresets(const std::string& radioModel) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    std::vector<PresetChannelInfo> results;
    for (const auto& preset : it->second) {
        if (preset.isActive) {
            results.push_back(preset);
        }
    }
    
    return results;
}

std::vector<PresetChannelInfo> PresetChannelManager::getInactivePresets(const std::string& radioModel) {
    if (!isInitialized) return std::vector<PresetChannelInfo>();
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return std::vector<PresetChannelInfo>();
    
    std::vector<PresetChannelInfo> results;
    for (const auto& preset : it->second) {
        if (!preset.isActive) {
            results.push_back(preset);
        }
    }
    
    return results;
}

int PresetChannelManager::getPresetCount(const std::string& radioModel) {
    if (!isInitialized) return 0;
    
    auto it = radioPresets.find(radioModel);
    if (it == radioPresets.end()) return 0;
    
    return static_cast<int>(it->second.size());
}

int PresetChannelManager::getActivePresetCount(const std::string& radioModel) {
    if (!isInitialized) return 0;
    
    auto activePresets = getActivePresets(radioModel);
    return static_cast<int>(activePresets.size());
}

int PresetChannelManager::getInactivePresetCount(const std::string& radioModel) {
    if (!isInitialized) return 0;
    
    auto inactivePresets = getInactivePresets(radioModel);
    return static_cast<int>(inactivePresets.size());
}

double PresetChannelManager::getPresetFrequencyRange(const std::string& radioModel) {
    if (!isInitialized) return 0.0;
    
    auto presets = getAllPresetChannels(radioModel);
    if (presets.empty()) return 0.0;
    
    double minFreq = presets[0].frequency;
    double maxFreq = presets[0].frequency;
    
    for (const auto& preset : presets) {
        if (preset.frequency < minFreq) minFreq = preset.frequency;
        if (preset.frequency > maxFreq) maxFreq = preset.frequency;
    }
    
    return maxFreq - minFreq;
}

std::map<int, int> PresetChannelManager::getPresetChannelDistribution(const std::string& radioModel) {
    if (!isInitialized) return std::map<int, int>();
    
    auto presets = getAllPresetChannels(radioModel);
    std::map<int, int> distribution;
    
    for (const auto& preset : presets) {
        distribution[preset.channelNumber]++;
    }
    
    return distribution;
}

std::string PresetChannelManager::exportPresetsToJSON(const std::string& radioModel) {
    if (!isInitialized) return "{}";
    
    auto presets = getAllPresetChannels(radioModel);
    std::ostringstream json;
    
    json << "[";
    for (size_t i = 0; i < presets.size(); ++i) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"presetNumber\":" << presets[i].presetNumber << ",";
        json << "\"channelNumber\":" << presets[i].channelNumber << ",";
        json << "\"frequency\":" << presets[i].frequency << ",";
        json << "\"label\":\"" << presets[i].label << "\",";
        json << "\"description\":\"" << presets[i].description << "\",";
        json << "\"isActive\":" << (presets[i].isActive ? "true" : "false");
        json << "}";
    }
    json << "]";
    
    return json.str();
}

bool PresetChannelManager::importPresetsFromJSON(const std::string& radioModel, const std::string& jsonData, bool overwrite) {
    if (!isInitialized) return false;
    
    // Simplified JSON import - in a real implementation, you would use a proper JSON library
    if (overwrite) {
        clearAllPresets(radioModel);
    }
    
    return true;
}

std::string PresetChannelManager::exportPresetsToCSV(const std::string& radioModel) {
    if (!isInitialized) return "";
    
    auto presets = getAllPresetChannels(radioModel);
    std::ostringstream csv;
    
    csv << "PresetNumber,ChannelNumber,Frequency,Label,Description,IsActive\n";
    for (const auto& preset : presets) {
        csv << preset.presetNumber << ",";
        csv << preset.channelNumber << ",";
        csv << preset.frequency << ",";
        csv << "\"" << preset.label << "\",";
        csv << "\"" << preset.description << "\",";
        csv << (preset.isActive ? "true" : "false") << "\n";
    }
    
    return csv.str();
}

bool PresetChannelManager::importPresetsFromCSV(const std::string& radioModel, const std::string& csvData, bool overwrite) {
    if (!isInitialized) return false;
    
    // Simplified CSV import - in a real implementation, you would parse the CSV properly
    if (overwrite) {
        clearAllPresets(radioModel);
    }
    
    return true;
}

std::string PresetChannelManager::backupPresets(const std::string& radioModel) {
    return exportPresetsToJSON(radioModel);
}

bool PresetChannelManager::restorePresets(const std::string& radioModel, const std::string& backupData) {
    return importPresetsFromJSON(radioModel, backupData, true);
}

bool PresetChannelManager::clearPresets(const std::string& radioModel) {
    return clearAllPresets(radioModel);
}

std::map<std::string, std::string> PresetChannelManager::comparePresets(const std::string& radioModel1, const std::string& radioModel2) {
    std::map<std::string, std::string> comparison;
    
    auto presets1 = getAllPresetChannels(radioModel1);
    auto presets2 = getAllPresetChannels(radioModel2);
    
    comparison["model1"] = radioModel1;
    comparison["model2"] = radioModel2;
    comparison["presets1_count"] = std::to_string(presets1.size());
    comparison["presets2_count"] = std::to_string(presets2.size());
    
    return comparison;
}

std::vector<PresetChannelInfo> PresetChannelManager::getCommonPresets(const std::string& radioModel1, const std::string& radioModel2) {
    auto presets1 = getAllPresetChannels(radioModel1);
    auto presets2 = getAllPresetChannels(radioModel2);
    
    std::vector<PresetChannelInfo> common;
    for (const auto& preset1 : presets1) {
        for (const auto& preset2 : presets2) {
            if (preset1.presetNumber == preset2.presetNumber) {
                common.push_back(preset1);
                break;
            }
        }
    }
    
    return common;
}

std::vector<PresetChannelInfo> PresetChannelManager::getUniquePresets(const std::string& radioModel1, const std::string& radioModel2) {
    auto presets1 = getAllPresetChannels(radioModel1);
    auto presets2 = getAllPresetChannels(radioModel2);
    
    std::vector<PresetChannelInfo> unique;
    for (const auto& preset1 : presets1) {
        bool found = false;
        for (const auto& preset2 : presets2) {
            if (preset1.presetNumber == preset2.presetNumber) {
                found = true;
                break;
            }
        }
        if (!found) {
            unique.push_back(preset1);
        }
    }
    
    return unique;
}

std::vector<PresetChannelInfo> PresetChannelManager::getPresetRecommendations(const std::string& radioModel, const std::string& criteria) {
    // Simplified recommendations - in a real implementation, this would be more sophisticated
    return searchPresets(radioModel, criteria);
}

std::vector<PresetChannelInfo> PresetChannelManager::getPopularPresets(const std::string& radioModel) {
    // Simplified popular presets - in a real implementation, this would track usage
    return getActivePresets(radioModel);
}

std::vector<PresetChannelInfo> PresetChannelManager::getRecentlyUsedPresets(const std::string& radioModel) {
    // Simplified recent presets - in a real implementation, this would track usage history
    return getActivePresets(radioModel);
}

} // namespace PresetChannelAPI
