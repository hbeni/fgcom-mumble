#ifndef FGCOM_PATTERN_INTERPOLATION_H
#define FGCOM_PATTERN_INTERPOLATION_H

#include <vector>
#include <map>
#include <string>
#include <memory>

// 4NEC2 radiation pattern data structure
struct FGCom_RadiationPattern {
    double theta;           // Elevation angle (degrees)
    double phi;             // Azimuth angle (degrees)
    double gain_dbi;        // Gain in dBi
    double phase_deg;       // Phase in degrees
    std::string polarization; // "V" for vertical, "H" for horizontal
    
    FGCom_RadiationPattern() : theta(0), phi(0), gain_dbi(0), phase_deg(0), polarization("V") {}
    FGCom_RadiationPattern(double t, double p, double g, double ph, const std::string& pol)
        : theta(t), phi(p), gain_dbi(g), phase_deg(ph), polarization(pol) {}
};

// Altitude-specific pattern data
struct FGCom_AltitudePattern {
    int altitude_m;         // Altitude in meters
    double frequency_mhz;   // Frequency in MHz
    std::vector<FGCom_RadiationPattern> patterns;
    
    FGCom_AltitudePattern() : altitude_m(0), frequency_mhz(0) {}
    FGCom_AltitudePattern(int alt, double freq) : altitude_m(alt), frequency_mhz(freq) {}
};

// Pattern interpolation class for altitude-dependent radiation patterns
class FGCom_PatternInterpolation {
private:
    // Map: antenna_name -> altitude -> pattern data
    std::map<std::string, std::map<int, FGCom_AltitudePattern>> antenna_patterns;
    
    // Critical altitude ranges for aircraft
    static const std::vector<int> GROUND_EFFECT_ALTITUDES;
    static const std::vector<int> LOW_ALTITUDE_ALTITUDES;
    static const std::vector<int> MEDIUM_ALTITUDE_ALTITUDES;
    static const std::vector<int> HIGH_ALTITUDE_ALTITUDES;
    
public:
    FGCom_PatternInterpolation();
    ~FGCom_PatternInterpolation();
    
    // Load 4NEC2 pattern file (.out format)
    bool load4NEC2Pattern(const std::string& filename, const std::string& antenna_name, 
                         int altitude_m, double frequency_mhz);
    
    // Load multiple altitude patterns for an antenna
    bool loadAltitudePatterns(const std::string& antenna_name, const std::string& pattern_dir);
    
    // Get interpolated gain at specific angle and altitude
    double getInterpolatedGain(const std::string& antenna_name, int altitude_m, 
                              double frequency_mhz, double theta_deg, double phi_deg);
    
    // Get interpolated gain with bilinear interpolation
    double getBilinearInterpolatedGain(const std::string& antenna_name, int altitude_m,
                                      double frequency_mhz, double theta_deg, double phi_deg);
    
    // Get pattern at specific altitude (closest match)
    const FGCom_AltitudePattern* getPatternAtAltitude(const std::string& antenna_name, 
                                                      int altitude_m, double frequency_mhz);
    
    // Get ground effect factor based on altitude
    double getGroundEffectFactor(int altitude_m, double frequency_mhz);
    
    // Get multipath interference factor
    double getMultipathFactor(int altitude_m, double frequency_mhz, double theta_deg);
    
    // Calculate altitude-dependent pattern characteristics
    struct AltitudeCharacteristics {
        double ground_effect_factor;    // 0.0 (free space) to 1.0 (full ground effects)
        double multipath_factor;        // Multipath interference strength
        double pattern_stability;       // Pattern stability (0.0 to 1.0)
        std::string dominant_mode;      // "ground_wave", "sky_wave", "mixed"
    };
    
    AltitudeCharacteristics getAltitudeCharacteristics(int altitude_m, double frequency_mhz);
    
    // Utility functions
    bool isAntennaLoaded(const std::string& antenna_name);
    std::vector<int> getAvailableAltitudes(const std::string& antenna_name);
    std::vector<double> getAvailableFrequencies(const std::string& antenna_name);
    
    // Pattern analysis functions
    double getMaximumGain(const std::string& antenna_name, int altitude_m, double frequency_mhz);
    double getMinimumGain(const std::string& antenna_name, int altitude_m, double frequency_mhz);
    double getAverageGain(const std::string& antenna_name, int altitude_m, double frequency_mhz);
    
    // Ground effect calculations
    double calculateGroundReflectionCoefficient(int altitude_m, double frequency_mhz, 
                                               double theta_deg, double ground_conductivity);
    double calculatePathDifference(int altitude_m, double theta_deg);
    double calculatePhaseDifference(double path_diff_m, double frequency_mhz);
    
    // Pattern smoothing and filtering
    void smoothPattern(FGCom_AltitudePattern& pattern, double smoothing_factor = 0.1);
    void filterPattern(FGCom_AltitudePattern& pattern, double min_gain_threshold = -30.0);
    
private:
    // Internal interpolation functions
    double linearInterpolate(double x1, double y1, double x2, double y2, double x);
    double bilinearInterpolate(double x1, double y1, double x2, double y2, 
                              double x, double y, double q11, double q12, double q21, double q22);
    
    // Find closest pattern points for interpolation
    std::vector<FGCom_RadiationPattern*> findClosestPatterns(
        const FGCom_AltitudePattern& pattern, double theta_deg, double phi_deg, int count = 4);
    
    // Parse 4NEC2 output file
    bool parse4NEC2File(const std::string& filename, FGCom_AltitudePattern& pattern);
    
    // Validate pattern data
    bool validatePattern(const FGCom_AltitudePattern& pattern);
    
    // Calculate pattern statistics
    struct PatternStats {
        double max_gain;
        double min_gain;
        double avg_gain;
        double std_dev;
        int total_points;
    };
    
    PatternStats calculatePatternStats(const FGCom_AltitudePattern& pattern);
};

// Global pattern interpolation instance
extern std::unique_ptr<FGCom_PatternInterpolation> g_pattern_interpolation;

// Utility functions for altitude-dependent calculations
namespace FGCom_AltitudeUtils {
    // Get altitude category
    enum AltitudeCategory {
        GROUND_EFFECT,      // 0-1000m
        LOW_ALTITUDE,       // 1000-3000m  
        MEDIUM_ALTITUDE,    // 3000-8000m
        HIGH_ALTITUDE       // 8000m+
    };
    
    AltitudeCategory getAltitudeCategory(int altitude_m);
    
    // Get recommended sampling interval for altitude
    int getRecommendedSamplingInterval(int altitude_m);
    
    // Check if altitude is in critical transition zone
    bool isCriticalTransitionZone(int altitude_m);
    
    // Get ground effect strength (0.0 to 1.0)
    double getGroundEffectStrength(int altitude_m, double frequency_mhz);
    
    // Calculate multipath null depth
    double calculateMultipathNullDepth(int altitude_m, double frequency_mhz, double theta_deg);
}

#endif // FGCOM_PATTERN_INTERPOLATION_H
