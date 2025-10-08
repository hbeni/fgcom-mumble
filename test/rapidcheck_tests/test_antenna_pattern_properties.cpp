#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <gtest/gtest.h>
#include <cmath>
#include <algorithm>
#include <vector>
#include <map>
#include <limits>

// Mock antenna pattern classes for property-based testing
class AntennaPattern {
public:
    struct GainPoint {
        double azimuth;    // degrees
        double elevation;  // degrees
        double gain_db;    // gain in dB
    };
    
    struct AntennaPattern3D {
        std::vector<GainPoint> points;
        double frequency_hz;
        std::string antenna_type;
    };
    
    // Calculate gain at specific azimuth and elevation
    static double getGainAt(const AntennaPattern3D& pattern, double azimuth, double elevation) {
        // Simple interpolation for property testing
        double min_distance = std::numeric_limits<double>::max();
        double closest_gain = 0.0;
        
        for (const auto& point : pattern.points) {
            double az_diff = std::abs(azimuth - point.azimuth);
            double el_diff = std::abs(elevation - point.elevation);
            double distance = std::sqrt(az_diff * az_diff + el_diff * el_diff);
            
            if (distance < min_distance) {
                min_distance = distance;
                closest_gain = point.gain_db;
            }
        }
        
        return closest_gain;
    }
    
    // Calculate maximum gain
    static double getMaximumGain(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 0.0;
        
        double max_gain = pattern.points[0].gain_db;
        for (const auto& point : pattern.points) {
            max_gain = std::max(max_gain, point.gain_db);
        }
        return max_gain;
    }
    
    // Calculate minimum gain
    static double getMinimumGain(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 0.0;
        
        double min_gain = pattern.points[0].gain_db;
        for (const auto& point : pattern.points) {
            min_gain = std::min(min_gain, point.gain_db);
        }
        return min_gain;
    }
    
    // Calculate front-to-back ratio
    static double getFrontToBackRatio(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 0.0;
        
        double front_gain = getGainAt(pattern, 0.0, 0.0);
        double back_gain = getGainAt(pattern, 180.0, 0.0);
        
        return front_gain - back_gain;
    }
    
    // Calculate 3dB beamwidth in azimuth
    static double get3dBBeamwidthAzimuth(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 360.0;
        
        double max_gain = getMaximumGain(pattern);
        double threshold = max_gain - 3.0;
        
        std::vector<double> azimuths;
        for (const auto& point : pattern.points) {
            if (point.gain_db >= threshold) {
                azimuths.push_back(point.azimuth);
            }
        }
        
        if (azimuths.size() < 2) return 360.0;
        
        std::sort(azimuths.begin(), azimuths.end());
        return azimuths.back() - azimuths.front();
    }
    
    // Calculate 3dB beamwidth in elevation
    static double get3dBBeamwidthElevation(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 180.0;
        
        double max_gain = getMaximumGain(pattern);
        double threshold = max_gain - 3.0;
        
        std::vector<double> elevations;
        for (const auto& point : pattern.points) {
            if (point.gain_db >= threshold) {
                elevations.push_back(point.elevation);
            }
        }
        
        if (elevations.size() < 2) return 180.0;
        
        std::sort(elevations.begin(), elevations.end());
        return elevations.back() - elevations.front();
    }
    
    // Rotate antenna pattern
    static AntennaPattern3D rotatePattern(const AntennaPattern3D& pattern, double rotation_azimuth) {
        AntennaPattern3D rotated = pattern;
        for (auto& point : rotated.points) {
            point.azimuth = std::fmod(point.azimuth + rotation_azimuth + 360.0, 360.0);
        }
        return rotated;
    }
    
    // Scale antenna pattern gain
    static AntennaPattern3D scalePattern(const AntennaPattern3D& pattern, double scale_factor) {
        AntennaPattern3D scaled = pattern;
        for (auto& point : scaled.points) {
            point.gain_db *= scale_factor;
        }
        return scaled;
    }
    
    // Calculate pattern symmetry (for omnidirectional antennas)
    static double calculateSymmetry(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 0.0;
        
        double total_variance = 0.0;
        int count = 0;
        
        for (const auto& point : pattern.points) {
            double opposite_azimuth = std::fmod(point.azimuth + 180.0, 360.0);
            double gain_at_opposite = getGainAt(pattern, opposite_azimuth, point.elevation);
            double difference = std::abs(point.gain_db - gain_at_opposite);
            total_variance += difference * difference;
            count++;
        }
        
        return count > 0 ? std::sqrt(total_variance / count) : 0.0;
    }
    
    // Calculate pattern efficiency
    static double calculateEfficiency(const AntennaPattern3D& pattern) {
        if (pattern.points.empty()) return 0.0;
        
        double total_gain = 0.0;
        for (const auto& point : pattern.points) {
            total_gain += std::pow(10.0, point.gain_db / 10.0);
        }
        
        double average_gain_linear = total_gain / pattern.points.size();
        return average_gain_linear;
    }
    
    // Check if pattern is omnidirectional
    static bool isOmnidirectional(const AntennaPattern3D& pattern, double tolerance_db) {
        if (pattern.points.empty()) return false;
        
        double max_gain = getMaximumGain(pattern);
        double min_gain = getMinimumGain(pattern);
        
        return (max_gain - min_gain) <= tolerance_db;
    }
    
    // Check if pattern is directional
    static bool isDirectional(const AntennaPattern3D& pattern, double threshold_db) {
        if (pattern.points.empty()) return false;
        
        double max_gain = getMaximumGain(pattern);
        double min_gain = getMinimumGain(pattern);
        
        return (max_gain - min_gain) >= threshold_db;
    }
};

// Property-based tests for antenna patterns
RC_GTEST_PROP(AntennaPatternTests,
              MaximumGainIsLargest,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double max_gain = AntennaPattern::getMaximumGain(pattern);
    
    for (const auto& point : pattern.points) {
        RC_ASSERT(point.gain_db <= max_gain);
    }
}

RC_GTEST_PROP(AntennaPatternTests,
              MinimumGainIsSmallest,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double min_gain = AntennaPattern::getMinimumGain(pattern);
    
    for (const auto& point : pattern.points) {
        RC_ASSERT(point.gain_db >= min_gain);
    }
}

RC_GTEST_PROP(AntennaPatternTests,
              MaximumGainGreaterThanOrEqualToMinimumGain,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double max_gain = AntennaPattern::getMaximumGain(pattern);
    double min_gain = AntennaPattern::getMinimumGain(pattern);
    
    RC_ASSERT(max_gain >= min_gain);
}

RC_GTEST_PROP(AntennaPatternTests,
              FrontToBackRatioIsNonNegative,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double fbr = AntennaPattern::getFrontToBackRatio(pattern);
    RC_ASSERT(fbr >= 0.0);
}

RC_GTEST_PROP(AntennaPatternTests,
              BeamwidthIsPositive,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double beamwidth_az = AntennaPattern::get3dBBeamwidthAzimuth(pattern);
    double beamwidth_el = AntennaPattern::get3dBBeamwidthElevation(pattern);
    
    RC_ASSERT(beamwidth_az > 0.0);
    RC_ASSERT(beamwidth_el > 0.0);
}

RC_GTEST_PROP(AntennaPatternTests,
              BeamwidthIsWithinReasonableBounds,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double beamwidth_az = AntennaPattern::get3dBBeamwidthAzimuth(pattern);
    double beamwidth_el = AntennaPattern::get3dBBeamwidthElevation(pattern);
    
    RC_ASSERT(beamwidth_az <= 360.0);
    RC_ASSERT(beamwidth_el <= 180.0);
}

RC_GTEST_PROP(AntennaPatternTests,
              RotationPreservesGainValues,
              (AntennaPattern::AntennaPattern3D pattern, double rotation_azimuth)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(rotation_azimuth >= 0.0 && rotation_azimuth < 360.0);
    
    AntennaPattern::AntennaPattern3D rotated = AntennaPattern::rotatePattern(pattern, rotation_azimuth);
    
    // Check that all gain values are preserved
    std::map<double, int> original_gains;
    std::map<double, int> rotated_gains;
    
    for (const auto& point : pattern.points) {
        original_gains[point.gain_db]++;
    }
    
    for (const auto& point : rotated.points) {
        rotated_gains[point.gain_db]++;
    }
    
    RC_ASSERT(original_gains == rotated_gains);
}

RC_GTEST_PROP(AntennaPatternTests,
              ScalingPreservesRelativeGain,
              (AntennaPattern::AntennaPattern3D pattern, double scale_factor)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(scale_factor > 0.0);
    RC_PRE(scale_factor < 10.0);
    
    AntennaPattern::AntennaPattern3D scaled = AntennaPattern::scalePattern(pattern, scale_factor);
    
    // Check that relative gain differences are preserved
    for (size_t i = 0; i < pattern.points.size(); ++i) {
        for (size_t j = i + 1; j < pattern.points.size(); ++j) {
            double original_diff = pattern.points[i].gain_db - pattern.points[j].gain_db;
            double scaled_diff = scaled.points[i].gain_db - scaled.points[j].gain_db;
            
            RC_ASSERT(std::abs(original_diff - scaled_diff) < 1e-6);
        }
    }
}

RC_GTEST_PROP(AntennaPatternTests,
              SymmetryCalculationIsNonNegative,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double symmetry = AntennaPattern::calculateSymmetry(pattern);
    RC_ASSERT(symmetry >= 0.0);
}

RC_GTEST_PROP(AntennaPatternTests,
              EfficiencyIsNonNegative,
              (AntennaPattern::AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double efficiency = AntennaPattern::calculateEfficiency(pattern);
    RC_ASSERT(efficiency >= 0.0);
}

RC_GTEST_PROP(AntennaPatternTests,
              OmnidirectionalCheckIsConsistent,
              (AntennaPattern::AntennaPattern3D pattern, double tolerance_db)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(tolerance_db >= 0.0);
    RC_PRE(tolerance_db <= 20.0);
    
    bool is_omni = AntennaPattern::isOmnidirectional(pattern, tolerance_db);
    bool is_directional = AntennaPattern::isDirectional(pattern, tolerance_db);
    
    // Cannot be both omnidirectional and directional
    RC_ASSERT(!(is_omni && is_directional));
}

RC_GTEST_PROP(AntennaPatternTests,
              GainInterpolationIsBounded,
              (AntennaPattern::AntennaPattern3D pattern, double azimuth, double elevation)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(azimuth >= 0.0 && azimuth < 360.0);
    RC_PRE(elevation >= -90.0 && elevation <= 90.0);
    
    double interpolated_gain = AntennaPattern::getGainAt(pattern, azimuth, elevation);
    double max_gain = AntennaPattern::getMaximumGain(pattern);
    double min_gain = AntennaPattern::getMinimumGain(pattern);
    
    RC_ASSERT(interpolated_gain >= min_gain);
    RC_ASSERT(interpolated_gain <= max_gain);
}

RC_GTEST_PROP(AntennaPatternTests,
              PatternConsistencyAfterRotation,
              (AntennaPattern::AntennaPattern3D pattern, double rotation1, double rotation2)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(rotation1 >= 0.0 && rotation1 < 360.0);
    RC_PRE(rotation2 >= 0.0 && rotation2 < 360.0);
    
    AntennaPattern::AntennaPattern3D rotated1 = AntennaPattern::rotatePattern(pattern, rotation1);
    AntennaPattern::AntennaPattern3D rotated2 = AntennaPattern::rotatePattern(rotated1, rotation2);
    AntennaPattern::AntennaPattern3D direct_rotation = AntennaPattern::rotatePattern(pattern, rotation1 + rotation2);
    
    // Check that double rotation equals direct rotation
    RC_ASSERT(rotated2.points.size() == direct_rotation.points.size());
    
    for (size_t i = 0; i < rotated2.points.size(); ++i) {
        RC_ASSERT(std::abs(rotated2.points[i].gain_db - direct_rotation.points[i].gain_db) < 1e-6);
    }
}

RC_GTEST_PROP(AntennaPatternTests,
              FrequencyDependentGainScaling,
              (AntennaPattern::AntennaPattern3D pattern, double frequency1_hz, double frequency2_hz)) {
    RC_PRE(!pattern.points.empty());
    RC_PRE(frequency1_hz > 0.0);
    RC_PRE(frequency2_hz > 0.0);
    RC_PRE(frequency1_hz != frequency2_hz);
    
    // Create frequency-scaled patterns
    AntennaPattern::AntennaPattern3D pattern1 = pattern;
    AntennaPattern::AntennaPattern3D pattern2 = pattern;
    
    pattern1.frequency_hz = frequency1_hz;
    pattern2.frequency_hz = frequency2_hz;
    
    // Scale gains based on frequency (simplified model)
    double freq_ratio = frequency2_hz / frequency1_hz;
    for (size_t i = 0; i < pattern2.points.size(); ++i) {
        pattern2.points[i].gain_db += 20.0 * std::log10(freq_ratio);
    }
    
    // Check that frequency scaling is consistent
    double max_gain1 = AntennaPattern::getMaximumGain(pattern1);
    double max_gain2 = AntennaPattern::getMaximumGain(pattern2);
    
    double expected_ratio = 20.0 * std::log10(freq_ratio);
    double actual_ratio = max_gain2 - max_gain1;
    
    RC_ASSERT(std::abs(actual_ratio - expected_ratio) < 1e-6);
}

// Custom generators for antenna patterns
namespace rc {
    template<>
    struct Arbitrary<AntennaPattern::GainPoint> {
        static Gen<AntennaPattern::GainPoint> arbitrary() {
            return gen::construct<AntennaPattern::GainPoint>(
                gen::inRange(0.0, 360.0),      // azimuth
                gen::inRange(-90.0, 90.0),     // elevation
                gen::inRange(-50.0, 20.0)      // gain in dB
            );
        }
    };
    
    template<>
    struct Arbitrary<AntennaPattern::AntennaPattern3D> {
        static Gen<AntennaPattern::AntennaPattern3D> arbitrary() {
            return gen::construct<AntennaPattern::AntennaPattern3D>(
                gen::container<std::vector<AntennaPattern::GainPoint>>(
                    gen::inRange(1, 100),  // 1 to 100 points
                    gen::arbitrary<AntennaPattern::GainPoint>()
                ),
                gen::inRange(1e6, 1e12),  // frequency
                gen::element<std::string>("omnidirectional", "directional", "yagi", "dipole")
            );
        }
    };
}
