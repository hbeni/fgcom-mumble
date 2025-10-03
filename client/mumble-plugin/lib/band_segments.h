/*
 * Band Segments API for FGCom-mumble
 * Provides frequency band segment definitions and utilities
 */

#ifndef BAND_SEGMENTS_H
#define BAND_SEGMENTS_H

#include <string>
#include <vector>
#include <map>

namespace FGComBandSegments {

// Frequency band segment data structure
struct BandSegment {
    std::string name;
    double start_frequency_mhz;
    double end_frequency_mhz;
    std::string band_type; // "amateur", "commercial", "military", "aviation", "maritime"
    std::string region; // "ITU_Region_1", "ITU_Region_2", "ITU_Region_3"
    bool is_allocated;
    std::string allocation_notes;
    
    BandSegment() : start_frequency_mhz(0.0), end_frequency_mhz(0.0), 
                    band_type("amateur"), region("ITU_Region_1"), is_allocated(false) {}
};

// Band segment manager
class BandSegmentManager {
public:
    static std::vector<BandSegment> getAllBandSegments();
    static std::vector<BandSegment> getBandSegmentsByType(const std::string& band_type);
    static std::vector<BandSegment> getBandSegmentsByRegion(const std::string& region);
    static BandSegment getBandSegmentForFrequency(double frequency_mhz);
    static bool isFrequencyInBand(double frequency_mhz, const std::string& band_name);
    static std::vector<BandSegment> getOverlappingSegments(double start_freq, double end_freq);
};

} // namespace FGComBandSegments

#endif // BAND_SEGMENTS_H


