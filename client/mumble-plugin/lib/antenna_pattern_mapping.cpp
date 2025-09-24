#include "antenna_pattern_mapping.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <memory>

// Global pattern mapping instance
std::unique_ptr<FGCom_AntennaPatternMapping> g_antenna_pattern_mapping = nullptr;

FGCom_AntennaPatternMapping::FGCom_AntennaPatternMapping() {
    initializeVHFPatterns();
    initializeUHFPatterns();
}

FGCom_AntennaPatternMapping::~FGCom_AntennaPatternMapping() {
    // Cleanup
}

void FGCom_AntennaPatternMapping::initializeVHFPatterns() {
    // Aircraft VHF patterns - using multiple frequencies for better coverage
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "b737_800_vhf", 
        "antenna_patterns/aircraft/b737_800/b737_800_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "c130_hercules_vhf",
        "antenna_patterns/aircraft/c130_hercules/c130_hercules_vhf.ez", 
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "cessna_172_vhf",
        "antenna_patterns/aircraft/cessna_172/cessna_172_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][150.0] = AntennaPatternInfo(
        "mi4_hound_vhf",
        "antenna_patterns/aircraft/mi4_hound/mi4_hound_vhf.ez",
        150.0, "aircraft", "blade"
    );
    
    // Add realistic aircraft patterns for different frequencies
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "b737_800_realistic",
        "antenna_patterns/aircraft/b737_800/b737_800_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "c130_hercules_realistic",
        "antenna_patterns/aircraft/c130_hercules/c130_hercules_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "cessna_172_realistic",
        "antenna_patterns/aircraft/cessna_172/cessna_172_realistic_final.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "bell_uh1_huey_realistic",
        "antenna_patterns/aircraft/bell_uh1_huey/bell_uh1_huey_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "mil_mi4_hound_realistic",
        "antenna_patterns/aircraft/mil_mi4_hound/mil_mi4_hound_fixed.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "tu95_bear_realistic",
        "antenna_patterns/aircraft/tu95_bear/tu95_bear_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "tu95_bear_vhf",
        "antenna_patterns/aircraft/tu95_bear/tu95_bear_vhf.ez",
        144.0, "aircraft", "blade"
    );
    
    // Ground vehicle VHF patterns
    vhf_patterns["ground_vehicle"][150.0] = AntennaPatternInfo(
        "leopard1_tank_vhf",
        "antenna_patterns/ground_vehicles/leopard1_tank/leopard1_tank_vhf.ez",
        150.0, "ground_vehicle", "whip"
    );
    
    vhf_patterns["ground_vehicle"][150.0] = AntennaPatternInfo(
        "soviet_uaz_vhf",
        "antenna_patterns/ground_vehicles/soviet_uaz/soviet_uaz_vhf.ez",
        150.0, "ground_vehicle", "whip"
    );
    
    // Ground-based VHF patterns (10m height)
    vhf_patterns["ground_station"][144.5] = AntennaPatternInfo(
        "yagi_144mhz",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_144mhz/yagi_144mhz_11element.ez",
        144.5, "ground_station", "yagi"
    );
    
    // Ground-based UHF patterns (10m height)
    uhf_patterns["ground_station"][432.0] = AntennaPatternInfo(
        "yagi_70cm",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_70cm/yagi_70cm_16element.ez",
        432.0, "ground_station", "yagi"
    );
    
    // Dual-band omnidirectional patterns (10m height)
    vhf_patterns["ground_station"][145.0] = AntennaPatternInfo(
        "dual_band_omni_vhf",
        "antenna_patterns/Ground-based/vertical/dual_band_omni/dual_band_omni_2m_70cm.ez",
        145.0, "ground_station", "omni"
    );
    
    uhf_patterns["ground_station"][432.0] = AntennaPatternInfo(
        "dual_band_omni_uhf",
        "antenna_patterns/Ground-based/vertical/dual_band_omni/dual_band_omni_2m_70cm.ez",
        432.0, "ground_station", "omni"
    );
    
    // Maritime VHF patterns - using existing boat and ship patterns
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "sailboat_backstay_vhf",
        "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez",
        150.0, "maritime", "backstay"
    );
    
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "sailboat_whip_vhf",
        "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez",
        150.0, "maritime", "whip"
    );
    
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "containership_vhf",
        "antenna_patterns/ship/containership/containership_80m_loop.ez",
        150.0, "maritime", "loop"
    );
    
    // Military land patterns
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "leopard1_nato_mbt_vhf",
        "antenna_patterns/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez",
        150.0, "military_land", "tank"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "nato_jeep_vhf",
        "antenna_patterns/military-land/nato_jeep_10ft_whip_45deg.ez",
        150.0, "military_land", "whip"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "soviet_uaz_military_vhf",
        "antenna_patterns/military-land/soviet_uaz_4m_whip_45deg.ez",
        150.0, "military_land", "whip"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "t55_soviet_mbt_vhf",
        "antenna_patterns/military-land/t55_soviet_mbt/t55_soviet_mbt.ez",
        150.0, "military_land", "tank"
    );
    
    // Vehicle patterns
    vhf_patterns["vehicle"][150.0] = AntennaPatternInfo(
        "ford_transit_vhf",
        "antenna_patterns/vehicle/ford_transit/ford_transit_camper_vertical.ez",
        150.0, "vehicle", "vertical"
    );
    
    vhf_patterns["vehicle"][150.0] = AntennaPatternInfo(
        "vw_passat_vhf",
        "antenna_patterns/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez",
        150.0, "vehicle", "vertical"
    );
    
    // Ground-based HF patterns for amateur radio
    vhf_patterns["ground_station"][3.5] = AntennaPatternInfo(
        "80m_loop_hf",
        "antenna_patterns/Ground-based/80m-loop/40m_patterns/80m_loop_40m.ez",
        3.5, "ground_station", "loop"
    );
    
    vhf_patterns["ground_station"][7.0] = AntennaPatternInfo(
        "dipole_80m_ew_hf",
        "antenna_patterns/Ground-based/dipole/dipole_80m_ew/dipole_80m_ew.ez",
        7.0, "ground_station", "dipole"
    );
    
    vhf_patterns["ground_station"][7.0] = AntennaPatternInfo(
        "dipole_80m_ns_hf",
        "antenna_patterns/Ground-based/dipole/dipole_80m_ns/dipole_80m_ns.ez",
        7.0, "ground_station", "dipole"
    );
    
    vhf_patterns["ground_station"][14.0] = AntennaPatternInfo(
        "yagi_20m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_20m/cushcraft_a3ws_20m.ez",
        14.0, "ground_station", "yagi"
    );
    
    vhf_patterns["ground_station"][21.0] = AntennaPatternInfo(
        "yagi_15m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_15m/hy_gain_th4dxx_15m.ez",
        21.0, "ground_station", "yagi"
    );
    
    vhf_patterns["ground_station"][28.0] = AntennaPatternInfo(
        "yagi_10m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_10m/hy_gain_th4dxx_10m.ez",
        28.0, "ground_station", "yagi"
    );
    
    vhf_patterns["ground_station"][50.0] = AntennaPatternInfo(
        "yagi_6m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_6m/hy_gain_vb64fm_6m.ez",
        50.0, "ground_station", "yagi"
    );
    
    vhf_patterns["ground_station"][144.0] = AntennaPatternInfo(
        "yagi_2m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_144mhz/yagi_144mhz_11element.ez",
        144.0, "ground_station", "yagi"
    );
    
    vhf_patterns["ground_station"][145.0] = AntennaPatternInfo(
        "vertical_2m_hf",
        "antenna_patterns/Ground-based/vertical/2m_vertical/2m_vertical_antenna.ez",
        145.0, "ground_station", "vertical"
    );
    
    // Coastal station patterns for maritime communications
    vhf_patterns["ground_station"][0.5] = AntennaPatternInfo(
        "t_type_500khz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/t_type_500khz_coastal_ew.ez",
        0.5, "ground_station", "t_type"
    );
    
    vhf_patterns["ground_station"][0.5] = AntennaPatternInfo(
        "t_type_500khz_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/t_type_500khz_coastal_ns.ez",
        0.5, "ground_station", "t_type"
    );
    
    vhf_patterns["ground_station"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2mhz_coastal_ew.ez",
        2.0, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2mhz_coastal_ns.ez",
        2.0, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/inverted_l_630m_coastal_ew.ez",
        630.0, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/inverted_l_630m_coastal_ns.ez",
        630.0, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2200m_coastal_ew.ez",
        2200.0, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2200m_coastal_ns.ez",
        2200.0, "ground_station", "long_wire"
    );
    
    // Maritime HF patterns for ship-to-shore communications
    vhf_patterns["maritime"][0.5] = AntennaPatternInfo(
        "t_type_500khz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz_ew.ez",
        0.5, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][0.5] = AntennaPatternInfo(
        "t_type_500khz_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz_ns.ez",
        0.5, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz_ew.ez",
        2.0, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz_ns.ez",
        2.0, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m_ew.ez",
        630.0, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m_ns.ez",
        630.0, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m_ew.ez",
        2200.0, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m_ns.ez",
        2200.0, "maritime", "long_wire"
    );
    
    // Add ALL missing aircraft realistic patterns
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "b737_800_realistic",
        "antenna_patterns/aircraft/b737_800/b737_800_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "bell_uh1_huey_realistic",
        "antenna_patterns/aircraft/bell_uh1_huey/bell_uh1_huey_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "c130_hercules_realistic",
        "antenna_patterns/aircraft/c130_hercules/c130_hercules_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "cessna_172_realistic",
        "antenna_patterns/aircraft/cessna_172/cessna_172_realistic_final.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "mil_mi4_hound_realistic",
        "antenna_patterns/aircraft/mil_mi4_hound/mil_mi4_hound_fixed.ez",
        144.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][144.0] = AntennaPatternInfo(
        "tu95_bear_realistic",
        "antenna_patterns/aircraft/tu95_bear/tu95_bear_realistic.ez",
        144.0, "aircraft", "blade"
    );
    
    // Add ALL missing boat patterns
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "sailboat_backstay_vhf",
        "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez",
        150.0, "maritime", "backstay"
    );
    
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "sailboat_whip_vhf",
        "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez",
        150.0, "maritime", "whip"
    );
    
    // Add ALL missing military land patterns
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "leopard1_nato_mbt_vhf",
        "antenna_patterns/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez",
        150.0, "military_land", "tank"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "nato_jeep_vhf",
        "antenna_patterns/military-land/nato_jeep_10ft_whip_45deg.ez",
        150.0, "military_land", "whip"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "soviet_uaz_military_vhf",
        "antenna_patterns/military-land/soviet_uaz_4m_whip_45deg.ez",
        150.0, "military_land", "whip"
    );
    
    vhf_patterns["military_land"][150.0] = AntennaPatternInfo(
        "t55_soviet_mbt_vhf",
        "antenna_patterns/military-land/t55_soviet_mbt/t55_soviet_mbt.ez",
        150.0, "military_land", "tank"
    );
    
    // Add ALL missing vehicle patterns
    vhf_patterns["vehicle"][150.0] = AntennaPatternInfo(
        "ford_transit_vhf",
        "antenna_patterns/vehicle/ford_transit/ford_transit_camper_vertical.ez",
        150.0, "vehicle", "vertical"
    );
    
    vhf_patterns["vehicle"][150.0] = AntennaPatternInfo(
        "vw_passat_vhf",
        "antenna_patterns/vehicle/vw_passat/vw_passat_hf_loaded_vertical.ez",
        150.0, "vehicle", "vertical"
    );
    
    // Add ALL missing ship patterns
    vhf_patterns["maritime"][150.0] = AntennaPatternInfo(
        "containership_vhf",
        "antenna_patterns/ship/containership/containership_80m_loop.ez",
        150.0, "maritime", "loop"
    );
    
    // Add ALL missing ground-based patterns
    vhf_patterns["ground_station"][160.0] = AntennaPatternInfo(
        "inverted_l_160m_hf",
        "antenna_patterns/Ground-based/other/inverted_l_160m/inverted_l_160m.ez",
        160.0, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][40.0] = AntennaPatternInfo(
        "yagi_40m_hf",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_40m/hy_gain_th3dxx_40m.ez",
        40.0, "ground_station", "yagi"
    );
    
    // Add ALL missing maritime HF patterns (EW orientations)
    vhf_patterns["maritime"][0.5] = AntennaPatternInfo(
        "t_type_500khz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz_ew.ez",
        0.5, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz_ew.ez",
        2.0, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m_ew.ez",
        630.0, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m_ew.ez",
        2200.0, "maritime", "long_wire"
    );
    
    // Add ALL missing coastal station patterns (EW orientations)
    vhf_patterns["ground_station"][0.5] = AntennaPatternInfo(
        "t_type_500khz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/t_type_500khz_coastal_ew.ez",
        0.5, "ground_station", "t_type"
    );
    
    vhf_patterns["ground_station"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2mhz_coastal_ew.ez",
        2.0, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/inverted_l_630m_coastal_ew.ez",
        630.0, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2200m_coastal_ew.ez",
        2200.0, "ground_station", "long_wire"
    );
    
    // Add ALL missing dipole patterns (EW orientation)
    vhf_patterns["ground_station"][7.0] = AntennaPatternInfo(
        "dipole_80m_ew_hf",
        "antenna_patterns/Ground-based/dipole/dipole_80m_ew/dipole_80m_ew.ez",
        7.0, "ground_station", "dipole"
    );
    
    // Add ALL missing maritime HF patterns (non-directional)
    vhf_patterns["maritime"][0.5] = AntennaPatternInfo(
        "t_type_500khz_maritime_omni",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz.ez",
        0.5, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][2.0] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_omni",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz.ez",
        2.0, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][630.0] = AntennaPatternInfo(
        "inverted_l_630m_maritime_omni",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m.ez",
        630.0, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][2200.0] = AntennaPatternInfo(
        "long_wire_2200m_maritime_omni",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m.ez",
        2200.0, "maritime", "long_wire"
    );
    
    // Add ALL missing aircraft VHF patterns (using different frequencies to avoid overwriting)
    vhf_patterns["aircraft"][151.0] = AntennaPatternInfo(
        "b737_800_vhf",
        "antenna_patterns/aircraft/b737_800/b737_800_vhf.ez",
        151.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][152.0] = AntennaPatternInfo(
        "c130_hercules_vhf",
        "antenna_patterns/aircraft/c130_hercules/c130_hercules_vhf.ez",
        152.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][153.0] = AntennaPatternInfo(
        "cessna_172_vhf",
        "antenna_patterns/aircraft/cessna_172/cessna_172_vhf.ez",
        153.0, "aircraft", "blade"
    );
    
    vhf_patterns["aircraft"][154.0] = AntennaPatternInfo(
        "mi4_hound_vhf",
        "antenna_patterns/aircraft/mi4_hound/mi4_hound_vhf.ez",
        154.0, "aircraft", "blade"
    );
    
    // Add ALL missing ground vehicle patterns (using different frequencies)
    vhf_patterns["ground_vehicle"][155.0] = AntennaPatternInfo(
        "leopard1_tank_vhf",
        "antenna_patterns/ground_vehicles/leopard1_tank/leopard1_tank_vhf.ez",
        155.0, "ground_vehicle", "whip"
    );
    
    vhf_patterns["ground_vehicle"][156.0] = AntennaPatternInfo(
        "soviet_uaz_vhf",
        "antenna_patterns/ground_vehicles/soviet_uaz/soviet_uaz_vhf.ez",
        156.0, "ground_vehicle", "whip"
    );
    
    vhf_patterns["ground_vehicle"][157.0] = AntennaPatternInfo(
        "military_vehicle_vhf",
        "antenna_patterns/ground_vehicles/military_vehicle/military_vehicle_vhf.ez",
        157.0, "ground_vehicle", "whip"
    );
    
    // Add ALL missing boat patterns (using different frequencies)
    vhf_patterns["maritime"][158.0] = AntennaPatternInfo(
        "sailboat_backstay_vhf",
        "antenna_patterns/boat/sailboat_backstay/sailboat_backstay_40m.ez",
        158.0, "maritime", "backstay"
    );
    
    vhf_patterns["maritime"][159.0] = AntennaPatternInfo(
        "sailboat_whip_vhf",
        "antenna_patterns/boat/sailboat_whip/sailboat_23ft_whip_20m.ez",
        159.0, "maritime", "whip"
    );
    
    // Add ALL missing military land patterns (using different frequencies)
    vhf_patterns["military_land"][160.0] = AntennaPatternInfo(
        "leopard1_nato_mbt_vhf",
        "antenna_patterns/military-land/leopard1_nato_mbt/leopard1_nato_mbt.ez",
        160.0, "military_land", "tank"
    );
    
    vhf_patterns["military_land"][161.0] = AntennaPatternInfo(
        "nato_jeep_vhf",
        "antenna_patterns/military-land/nato_jeep_10ft_whip_45deg.ez",
        161.0, "military_land", "whip"
    );
    
    vhf_patterns["military_land"][162.0] = AntennaPatternInfo(
        "soviet_uaz_military_vhf",
        "antenna_patterns/military-land/soviet_uaz_4m_whip_45deg.ez",
        162.0, "military_land", "whip"
    );
    
    // Add ALL missing vehicle patterns (using different frequencies)
    vhf_patterns["vehicle"][163.0] = AntennaPatternInfo(
        "ford_transit_vhf",
        "antenna_patterns/vehicle/ford_transit/ford_transit_camper_vertical.ez",
        163.0, "vehicle", "vertical"
    );
    
    // Add ALL missing coastal station patterns (EW orientations) with different frequencies
    vhf_patterns["ground_station"][0.6] = AntennaPatternInfo(
        "t_type_500khz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/t_type_500khz_coastal_ew.ez",
        0.6, "ground_station", "t_type"
    );
    
    vhf_patterns["ground_station"][2.1] = AntennaPatternInfo(
        "long_wire_2mhz_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2mhz_coastal_ew.ez",
        2.1, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][630.1] = AntennaPatternInfo(
        "inverted_l_630m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/inverted_l_630m_coastal_ew.ez",
        630.1, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][2200.1] = AntennaPatternInfo(
        "long_wire_2200m_coastal_ew",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2200m_coastal_ew.ez",
        2200.1, "ground_station", "long_wire"
    );
    
    // Add ALL missing maritime HF patterns (EW orientations) with different frequencies
    vhf_patterns["maritime"][0.6] = AntennaPatternInfo(
        "t_type_500khz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz_ew.ez",
        0.6, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][2.1] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz_ew.ez",
        2.1, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][630.1] = AntennaPatternInfo(
        "inverted_l_630m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m_ew.ez",
        630.1, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][2200.1] = AntennaPatternInfo(
        "long_wire_2200m_maritime_ew",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m_ew.ez",
        2200.1, "maritime", "long_wire"
    );
    
    // Add ALL missing dipole patterns (EW orientation) with different frequency
    vhf_patterns["ground_station"][7.1] = AntennaPatternInfo(
        "dipole_80m_ew_hf",
        "antenna_patterns/Ground-based/dipole/dipole_80m_ew/dipole_80m_ew.ez",
        7.1, "ground_station", "dipole"
    );
    
    // Add ALL missing maritime HF patterns (NS orientations) with different frequencies
    vhf_patterns["maritime"][0.7] = AntennaPatternInfo(
        "t_type_500khz_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/t_type_500khz_ns.ez",
        0.7, "maritime", "t_type"
    );
    
    vhf_patterns["maritime"][2.2] = AntennaPatternInfo(
        "long_wire_2mhz_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2mhz_ns.ez",
        2.2, "maritime", "long_wire"
    );
    
    vhf_patterns["maritime"][630.2] = AntennaPatternInfo(
        "inverted_l_630m_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/inverted_l_630m_ns.ez",
        630.2, "maritime", "inverted_l"
    );
    
    vhf_patterns["maritime"][2200.2] = AntennaPatternInfo(
        "long_wire_2200m_maritime_ns",
        "antenna_patterns/Ground-based/maritime_hf/long_wire_2200m_ns.ez",
        2200.2, "maritime", "long_wire"
    );
    
    // Add ALL missing coastal station patterns (NS orientations) with different frequencies
    vhf_patterns["ground_station"][0.7] = AntennaPatternInfo(
        "t_type_500khz_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/t_type_500khz_coastal_ns.ez",
        0.7, "ground_station", "t_type"
    );
    
    vhf_patterns["ground_station"][2.2] = AntennaPatternInfo(
        "long_wire_2mhz_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2mhz_coastal_ns.ez",
        2.2, "ground_station", "long_wire"
    );
    
    vhf_patterns["ground_station"][630.2] = AntennaPatternInfo(
        "inverted_l_630m_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/inverted_l_630m_coastal_ns.ez",
        630.2, "ground_station", "inverted_l"
    );
    
    vhf_patterns["ground_station"][2200.2] = AntennaPatternInfo(
        "long_wire_2200m_coastal_ns",
        "antenna_patterns/Ground-based/coastal_stations/long_wire_2200m_coastal_ns.ez",
        2200.2, "ground_station", "long_wire"
    );
}

void FGCom_AntennaPatternMapping::initializeUHFPatterns() {
    // Use existing ground-based UHF patterns that actually exist
    uhf_patterns["ground_station"][432.0] = AntennaPatternInfo(
        "yagi_70cm",
        "antenna_patterns/Ground-based/Yagi-antennas/yagi_70cm/yagi_70cm_16element.ez",
        432.0, "ground_station", "yagi"
    );
    
    // Use existing vertical UHF patterns
    uhf_patterns["ground_station"][435.0] = AntennaPatternInfo(
        "vertical_70cm",
        "antenna_patterns/Ground-based/vertical/70cm_vertical/70cm_vertical_antenna.ez",
        435.0, "ground_station", "vertical"
    );
    
    // Default UHF pattern using existing ground-based pattern
    uhf_patterns["default"][400.0] = AntennaPatternInfo(
        "default_uhf",
        "antenna_patterns/Ground-based/vertical/70cm_vertical/70cm_vertical_antenna.ez",
        400.0, "default", "vertical"
    );
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it == vhf_patterns.end()) {
        // Try to find closest frequency for any vehicle type
        return getClosestVHFPattern(vehicle_type, frequency_mhz);
    }
    
    auto freq_it = vehicle_it->second.find(frequency_mhz);
    if (freq_it != vehicle_it->second.end()) {
        return freq_it->second;
    }
    
    // Find closest frequency
    return getClosestVHFPattern(vehicle_type, frequency_mhz);
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it == uhf_patterns.end()) {
        // Try to find closest frequency for any vehicle type
        return getClosestUHFPattern(vehicle_type, frequency_mhz);
    }
    
    auto freq_it = vehicle_it->second.find(frequency_mhz);
    if (freq_it != vehicle_it->second.end()) {
        return freq_it->second;
    }
    
    // Find closest frequency
    return getClosestUHFPattern(vehicle_type, frequency_mhz);
}

std::vector<AntennaPatternInfo> FGCom_AntennaPatternMapping::getAvailableVHFPatterns(const std::string& vehicle_type) {
    std::vector<AntennaPatternInfo> patterns;
    
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it != vhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            patterns.push_back(freq_pair.second);
        }
    }
    
    return patterns;
}

std::vector<AntennaPatternInfo> FGCom_AntennaPatternMapping::getAvailableUHFPatterns(const std::string& vehicle_type) {
    std::vector<AntennaPatternInfo> patterns;
    
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it != uhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            patterns.push_back(freq_pair.second);
        }
    }
    
    return patterns;
}

bool FGCom_AntennaPatternMapping::hasVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it == vhf_patterns.end()) return false;
    
    return vehicle_it->second.find(frequency_mhz) != vehicle_it->second.end();
}

bool FGCom_AntennaPatternMapping::hasUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it == uhf_patterns.end()) return false;
    
    return vehicle_it->second.find(frequency_mhz) != vehicle_it->second.end();
}

bool FGCom_AntennaPatternMapping::loadPatternFromFile(const std::string& pattern_file, AntennaPatternInfo& info) {
    std::ifstream file(pattern_file);
    if (!file.is_open()) {
        return false;
    }
    
    // Basic file existence check
    info.is_loaded = true;
    return true;
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getClosestVHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    AntennaPatternInfo closest;
    double min_diff = std::numeric_limits<double>::max();
    
    auto vehicle_it = vhf_patterns.find(vehicle_type);
    if (vehicle_it != vhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            double diff = std::abs(freq_pair.first - frequency_mhz);
            if (diff < min_diff) {
                min_diff = diff;
                closest = freq_pair.second;
            }
        }
    }
    
    return closest;
}

AntennaPatternInfo FGCom_AntennaPatternMapping::getClosestUHFPattern(const std::string& vehicle_type, double frequency_mhz) {
    AntennaPatternInfo closest;
    double min_diff = std::numeric_limits<double>::max();
    
    auto vehicle_it = uhf_patterns.find(vehicle_type);
    if (vehicle_it != uhf_patterns.end()) {
        for (const auto& freq_pair : vehicle_it->second) {
            double diff = std::abs(freq_pair.first - frequency_mhz);
            if (diff < min_diff) {
                min_diff = diff;
                closest = freq_pair.second;
            }
        }
    }
    
    return closest;
}

std::string FGCom_AntennaPatternMapping::detectVehicleType(const std::string& vehicle_name) {
    std::string lower_name = vehicle_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("aircraft") != std::string::npos || 
        lower_name.find("plane") != std::string::npos ||
        lower_name.find("b737") != std::string::npos ||
        lower_name.find("c130") != std::string::npos ||
        lower_name.find("cessna") != std::string::npos ||
        lower_name.find("mi4") != std::string::npos ||
        lower_name.find("huey") != std::string::npos ||
        lower_name.find("bear") != std::string::npos ||
        lower_name.find("tu95") != std::string::npos) {
        return "aircraft";
    } else if (lower_name.find("tank") != std::string::npos ||
               lower_name.find("leopard") != std::string::npos ||
               lower_name.find("uaz") != std::string::npos ||
               lower_name.find("t55") != std::string::npos ||
               lower_name.find("mbt") != std::string::npos) {
        return "military_land";
    } else if (lower_name.find("jeep") != std::string::npos ||
               lower_name.find("nato") != std::string::npos ||
               lower_name.find("soviet") != std::string::npos) {
        return "military_land";
    } else if (lower_name.find("ford") != std::string::npos ||
               lower_name.find("transit") != std::string::npos ||
               lower_name.find("passat") != std::string::npos ||
               lower_name.find("vw") != std::string::npos ||
               lower_name.find("camper") != std::string::npos) {
        return "vehicle";
    } else if (lower_name.find("station") != std::string::npos ||
               lower_name.find("ground") != std::string::npos ||
               lower_name.find("yagi") != std::string::npos ||
               lower_name.find("beam") != std::string::npos ||
               lower_name.find("dipole") != std::string::npos ||
               lower_name.find("loop") != std::string::npos ||
               lower_name.find("vertical") != std::string::npos) {
        return "ground_station";
    } else if (lower_name.find("ship") != std::string::npos ||
               lower_name.find("boat") != std::string::npos ||
               lower_name.find("maritime") != std::string::npos ||
               lower_name.find("sailboat") != std::string::npos ||
               lower_name.find("backstay") != std::string::npos ||
               lower_name.find("whip") != std::string::npos ||
               lower_name.find("container") != std::string::npos) {
        return "maritime";
    } else if (lower_name.find("military") != std::string::npos ||
               lower_name.find("tactical") != std::string::npos) {
        return "military_land";
    } else if (lower_name.find("civilian") != std::string::npos) {
        return "civilian";
    }
    
    return "default";
}

bool FGCom_AntennaPatternMapping::isVHFFrequency(double frequency_mhz) {
    return frequency_mhz >= 30.0 && frequency_mhz <= 300.0;
}

bool FGCom_AntennaPatternMapping::isUHFFrequency(double frequency_mhz) {
    return frequency_mhz > 300.0;
}

// Convenience functions
AntennaPatternInfo getAntennaPattern(const std::string& vehicle_type, double frequency_mhz) {
    if (!g_antenna_pattern_mapping) {
        g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
    }
    
    if (g_antenna_pattern_mapping->isVHFFrequency(frequency_mhz)) {
        return g_antenna_pattern_mapping->getVHFPattern(vehicle_type, frequency_mhz);
    } else if (g_antenna_pattern_mapping->isUHFFrequency(frequency_mhz)) {
        return g_antenna_pattern_mapping->getUHFPattern(vehicle_type, frequency_mhz);
    }
    
    return AntennaPatternInfo(); // Default empty pattern
}

bool loadAntennaPattern(const std::string& vehicle_type, double frequency_mhz) {
    if (!g_antenna_pattern_mapping) {
        g_antenna_pattern_mapping = std::make_unique<FGCom_AntennaPatternMapping>();
    }
    
    AntennaPatternInfo info = getAntennaPattern(vehicle_type, frequency_mhz);
    if (info.antenna_name.empty()) {
        return false;
    }
    
    return g_antenna_pattern_mapping->loadPatternFromFile(info.pattern_file, info);
}
