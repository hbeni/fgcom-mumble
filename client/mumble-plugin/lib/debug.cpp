// FOR TESTING PURPOSES ONLY.
// This is a simple thread function that puts internal state to the terminal every second.
bool fgcom_isPluginActive();
void debug_out_internal_state() { 
    std::cout.setf(std::ios::unitbuf); // unbuffered cout writes
    
    while (true) {
        std::cout << "---------LOCAL STATE-----------\n";
        printf("plugin state: %s\n", (fgcom_isPluginActive())?"active":"inactive");
        printf("[mumid=%i] %s: location: LAT=%f LON=%f ALT=%i\n", fgcom_local_client.mumid, fgcom_local_client.callsign.c_str(), fgcom_local_client.lat, fgcom_local_client.lon, fgcom_local_client.alt);
        printf("[mumid=%i] %s: %i radios registered\n", fgcom_local_client.mumid, fgcom_local_client.callsign.c_str(), fgcom_local_client.radios.size());
        if (fgcom_local_client.radios.size() > 0) {
            for (int i=0; i<fgcom_local_client.radios.size(); i++) {
                printf("  Radio %i:   frequency=%s\n", i, fgcom_local_client.radios[i].frequency.c_str());
                printf("  Radio %i:   power_btn=%i\n", i, fgcom_local_client.radios[i].power_btn);
                printf("  Radio %i:       volts=%f\n", i, fgcom_local_client.radios[i].volts);
                printf("  Radio %i: serviceable=%i\n", i, fgcom_local_client.radios[i].serviceable);
                printf("  Radio %i:         ptt=%i\n", i, fgcom_local_client.radios[i].ptt);
                printf("  Radio %i:      volume=%f\n", i, fgcom_local_client.radios[i].volume);
                printf("  Radio %i:         pwr=%f\n", i, fgcom_local_client.radios[i].pwr);
            }
        }
        
        std::cout << "---------REMOTE STATE-----------\n";
        for (const auto &p : fgcom_remote_clients) {
            printf("[id=%i; mumid=%i] %s: location: LAT=%f LON=%f ALT=%i\n", p.first, p.second.mumid, p.second.callsign.c_str(), p.second.lat, p.second.lon, p.second.alt);
            printf("[id=%i; mumid=%i] %s: %i radios registered\n", p.first, p.second.mumid, p.second.callsign.c_str(), p.second.radios.size());
            if (p.second.radios.size() > 0) {
                for (int i=0; i<p.second.radios.size(); i++) {
                    printf("  Radio %i:   frequency=%s\n", i, p.second.radios[i].frequency.c_str());
                    printf("  Radio %i:   power_btn=%i\n", i, p.second.radios[i].power_btn);
                    printf("  Radio %i:       volts=%f\n", i, p.second.radios[i].volts);
                    printf("  Radio %i: serviceable=%i\n", i, p.second.radios[i].serviceable);
                    printf("  Radio %i:         ptt=%i\n", i, p.second.radios[i].ptt);
                    printf("  Radio %i:      volume=%f\n", i, p.second.radios[i].volume);
                    printf("  Radio %i:         pwr=%f\n", i, p.second.radios[i].pwr);
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
}
 
