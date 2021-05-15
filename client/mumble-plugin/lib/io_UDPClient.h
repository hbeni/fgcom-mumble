#ifndef FGCOM_IO_UDPCLIENT_H
#define FGCOM_IO_UDPCLIENT_H

#include <cstring>
#include <vector>
#include <map>
#include <string>
#include "radio_model.h"

/*
 * Spawn UDP client thread.
 * He will push out data until stopped.
 */
extern bool udpClientRunning; // will be managed by client thread
void fgcom_spawnUDPClient(); 
void fgcom_stopUDPClient();

// This represents an RDF signal recording
struct fgcom_rdfInfo {
    // Transmitter info
    fgcom_radio txRadio;     // transmitting radio instance
    fgcom_client txIdentity; // transmitting identity
    
    // Receiver info
    fgcom_radio rxRadio;     // receiving radio instance
    int rxRadioId;           // receiving radio id (e.g. 1 for COM1)
    fgcom_client rxIdentity; // receiving identity
    
    // Signal info
    fgcom_radiowave_signal signal; // signal info
};


// Global mutex for read/write access to fgcom_rdf_activeSignals
extern std::mutex fgcom_rdfInfo_mtx;

/*
 * Register an RDF signal detection
 * This will populate the data for the next RDF output cycle
 */
void fgcom_rdf_registerSignal(std::string, fgcom_rdfInfo rdfInfo);


#endif
