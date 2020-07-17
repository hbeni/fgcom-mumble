
/*
 * Spawn UDP client thread.
 * He will push out data until stopped.
 */
extern bool rdfClientRunning; // will be managed by client thread
void fgcom_spawnRDFUDPClient(); 
