// An simple udp IO interface for the FGCom mumble plugin.
//
// It spawns an UDP server that accepts state inforamtion.
// The information is parsed and then put into a shared data
// structure, from where the plugin can read the current state.
//
#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <thread>
#include <mutex>
#include <vector>
#include "globalVars.h"
  
#define FGCOM_PORT 16661    // 16661 is the known FGCom udp port
#define MAXLINE    1024     // max size of a udp packet



/*
 * Process a received message:
 * Read the contents and put them into the shared structure
 * 
 * Note: uses the global fgcom_local_client structure!
 * @todo: that should be changed, so the udp server instance gets initialized with pointers to these variables.
 */
std::mutex fgcom_localcfg_mtx;
void fgcom_udp_parseMsg(char buffer[MAXLINE]) {
    printf("Client said: %s\n", buffer);
    
    fgcom_localcfg_mtx.lock();
    fgcom_local_client.radios[0].volts++;
    fgcom_localcfg_mtx.unlock();
}


/*
 * Spawn the udp server thread.
 * He should constantly monitor the port for incoming data.
 * 
 * @param ??? Pointer to the shared data structure.
 */
void fgcom_spawnUDPServer() {
    std::cout << "server spawning...";
    int  fgcom_UDPServer_sockfd; 
    char buffer[MAXLINE]; 
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (fgcom_UDPServer_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("FGCom: socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(FGCOM_PORT); 
      
    // Bind the socket with the server address 
    if ( bind(fgcom_UDPServer_sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("FGCom: udp socket bind to port failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    // wait for incoming data
    int n; 
    socklen_t len;
    while (true) {
        len = sizeof(cliaddr);  //len is value/result 
        n = recvfrom(fgcom_UDPServer_sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); 
        buffer[n] = '\0';
        fgcom_udp_parseMsg(buffer);
    }
      
    return;
}


// FOR TESTING PURPOSES ONLY. NEEDS TO BE DISCARDED ONCE THE CODE IS INTEGRATABLE INTO THE PLUGIN
int main() { 
    std::cout.setf(std::ios::unitbuf); // unbuffered cout writes
    
    // init local state
    fgcom_local_client.callsign = "itsMe"; // init local user callsign
    fgcom_local_client.radios.push_back(fgcom_radio()); // add new radio instance with default values
    fgcom_local_client.radios[0].frequency = "<unset>"; // initialize frequency
    
    std::cout << "Init udp server...";
    std::thread udpServerThread(fgcom_spawnUDPServer);
    std::cout << "server started.";
    
    while (true) {
        std::cout << "--------------\n";
        printf("TEST-State:   frequency=%s\n", fgcom_local_client.radios[0].frequency.c_str());
        printf("TEST-State:   power_btn=%i\n", fgcom_local_client.radios[0].power_btn);
        printf("TEST-State:       volts=%f\n", fgcom_local_client.radios[0].volts);
        printf("TEST-State: serviceable=%i\n", fgcom_local_client.radios[0].serviceable);
        printf("TEST-State:         ptt=%i\n", fgcom_local_client.radios[0].ptt);
        printf("TEST-State:      volume=%f\n", fgcom_local_client.radios[0].volume);
        printf("TEST-State:         pwr=%f\n", fgcom_local_client.radios[0].pwr);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
    // ensure that thread has finished before the main thread terminates
    udpServerThread.join();
}
