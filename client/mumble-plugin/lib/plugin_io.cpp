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
#include <sstream> 
#include <regex>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <thread>
#include <mutex>
#include <vector>
#include "globalVars.h"
#include "plugin_io.h"
#include "MumblePlugin.h"


/*****************************************************
 *               Plugin communications               *
 ****************************************************/

void notifyRemotes(int what, int selector ) {
    // check if we are connected and synchronized
    if (!connectionSynchronized) {
        std::cout << "notifyRemotes("<<what<<","<<selector<<"): not notifying, not connected!" << std::endl;
        return;
    }

    // @param what:  0=all local info; 1=location data; 2=comms
    // @param selector: ignored, when 'what'=2: id of radio (0=COM1,1=COM2,...); -1 sends all radios
    switch (what) {
    case 0:
        // notify all info
        notifyRemotes(1);
        notifyRemotes(2);
        break;
        
    case 1:
        // Notify on location
        std::cout << "notifyRemotes("<<what<<","<<selector<<"): location" << std::endl;
        break;
        
    case 2:
        // notify on radio state
        std::cout << "notifyRemotes(): radio" << std::endl;
        
        if (selector == -1) {
            std::cout << "  all radios selected" << std::endl;
        } else {
            std::cout << "  send state of COM" << selector+1 << std::endl;
        }
        
        break;
    }
    
/// Sends the provided data to the provided client(s). This kind of data can only be received by another plugin active
/// on that client. The sent data can be seen by any active plugin on the receiving client. Therefore the sent data
/// must not contain sensitive information or anything else that shouldn't be known by others.
///
/// @param callerID The ID of the plugin calling this function
/// @param connection The ID of the server-connection to send the data through (the server the given users are on)
/// @param users An array of user IDs to send the data to
/// @param userCount The size of the provided user-array
/// @param data The data that shall be sent as a String
/// @param dataLength The length of the data-string
/// @param dataID The ID of the sent data. This has to be used by the receiving plugin(s) to figure out what to do with
/// 	the data
/// @returns The error code. If everything went well, STATUS_OK will be returned.
//mumble_error_t (PLUGIN_CALLING_CONVENTION *sendData)(plugin_id_t callerID, mumble_connection_t connection, mumble_userid_t *users,
//		size_t userCount, const char *data, size_t dataLength, const char *dataID);
    
    
}



/*****************************************************
 *                     UDP Server                    *
 * The UDP interface is the plugins port to receive  *
 * configuration state from the outside world.       *
 * It is used for example from ATC clients or        *
 * FlightSims to inform the plugin of local state.   *
 ****************************************************/



/*
 * Process a received message:
 * Read the contents and put them into the shared structure.
 * This will be called from the UDP server thread when receiving new data.
 * 
 * Note: uses the global fgcom_local_client structure and fgcom_localcfg_mtx!
 * @todo: that should be changed, so the udp server instance gets initialized with pointers to these variables.
 */
std::mutex fgcom_localcfg_mtx;
struct fgcom_client fgcom_local_client;
void fgcom_udp_parseMsg(char buffer[MAXLINE]) {
    printf("Client said: %s\n", buffer);

    // convert to stringstream so we can easily tokenize
    // TODO: why not simply refactor to strtok()?
    std::stringstream streambuffer(buffer); //std::string(buffer)
    std::string segment;
    std::regex parse_key_value ("^(\\w+)=(.+)");
    std::regex parse_COM ("^(COM)(\\d)_(.+)");
    fgcom_localcfg_mtx.lock();
    while(std::getline(streambuffer, segment, ',')) {
        printf("Segment=%s",segment);
        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());

    
    
        try {
            std::smatch sm;
            if (std::regex_search(segment, sm, parse_key_value)) {
                // this is a valid token. Lets parse it!
                std::string token_key   = sm[1];
                std::string token_value = sm[2];
                printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                
                std::smatch smc;
                if (std::regex_search(token_key, smc, parse_COM)) {
                    // COM Radio mode detected
                    std::string radio_type = smc[1];
                    std::string radio_nr   = smc[2];
                    std::string radio_var  = smc[3];
                    
                    // if the selected radio does't exist, create it now
                    int radio_id = std::stoi(radio_nr.c_str());  // COM1 -> 1
                    if (fgcom_local_client.radios.size() < radio_id) {
                        for (int cr = fgcom_local_client.radios.size(); cr < radio_id; cr++) {
                            fgcom_local_client.radios.push_back(fgcom_radio()); // add new radio instance with default values
                        }
                    }
                    radio_id--; // convert to array index
                    
                    if (radio_var == "FRQ") fgcom_local_client.radios[radio_id].frequency   = token_value;
                    if (radio_var == "VLT") fgcom_local_client.radios[radio_id].volts       = std::stof(token_value);
                    if (radio_var == "PBT") fgcom_local_client.radios[radio_id].power_btn   = (token_value == "1")? true : false;
                    if (radio_var == "SRV") fgcom_local_client.radios[radio_id].serviceable = (token_value == "1")? true : false;
                    if (radio_var == "PTT") fgcom_local_client.radios[radio_id].ptt         = (token_value == "1")? true : false;
                    if (radio_var == "VOL") fgcom_local_client.radios[radio_id].volume      = std::stof(token_value);
                    if (radio_var == "PWR") fgcom_local_client.radios[radio_id].pwr         = std::stof(token_value);

                }
                
                
                // User client values
                if (token_key == "LON") fgcom_local_client.lon = std::stof(token_value);
                if (token_key == "LAT") fgcom_local_client.lat = std::stof(token_value);
                if (token_key == "ALT") {
                    // ALT comes in ft. We need meters however
                    fgcom_local_client.alt = std::stoi(token_value) / 3.2808;
                }
                if (token_key == "CALLSIGN") fgcom_local_client.callsign = token_value;
                
                
                // FGCom 3.0 compatibility
                if (token_key == "PTT") {
                    // PTT contains the ID of the used radio (0=none, 1=COM1, 2=COM2)
                    int ptt_id = std::stoi(token_value);
                    for (int i = 0; i<fgcom_local_client.radios.size(); i++) {
                        if (i == ptt_id - 1) {
                            fgcom_local_client.radios[i].ptt = 1;
                        } else {
                            fgcom_local_client.radios[i].ptt = 0;
                        }
                    }
                }
                if (token_key == "OUTPUT_VOL") {
                    // Set all radio instances to the selected volume
                    float comvol = std::stof(token_value);
                    for (int i = 0; i<fgcom_local_client.radios.size(); i++) {
                        fgcom_local_client.radios[i].volume = comvol;
                    }
                }
           
            } else {
                // this was an invalid token. skip it silently.
                printf("  segment invalid (is no key=value format): %s\n", segment.c_str());
            }
            
        // done with parsing?
        } catch (const std::exception& e) {
            std::cout << "Parsing throw exception, ignoring token " << segment.c_str() << std::endl;
        }
        
    }  //endwhile
    fgcom_localcfg_mtx.unlock();
}



void fgcom_spawnUDPServer() {
    printf("FGCom: server starting on port %i\n", FGCOM_PORT);
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
        
        if (strstr(buffer, "SHUTDOWN")) {
            // Allow the udp server to be shut down when receiving SHUTDOWN command
            printf("FGCom: shutdown command recieved, server stopping now");
            close(fgcom_UDPServer_sockfd);
            break;
        } else {
            fgcom_udp_parseMsg(buffer);
        }
    }
      
    return;
}

void fgcom_shutdownUDPServer() {
    //  Trigger shutdown: this just sends some magic UDP message.
    printf("FGCOM: sending UDP shutdown request\n");
    std::string message = "SHUTDOWN";
    
    const char* server_name = "localhost";
	const int server_port = FGCOM_PORT;

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	// creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
	inet_pton(AF_INET, server_name, &server_address.sin_addr);

	// htons: port in network order format
	server_address.sin_port = htons(server_port);

	// open socket
	int sock;
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("could not create socket\n");
		return;
	}

	// send data
	int len = sendto(sock, message.c_str(), strlen(message.c_str()), 0,
	           (struct sockaddr*)&server_address, sizeof(server_address));

}


// FOR TESTING PURPOSES ONLY. NEEDS TO BE DISCARDED ONCE THE CODE IS INTEGRATABLE INTO THE PLUGIN
/*int main() { 
    std::cout.setf(std::ios::unitbuf); // unbuffered cout writes
    
    // init local state
    fgcom_local_client.callsign = "itsMe"; // init local user callsign
    //fgcom_local_client.radios.push_back(fgcom_radio()); // add new radio instance with default values
    //fgcom_local_client.radios[0].frequency = "<unset>"; // initialize frequency
    
    std::cout << "Init udp server...";
    std::thread udpServerThread(fgcom_spawnUDPServer);
    std::cout << "server started.";
    
    while (true) {
        std::cout << "--------------\n";
        printf("%s: location: LAT=%f LON=%f ALT=%i\n", fgcom_local_client.callsign.c_str(), fgcom_local_client.lat, fgcom_local_client.lon, fgcom_local_client.alt);
        printf("%s: %i radios registered\n", fgcom_local_client.callsign.c_str(), fgcom_local_client.radios.size());
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
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
    // ensure that thread has finished before the main thread terminates
    udpServerThread.join();
}*/
