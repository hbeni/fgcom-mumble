#include <stdio.h>
#include <cstring>
#include <string>
#include <iostream>

#include "globalVars.h"
#include "mumble/MumbleAPI_v_1_0_x.h"
#include "mumble/MumblePlugin_v_1_0_x.h"

#include "io_plugin.cpp"

// fake some unneeded vars
mumble_connection_t activeConnection = 1;
mumble_plugin_id_t ownPluginID = 0;
MumbleAPI_v_1_0_x mumAPI;
std::map<int, struct fgcom_client> fgcom_local_client;
mumble_userid_t localMumId;
std::mutex fgcom_localcfg_mtx;
bool fgcom_isPluginActive() { return true; };

struct fgcom_config fgcom_cfg;

#include "updater.cpp"


// build with:
// mumble-plugin$ g++ -fPIC -o test/updater-test test/updater-test.cpp -DDEBUG -Wall -O3 -I. -I./lib



using namespace std; 

int main(int argc, char *argv[])
{
    std::cout << "INIT" <<std::endl;
    
    if (argc == 2 && strcmp(argv[1], "fun")==0) {
        // just here to play with the strcmp
        std::cout << argc << " args given :)" <<std::endl;
        for (int i = 0; i<argc; i++) std::cout << "argv[" << i << "] = '" << argv[i] << "'" <<std::endl;
        
    } else if (argc == 2 && strcmp(argv[1], "WebVersionChecker")==0) {
        // Test the basic WebVersionChecker
        fgcom_cfg.updaterURL = "http://fgcom.hallinger.org/version.php";
        fgcom_getLatestReleaseFrom_WebVersionChecker();

    
    } else {
        std::cout << "ERROR: Specify test to run" <<std::endl;
        std::cout << "  ./test/updater-test WebVersionChecker" <<std::endl;
    }
    
    
    std::cout << "DONE" <<std::endl;
    std::string verStr = std::to_string(fgcom_release_latest.version.major)
                         + "." + std::to_string(fgcom_release_latest.version.minor)
                         + "." + std::to_string(fgcom_release_latest.version.patch);
    std::cout << "fgcom_release_latest.version=" << verStr <<std::endl;
    std::cout << "fgcom_release_latest.downUrl=" << fgcom_release_latest.downUrl <<std::endl;
    
}
