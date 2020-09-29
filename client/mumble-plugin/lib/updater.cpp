/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * OpenSSL exception (under GNU GPL version 3 section 7):
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 * 
 * This product includes software developed by the OpenSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/)
 *
 * Mumble API:
 * Copyright 2019-2020 The Mumble Developers. All rights reserved.
 * Use of this source code is governed by a BSD-style license
 * that can be found in the LICENSE file at the root of the
 * Mumble source tree or at <https://www.mumble.info/LICENSE>.
 * 
 */


/*
 * This implements the update functionality.
 * Currently we query githubs web API.
 */
#include <regex>
#include "fgcom-mumble.h"   // plugin version number

// HTTPLib from https://github.com/yhirose/cpp-httplib (MIT-License)
// This needs OpenSSL.
#define CPPHTTPLIB_OPENSSL_SUPPORT 1
#include "http/httplib.h"
using namespace httplib;

// JSON lib from https://github.com/nlohmann/json (MIT-License)
//#include "lib/json/json.hpp"
//using json = nlohmann::json;




/* Version struct */
struct fgcom_version {
    short major;
    short minor;
    short patch;
    fgcom_version()  {
        major = -1;  // -1 signifies error/not initialized
        minor = -1;
        patch = -1;
    };
};

/*
 * Util function to compare versions
 */
bool fgcom_isVersionNewer(fgcom_version ver) {
    fgcom_version curVer;
    curVer.major = FGCOM_VERSION_MAJOR;
    curVer.minor = FGCOM_VERSION_MINOR;
    curVer.patch = FGCOM_VERSION_PATCH;
    
    
    bool newer = false;
    if (ver.major > curVer.major) newer = true;
    if (ver.major == curVer.major && ver.minor > curVer.minor) newer = true;
    if (ver.major == curVer.major && ver.minor == curVer.minor && ver.patch > curVer.patch) newer = true;
    pluginDbg("[UPDATER] current="
        +std::to_string(curVer.major)+"."+std::to_string(curVer.minor)+"."+std::to_string(curVer.patch)
        +";  compareTo="
        +std::to_string(ver.major)+"."+std::to_string(ver.minor)+"."+std::to_string(ver.patch)
        +";  isNewer="+std::to_string(newer)
        
    );
    
    return newer;
}

/*
 * Struct and data for the latest release.
 * This is supposed to be filled by some function.
 */
struct fgcom_release {
    fgcom_version version;
    std::string tag;      // git tag
    std::string url;      // release page
    std::string downUrl;  // download url base
};
fgcom_release fgcom_release_latest;


/*
 * Fetch latest release information from github.
 * This fills in the fgcom_release_latest struct.
 */
int fgcom_githubQueryPerformed = 0;  // to limit update API requests
void fgcom_getLatestReleaseFromGithub_Web() {
    
    if (fgcom_release_latest.version.major > -1) return; // do not retrieve twice if retrieved successfully
    if (fgcom_githubQueryPerformed++ > 1) return; // limit github API requests to 1 per session
    
    
    /*
    fgcom_release_latest.version.major = std::stoi("0");
    fgcom_release_latest.version.minor = std::stoi("4");
    fgcom_release_latest.version.patch = std::stoi("0");
    fgcom_release_latest.tag           = "v.0.4.0";
    fgcom_release_latest.url           = "https://github.com/hbeni/fgcom-mumble/releases/tag/v.0.4.0";
    fgcom_release_latest.downUrl       = "https://github.com/hbeni/fgcom-mumble/releases/download/v.0.3.0/";
    
    pluginLog("[TEST]: Updater TEST CODE IN EFFECT!");
    return;
    */
    
    std::string scheme("https://");
    std::string host("github.com");
    std::string path("/hbeni/fgcom-mumble/releases");
    std::string rel("");
    std::string url(scheme + host + path + rel);
    
    // fetch release info JSON from github API
    httplib::SSLClient cli(host.c_str());
    httplib::Headers headers = {
        { "User-Agent", "hbeni/fgcom-mumble:release-checker" }
    };

    pluginLog("[UPDATER] fetching update information from: "+url);
    if (auto res = cli.Get(path.c_str(), headers)) {
        pluginDbg("[UPDATER] fetch OK; resultCode="+std::to_string(res->status));
        if (res->status == 200) {
            //std::cout << res->body << std::endl;
            
            // parse tag name from HTML body
            std::regex regex (path+"/tag/([v\\.\\d]+?)\">");
            std::smatch sm;

            if (std::regex_search(res->body, sm, regex)) {
                std::string tag_name = sm[1];
                fgcom_release_latest.tag = tag_name;
                std::regex regex ("^(?:v\\.?)?(\\d+)\\.(\\d+)\\.(\\d+)$");
                std::smatch sm;
                if (std::regex_search(tag_name, sm, regex)) {         // parse version number from tag name
                    fgcom_release_latest.version.major = stoi(sm[1]);
                    fgcom_release_latest.version.minor = stoi(sm[2]);
                    fgcom_release_latest.version.patch = stoi(sm[3]);
                    
                    // get release url
                    // https://github.com/hbeni/fgcom-mumble/releases/tag/v.0.3.0
                    fgcom_release_latest.url = url + "/tag/" + tag_name;
                    
                    //construct download url base
                    // https://github.com/hbeni/fgcom-mumble/releases/download/v.0.3.0/fgcom-mumble-linux-0.3.0.tar.gz
                    std::string dlurlbase(scheme + host + path + "/download/" + tag_name); 
                    
                    // generate download url for target platform
                    std::string verStr = std::to_string(fgcom_release_latest.version.major)
                                        + "." + std::to_string(fgcom_release_latest.version.minor)
                                        + "." + std::to_string(fgcom_release_latest.version.patch);
                    fgcom_release_latest.downUrl = dlurlbase+"/fgcom-mumble-client-binOnly-"+verStr+".zip";

                } else {
                    // something went wrong.
                    pluginLog("[UPDATER] ERROR: Can't obtain release version number from '"+tag_name+"'");
                }
            } else {
                // something went wrong.
                pluginLog("[UPDATER] ERROR: Can't obtain release info from '"+url+"'");
            }            
            
            
            pluginDbg("[UPDATER] latest version: "+std::to_string(fgcom_release_latest.version.major)+"."+std::to_string(fgcom_release_latest.version.minor)+"."+std::to_string(fgcom_release_latest.version.patch));
            pluginDbg("[UPDATER] download from:  "+ fgcom_release_latest.downUrl);

            
        } else {
            pluginDbg("[UPDATER] fetch resultCode not compatible; resultCode="+std::to_string(res->status));
        }
        
    } else {
        auto err = res.error();
        pluginLog("[UPDATER] ERROR fetching latest release info from web: "+std::to_string(err));
    }
}



/**
* Check via Githubs REST API service, which results in a JSON document
*/
/*  CODE ALREADY TESTED, but disabled due to github API rate limits
void fgcom_getLatestReleaseFromGithub_JSON_API() {
    
    if (fgcom_release_latest.version.major > -1) return; // do not retrieve twice if retrieved successfully
    if (fgcom_githubQueryPerformed++ > 1) return; // limit github API requests to 1 per session
    
    std::string scheme("https://");
    std::string host("api.github.com");
    std::string path("/repos/hbeni/fgcom-mumble/releases");
    std::string rel("/latest");
    std::string url(scheme + host + path + rel);
    
    // fetch release info JSON from github API
    httplib::SSLClient cli(host.c_str());
    httplib::Headers headers = {
        { "User-Agent", "hbeni/fgcom-mumble:release-checker" },
        { "accept", "application/vnd.github.v3+json" }
    };

    pluginLog("[UPDATER] fetching update information from: "+url);
    if (auto res = cli.Get(path.c_str(), headers)) {
        pluginDbg("[UPDATER] fetch OK; resultCode="+std::to_string(res->status));
        if (res->status == 200) {
            //std::cout << res->body << std::endl;
            
            // Decode the retrived data
            auto json_decoded = json::parse(res->body);
            
            // get version number for the release
            if (json_decoded.contains("tag_name")) {
                std::string tag_name     = json_decoded["tag_name"];
                fgcom_release_latest.tag = tag_name;
                std::regex regex ("^(?:v\\.)?(\\d+)\\.(\\d+)\\.(\\d+)$");
                std::smatch sm;
                if (std::regex_search(tag_name, sm, regex)) {         // parse version number from tag name
                    fgcom_release_latest.version.major = stoi(sm[1]);
                    fgcom_release_latest.version.minor = stoi(sm[2]);
                    fgcom_release_latest.version.patch = stoi(sm[3]);
                    
                    // get release url
                    if (json_decoded.contains("html_url")) {
                        std::string html_url = json_decoded["html_url"];
                        fgcom_release_latest.url = html_url;
                    }
                    
                    // construct download url base
                    fgcom_release_latest.downUrl = scheme + host + path + "/download/" + tag_name;
                    
                } else {
                    // something went wrong.
                    pluginLog("[UPDATER] ERROR: Can't obtain release version number from '"+url+"'");
                }
            } else {
                // something went wrong.
                pluginLog("[UPDATER] ERROR: Can't obtain release info from '"+url+"'");
            }         
            
            
            pluginDbg("[UPDATER] latest version: "+std::to_string(fgcom_release_latest.version.major)+"."+std::to_string(fgcom_release_latest.version.minor)+"."+std::to_string(fgcom_release_latest.version.patch));
            pluginDbg("[UPDATER] download from:  "+ fgcom_release_latest.downUrl);

            
        } else {
            pluginDbg("[UPDATER] fetch resultCode not compatible; resultCode="+std::to_string(res->status));
        }
        
    } else {
        auto err = res.error();
        pluginLog("[UPDATER] ERROR fetching latest release info from web: "+std::to_string(err));
    }
}
*/




/*************************************
 * Mumble Plugin API implementation  *
 ************************************/


/*
 * Check for new releases
 */
bool mumble_hasUpdate() {
    
    // fetch latest info; this will populate the struct fgcom_release_latest
    fgcom_getLatestReleaseFromGithub_Web();
    
    // check for errors
    if (fgcom_release_latest.version.major <= -1
    || fgcom_release_latest.downUrl == ""   ) {
        pluginLog("ERROR fetching release info: i have no idea if there is an update!");
        return false;

    } else {
        bool updatePending = fgcom_isVersionNewer(fgcom_release_latest.version);
        std::string verStr = std::to_string(fgcom_release_latest.version.major)
                         + "." + std::to_string(fgcom_release_latest.version.minor)
                         + "." + std::to_string(fgcom_release_latest.version.patch);
        pluginDbg("Version check: latest='"+verStr+"'; newer="+std::to_string(updatePending));
        
        if (updatePending) {    
            pluginLog("[UPDATER] Update to "+verStr+" pending!");
        } else {
            pluginLog("[UPDATER] Version is up to date.");
        }
            
        return updatePending;
    }
    
   
}


/*
 * Generates the URL to the latest release tarball suitable for the platform.
 * Will be called in case there is an update pendig (ie. mumble_hasUpdate()==true).
 */
MumbleStringWrapper mumble_getUpdateDownloadURL() {
    std::string url = fgcom_release_latest.downUrl;

    // write the generated URL to a char buffer
    char * buffer = new char[url.size() + 1];
    std::copy(url.begin(), url.end(), buffer);
    buffer[url.size()] = '\0'; // don't forget the terminating 0

    // build return wrapper
    MumbleStringWrapper wrapper;
    wrapper.data = buffer;
    wrapper.size = strlen(buffer);
    wrapper.needsReleasing = true; // will make mumble call mumble_releaseResource() after usage

    return wrapper;

}
