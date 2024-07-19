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
#ifdef SSLFLAGS
#define CPPHTTPLIB_OPENSSL_SUPPORT 1
#endif
#include "http/httplib.h"
using namespace httplib;

// JSON lib from https://github.com/nlohmann/json (MIT-License)
//#include "lib/json/json.hpp"
//using json = nlohmann::json;


// Naming components of the download asset:
//   name + version + postfix + extension
//   fgcom-mumble-0.14.0.mumble_plugin
std::string fgcom_asset_name("fgcom-mumble-");
std::string fgcom_bin_postfix("");
std::string fgcom_bin_extension(".mumble_plugin");

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
void fgcom_getLatestReleaseFrom_Github_Web() {
    
    if (fgcom_release_latest.version.major > -1) return; // do not retrieve twice if retrieved successfully
    if (fgcom_githubQueryPerformed++ > 1) return; // limit github API requests to 1 per session
    
    
    /*
    fgcom_release_latest.version.major = std::stoi("0");
    fgcom_release_latest.version.minor = std::stoi("14");
    fgcom_release_latest.version.patch = std::stoi("2");
    fgcom_release_latest.tag           = "v.0.14.2";
    fgcom_release_latest.url           = "https://github.com/hbeni/fgcom-mumble/releases/tag/"+fgcom_release_latest.tag;
    fgcom_release_latest.downUrl       = "https://github.com/hbeni/fgcom-mumble/releases/download/"+fgcom_release_latest.tag
                                       + "/fgcom-mumble-"+std::to_string(fgcom_release_latest.version.major)+"."+std::to_string(fgcom_release_latest.version.minor)+"."+std::to_string(fgcom_release_latest.version.patch)+".mumble_plugin";
    
    pluginLog("[TEST]: Updater TEST CODE IN EFFECT!");
    return;
    */
    
#ifdef SSLFLAGS
    std::string scheme("https://");
#else
    std::string scheme("http://");
#endif
    std::string host("github.com");
    std::string proj("hbeni/fgcom-mumble");
    std::string path("/"+proj+"/releases");
    std::string rel("");
    std::string url(scheme + host + path + rel);
    
    // fetch release info from github API
#ifdef SSLFLAGS
    httplib::SSLClient cli(host.c_str());
#else
    httplib::Client cli(host.c_str());
#endif
    std::string user_agent("FGCom-mumble/"
                +std::to_string(FGCOM_VERSION_MAJOR)+"."+std::to_string(FGCOM_VERSION_MINOR)+"."+std::to_string(FGCOM_VERSION_PATCH)
                +" plugin-release-checker");
    httplib::Headers headers = {
        { "User-Agent",      user_agent },
        { "Accept",          "*/*"},
        { "Accept-Encoding", "identity"},
        { "Connection",      "Keep-Alive"}
    };

    pluginLog("[UPDATER] fetching update information from: '"+url+"' (Github_Web)");
    pluginDbg("[UPDATER] user_agent="+user_agent);
    if (auto res = cli.Get(path.c_str(), headers)) {
        pluginDbg("[UPDATER] fetch OK; resultCode="+std::to_string(res->status));
        if (res->status == 200) {
            //std::cout << res->body << std::endl;
            
            // parse tag name from HTML body
            std::regex regex_tag (path+"/tag/([-_.0-9a-zA-Z]+?)[^-_.0-9a-zA-Z]");
            std::smatch sm;
            if (std::regex_search(res->body, sm, regex_tag)) {
                std::string tag_name = sm[1];
                fgcom_release_latest.tag = tag_name;
                
                // use the tag name to fetch the plugin header file from the source tree of that release
                //std::string header_url(scheme + host + "/" + proj + "/raw/" + tag_name + "/client/mumble-plugin/fgcom-mumble.h");
                //https://raw.githubusercontent.com/hbeni/fgcom-mumble/v.0.14.0/client/mumble-plugin/fgcom-mumble.h
                //https://github.com/hbeni/fgcom-mumble/blob/v.0.14.0/client/mumble-plugin/fgcom-mumble.h
                std::string header_url(scheme + host + "/" + proj + "/blob/" + tag_name + "/client/mumble-plugin/fgcom-mumble.h");
                pluginDbg("[UPDATER] fetching version information from: '"+header_url+"'");
                if (auto res_hdr = cli.Get(header_url.c_str(), headers)) {
                    pluginDbg("[UPDATER] fetch OK; resultCode="+std::to_string(res_hdr->status));
                    if (res_hdr->status == 200) {
                        // parse version info name from HTML body
                        //   (i know this is somewhat ugly. But the github raw page does not work reliably when using the httplib,
                        //    and stripping HTML with regex did already cost me three days debugging and testing.)
                        pluginDbg("[UPDATER] parsing version strings");
                        std::regex regex_major ("#(?:<.+>)?define(?:<.+>)? (?:<.+>)?FGCOM_VERSION_MAJOR(?:<.+>)? (?:<.+>)?(\\d+)(?:<.+>)?");
                        std::smatch sm_major;
                        if (std::regex_search(res_hdr->body, sm_major, regex_major)) {
                            pluginDbg("[UPDATER]   parsed version_major="+std::string(sm_major[1]));
                            fgcom_release_latest.version.major = stoi(sm_major[1]);
                        }
                        std::regex regex_minor ("#(?:<.+>)?define(?:<.+>)? (?:<.+>)?FGCOM_VERSION_MINOR(?:<.+>)? (?:<.+>)?(\\d+)(?:<.+>)?");
                        std::smatch sm_minor;
                        if (std::regex_search(res_hdr->body, sm_minor, regex_minor)) {
                            pluginDbg("[UPDATER]   parsed version_minor="+std::string(sm_minor[1]));
                            fgcom_release_latest.version.minor = stoi(sm_minor[1]);
                        }
                        std::regex regex_patch ("#(?:<.+>)?define(?:<.+>)? (?:<.+>)?FGCOM_VERSION_PATCH(?:<.+>)? (?:<.+>)?(\\d+)(?:<.+>)?");
                        std::smatch sm_patch;
                        if (std::regex_search(res_hdr->body, sm_patch, regex_patch)) {
                            pluginDbg("[UPDATER]   parsed version_patch="+std::string(sm_patch[1]));
                            fgcom_release_latest.version.patch = stoi(sm_patch[1]);
                        }

                        // Check if version could be parsed successfully
                        if (   fgcom_release_latest.version.major > -1
                            && fgcom_release_latest.version.minor > -1
                            && fgcom_release_latest.version.patch > -1
                        ) {
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
                            //fgcom_release_latest.downUrl = dlurlbase+"/fgcom-mumble-client-binOnly-"+verStr+".zip";
                            fgcom_release_latest.downUrl = dlurlbase+"/"+fgcom_asset_name+verStr+fgcom_bin_postfix+fgcom_bin_extension;

                        } else {
                            // something went wrong.
                            pluginLog("[UPDATER] ERROR: Can't obtain the tags header version number from '"+header_url+"'");
                        }
                    } else {
                        pluginLog("[UPDATER] fetch resultCode not compatible; resultCode="+std::to_string(res_hdr->status));
                    }
                    
                } else {
                    // something went wrong.
                    auto http_err = res_hdr.error();
                    std::ostringstream http_err_stream;
                    http_err_stream << http_err;
                    pluginLog("[UPDATER] ERROR: Can't obtain tag name from '"+tag_name+"': "+http_err_stream.str());
                }
            } else {
                // something went wrong.
                pluginLog("[UPDATER] ERROR: Can't obtain release info from '"+url+"'");
            }
            
            
            pluginDbg("[UPDATER] latest version: "+std::to_string(fgcom_release_latest.version.major)+"."+std::to_string(fgcom_release_latest.version.minor)+"."+std::to_string(fgcom_release_latest.version.patch));
            pluginDbg("[UPDATER] download from:  "+ fgcom_release_latest.downUrl);

            
        } else {
            pluginLog("[UPDATER] fetch resultCode not compatible; resultCode="+std::to_string(res->status));
        }
        
    } else {
        auto http_err = res.error();
        std::ostringstream http_err_stream;
        http_err_stream << http_err;
        pluginLog("[UPDATER] ERROR fetching latest release info from web: "+http_err_stream.str());
    }
}



/**
* Check via Githubs REST API service, which results in a JSON document
*/
/*  CODE ALREADY TESTED, but disabled due to github API rate limits
void fgcom_getLatestReleaseFrom_Github_JSON_API() {
    
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

    pluginLog("[UPDATER] fetching update information from: "+url+" (Github_JSON_API));
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
        auto http_err = res.error();
        std::ostringstream http_err_stream;
        http_err_stream << http_err;
        pluginLog("[UPDATER] ERROR fetching latest release info from web: "+http_err_stream.str());
    }
}
*/


/**
 * Fetch latest version from plain Web using a custom structure
 *
 * The structure is defined like the following example:
 * FGCOM_TAG_NAME=v.1.2.0
 * FGCOM_VERSION_MAJOR=1
 * FGCOM_VERSION_MINOR=0
 * FGCOM_VERSION_PATCH=3
 */
void fgcom_getLatestReleaseFrom_WebVersionChecker() {
    pluginLog("[UPDATER] fetching update information from: '"+fgcom_cfg.updaterURL+"' (WebVersionChecker)");
    if (fgcom_release_latest.version.major > -1) return; // do not retrieve twice if retrieved successfully
    
    // parse the url into its parts
    std::regex parse_url ("^(https?)://([.a-zA-Z0-9]+)/([a-zA-Z0-9/.?_-]+)$");
    std::smatch parse_url_matches;
    if (std::regex_search(fgcom_cfg.updaterURL, parse_url_matches, parse_url)) {
        std::string scheme(parse_url_matches[1]);
        std::string host(parse_url_matches[2]);
        std::string path(parse_url_matches[3]);
        std::string rel("");
        std::string url(scheme + host + path + rel);
        httplib::Client cli((host).c_str());
        
        std::string user_agent("FGCom-mumble/"
                +std::to_string(FGCOM_VERSION_MAJOR)+"."+std::to_string(FGCOM_VERSION_MINOR)+"."+std::to_string(FGCOM_VERSION_PATCH)
                +" plugin-release-checker");
        httplib::Headers headers = {
            { "User-Agent",      user_agent },
            { "Accept",          "*/*"},
            { "Connection",      "Keep-Alive"}
        };
        if (auto res = cli.Get(("/"+path).c_str(), headers)) {
            pluginDbg("[UPDATER] fetch OK; resultCode="+std::to_string(res->status));
            if (res->status == 200) {
                std::cout << res->body << std::endl;
                
                pluginDbg("[UPDATER] parsing version strings");
                std::regex regex_tag ("FGCOM_TAG_NAME=(v[.\\d]+)");
                std::smatch sm_tag;
                if (std::regex_search(res->body, sm_tag, regex_tag)) {
                    pluginDbg("[UPDATER]   parsed tag_name="+std::string(sm_tag[1]));
                    fgcom_release_latest.tag = std::string(sm_tag[1]);
                }
                std::regex regex_major ("FGCOM_VERSION_MAJOR=(\\d+)");
                std::smatch sm_major;
                if (std::regex_search(res->body, sm_major, regex_major)) {
                    pluginDbg("[UPDATER]   parsed version_major="+std::string(sm_major[1]));
                    fgcom_release_latest.version.major = stoi(sm_major[1]);
                }
                std::regex regex_minor ("FGCOM_VERSION_MINOR=(\\d+)");
                std::smatch sm_minor;
                if (std::regex_search(res->body, sm_minor, regex_minor)) {
                    pluginDbg("[UPDATER]   parsed version_minor="+std::string(sm_minor[1]));
                    fgcom_release_latest.version.minor = stoi(sm_minor[1]);
                }
                std::regex regex_patch ("FGCOM_VERSION_PATCH=(\\d+)");
                std::smatch sm_patch;
                if (std::regex_search(res->body, sm_patch, regex_patch)) {
                    pluginDbg("[UPDATER]   parsed version_patch="+std::string(sm_patch[1]));
                    fgcom_release_latest.version.patch = stoi(sm_patch[1]);
                }

                // Check if version could be parsed successfully
                if (   fgcom_release_latest.version.major > -1
                    && fgcom_release_latest.version.minor > -1
                    && fgcom_release_latest.version.patch > -1
                ) {
                    // get release url
                    // https://github.com/hbeni/fgcom-mumble/releases/tag/v.0.3.0
                    std::string urlbase("https://github.com/hbeni/fgcom-mumble");
                    fgcom_release_latest.url = urlbase + "/tag/" + fgcom_release_latest.tag;
                    
                    //construct download url base
                    // https://github.com/hbeni/fgcom-mumble/releases/download/v.0.3.0/fgcom-mumble-linux-0.3.0.tar.gz
                    std::string dlurlbase(urlbase + "/releases/download/" + fgcom_release_latest.tag); 
                    
                    // generate download url for target platform
                    std::string verStr = std::to_string(fgcom_release_latest.version.major)
                                        + "." + std::to_string(fgcom_release_latest.version.minor)
                                        + "." + std::to_string(fgcom_release_latest.version.patch);
                    //fgcom_release_latest.downUrl = dlurlbase+"/fgcom-mumble-client-binOnly-"+verStr+".zip";
                    fgcom_release_latest.downUrl = dlurlbase+"/"+fgcom_asset_name+verStr+fgcom_bin_postfix+fgcom_bin_extension;

                } else {
                    // something went wrong.
                    pluginLog("[UPDATER] ERROR: Can't obtain the tags header version number from '"+fgcom_cfg.updaterURL+"'");
                }
            } else {
                pluginLog("[UPDATER] fetch resultCode not compatible; resultCode="+std::to_string(res->status));
            }
            
        } else {
            auto http_err = res.error();
            std::ostringstream http_err_stream;
            http_err_stream << http_err;
            pluginLog("[UPDATER] ERROR fetching latest release info from web: "+http_err_stream.str());
        }
    } else {
        pluginLog("[UPDATER] ERROR fetching latest release info from web: unsupported characters in URL");
    }
}



/*************************************
 * Mumble Plugin API implementation  *
 ************************************/


/*
 * Check for new releases
 */
bool mumble_hasUpdate() {

    // Updater can be disabled by setting url to "disabled" in the ini
    if (std::regex_search(fgcom_cfg.updaterURL, std::regex("^disabled|off$", std::regex_constants::icase))) {
        pluginLog("[UPDATER] skipping: update check is disabled (ini request).");
        return false;
    }

#ifndef SSLFLAGS
    // if no SSL support was compiled, and nothing specifically configured in the ini file, set default non-ssl location
    if (fgcom_cfg.updaterURL == "") {
        fgcom_cfg.updaterURL = "http://fgcom.hallinger.org/version.php";
    }
#endif

    // fetch latest info; this will populate the struct fgcom_release_latest
    if (fgcom_cfg.updaterURL != "") {
        fgcom_getLatestReleaseFrom_WebVersionChecker();
    } else {
        fgcom_getLatestReleaseFrom_Github_Web();
    }
    
    // check for errors
    if (fgcom_release_latest.version.major <= -1
    || fgcom_release_latest.downUrl == ""   ) {
        pluginLog("[UPDATER] ERROR fetching release info: i have no idea if there is an update!");
        return false;

    } else {
        bool updatePending = fgcom_isVersionNewer(fgcom_release_latest.version);
        std::string verStr = std::to_string(fgcom_release_latest.version.major)
                         + "." + std::to_string(fgcom_release_latest.version.minor)
                         + "." + std::to_string(fgcom_release_latest.version.patch);
        pluginDbg("[UPDATER] Version check: latest='"+verStr+"'; newer="+std::to_string(updatePending));
        
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
