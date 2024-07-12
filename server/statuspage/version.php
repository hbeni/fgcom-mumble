<?php
/**
* This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
* Copyright (c) 2024 Benedikt Hallinger
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
***********************************************************************
*
* This is a small version fetcher
*
* It simply gets the latest release from GitHub and outputs a structured
* dataset that the WebVersionChecker function of the mumble plugin updater can understand.
*/

// get github release page
$html = file_get_contents('https://github.com/hbeni/fgcom-mumble/releases');

// parse tag name of latest release
$tag_matches = array();
if (preg_match("@hbeni/fgcom-mumble/releases/tag/([-_.0-9a-zA-Z]+?)[^-_.0-9a-zA-Z]@", $html, $tag_matches)) {
        print("FGCOM_TAG_NAME=".$tag_matches[1]."\n");

        // fetch client header file to get version numbers
        $html = file_get_contents('https://github.com/hbeni/fgcom-mumble/blob/'.$tag_matches[1].'/client/mumble-plugin/fgcom-mumble.h');

        $versions = array(
                "FGCOM_VERSION_MAJOR" => -1,
                "FGCOM_VERSION_MINOR" => -1,
                "FGCOM_VERSION_PATCH" => -1
        );

        foreach ($versions as $vk => $vv) {
                $v_matches = array();
                if (preg_match("@#(?:<.+>)?define(?:<.+>)? (?:<.+>)?".$vk."(?:<.+>)? (?:<.+>)?(\d+)(?:<.+>)?@", $html, $v_matches)) {
                        $versions[$vk] = $v_matches[1];
                        print("$vk=".$versions[$vk]."\n");
                } else {
                        die("ERROR: could not parse ".$vk);
                }
        }

} else {
        die("ERROR: could not parse tag");
}

?>
