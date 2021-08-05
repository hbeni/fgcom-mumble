/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2021 Benedikt Hallinger
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
 */
package hbeni.fgcom_mumble.updater;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.InvalidParameterException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;

/**
* Github updater checker.
* 
* Tries to check the GitHub release page for current version.
*/
public class GitHubChecker extends Updater {
   protected VersionInfo upstreamVersion;

    @Override
    public VersionInfo getUpstreamVersion() {
        if (upstreamVersion == null) {
            try {
                String foundTag = getGitHubReleaseTag();
                upstreamVersion = new VersionInfo(getGitHubReleaseVersion(foundTag));
            } catch (Exception ex) {
                // Just report errornous version, so the application can carry on.
                upstreamVersion = new VersionInfo("-1.-1.-1");
                System.out.println("WARNING: error parsing the version info: "+ex.getMessage());
            }       
        }
        return upstreamVersion;
    }
    
    /**
     * Query the release page for the latest release
     * @return Tag string of latest release
     * @throws IOException 
     */
    protected String getGitHubReleaseTag() throws IOException {
        String httpsURL = "https://github.com/hbeni/fgcom-mumble/releases";
        URL myUrl = new URL(httpsURL);
        HttpsURLConnection conn = (HttpsURLConnection)myUrl.openConnection();
        InputStream is = conn.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        // try to parse out the version info
        String inputLine;
        String foundTag = null;
        parseTag:
        while ((inputLine = br.readLine()) != null) {
            //System.out.println(inputLine);
            
            Pattern pattern = Pattern.compile("<a href=\".+/releases/tag/(.+?)\">.+?</a>");
            Matcher matcher = pattern.matcher(inputLine);
            while (matcher.find()) {
                //System.out.println("DBG: FOUND TAG: "+matcher.group(1));
                foundTag = matcher.group(1);
                break parseTag;
            }
        }

        br.close();
        return foundTag;
    }

    /**
     * Query the tag for the actual released version
     * @param releaseTag
     * @return
     * @throws IOException 
     */
    protected String getGitHubReleaseVersion(String releaseTag) throws IOException {
        if (releaseTag == null) throw new InvalidParameterException("No valid release tag supplied: "+releaseTag);
        String httpsURL = 
                "https://raw.githubusercontent.com/hbeni/fgcom-mumble/"
                + releaseTag
                + "/client/radioGUI/pom.xml";
        URL myUrl = new URL(httpsURL);
        HttpsURLConnection conn = (HttpsURLConnection)myUrl.openConnection();
        InputStream is = conn.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        // try to parse out the version info
        String inputLine;
        String foundVersion = null;
        parseVersion:
        while ((inputLine = br.readLine()) != null) {
            //System.out.println(inputLine);
            
            Pattern pattern = Pattern.compile("<version>(.+?)</version>");
            Matcher matcher = pattern.matcher(inputLine);
            while (matcher.find()) {
                //System.out.println("DBG: FOUND VERSION: "+matcher.group(1));
                foundVersion = matcher.group(1);
                break parseVersion;
            }
        }

        br.close();
        return foundVersion;
    }
}