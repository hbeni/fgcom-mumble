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

import java.security.InvalidParameterException;


/**
 * Updater checks for updates
 * 
 * @author beni
 */
public abstract class Updater {
    
    /**
     * Makes a new instance of the Updater
     */
    public Updater() {
    }
    
    /**
     * Gets local version.
     * @return VersionInfo
     */
    public VersionInfo getLocalVersion() {
            java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("project"); 
            return(new VersionInfo(bundle.getString("version")));
    }
    
    /**
     * Gets upstream version.
     */
    public abstract VersionInfo getUpstreamVersion();
    
    
    /**
     * Details about versions
     */
    public class VersionInfo implements Comparable<VersionInfo>{
        protected String src;
        protected int major;
        protected int minor;
        protected int patch;
        
        /**
         * Construct VersionInfo out of a string formatted like "1.2.3"
         * @param versionStr
         */
        public VersionInfo(String versionStr) {
            this.src = versionStr;
            String[] dottedStrings = versionStr.split("\\.", 3);
            if (dottedStrings.length != 3)
                throw new InvalidParameterException("Version String '"+versionStr+"' not semantic (eg. like '1.2.3')");
            
            this.major = Integer.parseInt(dottedStrings[0]);
            this.minor = Integer.parseInt(dottedStrings[1]);
            this.patch = Integer.parseInt(dottedStrings[2]);
        }
 
        @Override
        public int compareTo(VersionInfo ver) {
            // return -1; // this object is smaller than ver
            if (ver.major > this.major) return -1;
            if (ver.major == this.major && ver.minor > this.minor) return -1;
            if (ver.major == this.major && ver.minor == this.minor && ver.patch > this.patch) return -1;
            
            // return  1; // this object is bigger than ver
            if (ver.major < this.major) return 1;
            if (ver.major == this.major && ver.minor < this.minor) return 1;
            if (ver.major == this.major && ver.minor == this.minor && ver.patch < this.patch) return 1;
            
            // this object is equal to ver
            return 0;
        }
        
        @Override
        public String toString() {
            return this.src;
        }
    } 
    
}