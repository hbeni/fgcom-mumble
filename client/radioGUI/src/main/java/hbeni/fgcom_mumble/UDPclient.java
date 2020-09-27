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
 */
package hbeni.fgcom_mumble;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

/**
 * UDP client that sends messages to the mumble plugin
 * 
 * @author beni
 */
public class UDPclient {

    protected boolean active;
    protected State state;
    
    
    /* UDP stuff */
    DatagramSocket socket;

    /**
     * Init / construct
     */
    public UDPclient(State s) {
        this.active = false;
        this.state = s;
    }
    
    /**
     * Open socket
     */
    protected void openSocket() throws UnknownHostException, SocketException {
        if (socket == null) {
            socket = new DatagramSocket();
        }
    }
    
    /**
     * Sets the UDP sending status
     */
    public void setActive(boolean act) {
        this.active = act;
    }
    
    /**
     * Update and compose state
     */
    public String prepare() {
        String msg = new String();
        msg += "CALLSIGN=" + state.getCallsign();
        msg += ",LAT=" + state.getLatitutde();
        msg += ",LON=" + state.getLongitude();
        msg += ",HGT=" + state.getHeight();
        
        int i = 1;
        for (Radio r : state.getRadios()) {
            String ptt_str = r.getPTT()? "1" : "0";
            msg += ",COM"+i+"_PTT="+ptt_str;
            msg += ",COM"+i+"_FRQ="+r.getFrequency();
            msg += ",COM"+i+"_VOL="+r.getVolume();
            msg += ",COM"+i+"_PWR="+r.getPower();
            msg += ",COM"+i+"_SQC="+r.getSquelch();
            
            // TODO: implement PBT, VLT, SRV
            //msg += ",COM"+i+"_PBT="+r.isSwitchedOn();
            //msg += ",COM"+i+"_VLT="+r.getVolts();
            //msg += ",COM"+i+"_SRQ="+r.isServiceable();
            
            i++;
        }
        
        // other stuff
        float dbgSignalQLY = (radioGUI.Options.debugSignalOverride >= 0.0)? (float)radioGUI.Options.debugSignalOverride/100 : -1;
        msg += ",DEBUG_SIGQLY="+dbgSignalQLY;
        String audioFX = (radioGUI.Options.enableAudioEffecs)? "1" : "0";
        msg += ",AUDIO_FX_RADIO="+audioFX;
        
        return msg;
    }

    /**
     * Sends a UDP packet
     * 
     * @return String that was sent, or nullpoiter in case of error
     */
    public SendRes send() {
        SendRes res = new SendRes();
        String msg  = prepare()+'\n';
        if (this.active) {
            try {
                openSocket();
                InetAddress address = InetAddress.getLoopbackAddress(); // fixed for now - the plugin does not support networking on purpose.
                
                
                byte[] buffer = msg.getBytes();
                //buffer = msg.getBytes();
                
                DatagramPacket request = new DatagramPacket(buffer, buffer.length, address, radioGUI.Options.udpPort);
                socket.send(request);
                
                res.res = true;
                res.msg = "SEND_OK: "+msg;
               

            } catch (UnknownHostException ex) {
                res.res = false;
                res.msg = "SEND_ERR: "+ex.toString();
            } catch (SocketException ex) {
                res.res = false;
                res.msg = "SEND_ERR: "+ex.toString();
            } catch (IOException ex) {
                res.res = false;
                res.msg = "SEND_ERR: "+ex.toString();
            }
            
        } else {
            // not active: return null
            res.res = false;
            res.msg = "not connected: "+msg;
        }
        
        return res;
    }
    
    
    public class SendRes {
        public String msg = "";
        public boolean res = false;
    }
    
}
