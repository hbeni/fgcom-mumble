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

import com.formdev.flatlaf.FlatDarkLaf;
import hbeni.fgcom_mumble.UDPclient.SendRes;
import hbeni.fgcom_mumble.gui.MainWindow;
import javax.swing.UnsupportedLookAndFeelException;

/**
 * FGCom-mumble radio GUI client
 * 
 * Implements a basic platform independent GUI to the mumble plugin in order
 * to simulate arbitary radio stacks.
 * 
 * @author Benedikt Hallinger
 */
public class radioGUI {
    
    /* A class containing the options */
    public static class Options {
        public static String  udpHost             = "localhost";
        public static int     udpPort             = 16661;
        public static float   udpSendRateHz       = 10;
        public static int     debugSignalOverride = -5;
        public static String  simConnectHost      = "localhost";
        public static int     simConnectPort      = 500; // 500=MSFS2020
        public static boolean enableAudioEffecs   = true;
        public static boolean allowHearingNonPluginUsers = false;
    }
    
    /* A structure with the internal model */
    protected static State state;
    
    /* A client pushing the packets to the udp port */
    protected static UDPclient udpClient;
    
    /* Window handles */
    public static MainWindow mainWindow;
    
    /**
     * Start the Application
     * 
     * @param args 
     */
    public static void main(String[] args) throws InterruptedException {
       
        /* Initialize the cool flatlaf Look&Feel */
        FlatDarkLaf.install();
        try {
            javax.swing.UIManager.setLookAndFeel(new FlatDarkLaf());
            //javax.swing.UIManager.setCurrentTheme(new OceanTheme());
        } catch (UnsupportedLookAndFeelException ex) {
            // ignore: default theme will be used
        }

        /* init internal data model (state) */
        state = new State();
        
        // init with default: somewhere at EDDM
        state.setCallsign("ZZZZ");
        state.setLocation(48.3440238, 11.7650830, 6.6f);  // height in ft AGL!
        state.getRadios().add(new Radio("121.000"));  // emergency
        state.getRadios().add(new Radio("122.540"));  // general chat
        
                
        /* Create and display the main form */
        mainWindow = new MainWindow(state);
        mainWindow.setVisible(true);
        
        
        /* start the main loop */
        udpClient = new UDPclient(state);
        SimConnectBridge simconnect_client = null;
        while (mainWindow.isVisible()) {
            
            /* Boot simConnect if it was requested */
            if (state.isSimConnectSlave() && simconnect_client == null) {
                simconnect_client = invokeSimConnect();
            }
            
            /* UDP sending */
            udpClient.setActive(mainWindow.getConnectionActivation());
            udpClient.prepare();
            SendRes result = udpClient.send();
            if (result.res) {
                mainWindow.setConnectionState(true);
            } else {
                mainWindow.setConnectionState(false);
                result.msg = (result.msg=="")? "not connected" : result.msg;
            }

            if (state.statusmessage != "") result.msg = state.statusmessage + " / " + result.msg;
            
            if (state.isSimConnectSlave()) result.msg = "[SimConnect] "+result.msg;
            
            mainWindow.setStatusText(result.msg);
            
            Thread.sleep( (long)(1000 / Options.udpSendRateHz) ); // try 10 times per second

        }

    }
    
    /**
     * Get internal state
     */
    public static State getState() {
        return state;
    }
    
    /**
     * Used to deregister a radio form the internal state
     * @param r 
     */
    public static void deregisterRadio(Radio r) {
        // set special delete frquency to let the plugin know the radio ceases to exist
        r.setFrequency("<del>");
        try {
            // sleep a bit so the UDP client has a chance to broadcast the deregistration to the plugin
            Thread.sleep(500);
        } catch (InterruptedException ex) { }
        
        // finally remove the radio from the internal state
        state.radios.remove(r);
    }
    
    
    /**
     * Signify that simConnect should be activated
     * Prepares internal and GUI state for slaving trough SimConnect
     */
    public static void enableSimConnect() {
        // stop the udp sending
        udpClient.setActive(false);
        
        // clear out internal state
        try {
            for (Radio r : state.getRadios()) {
                radioGUI.deregisterRadio(r);
            }
        } catch (Exception e) {
            state.statusmessage = "INTERNAL ERROR - restart RadioGUI!";
        }
        
        // Prepare state
        state.getRadios().clear();
        state.setCallsign("SimConnect");
        state.setLocation(0, 0, 0f);
        state.getRadios().add(new Radio("SimConnect-COM1"));
        state.getRadios().add(new Radio("SimConnect-COM2"));
        mainWindow.updateFromState();
        
        // update GUI
        mainWindow.prepareSimConnect();
        mainWindow.updateFromState();
        
        // signify to main loop that the bridge should be active
        state.setSimConnectSlaving(true);
    }
    
    /**
     * Establish SimConnect bridge
     * 
     * @return established bridge
     */
    public static SimConnectBridge invokeSimConnect() {

        // Invoke the simConnect brigde
        SimConnectBridge fgcom_simconnectbridge = null;
        try {
            fgcom_simconnectbridge = new SimConnectBridge();
        } catch (java.net.ConnectException e) {
            // connection failure. will be handled in the main loop already.
            // we just return null here.
        } catch (Exception e) {
            e.printStackTrace();
        }
        return fgcom_simconnectbridge;
    }
    
}