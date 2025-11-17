/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2023 Benedikt Hallinger
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

import hbeni.fgcom_mumble.gui.RDFWindow;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UDP server to receive UDP messages from the plugin
 * 
 * @author beni
 */
public class UDPserver extends Thread {
    
    protected RDFWindow rdfWindow;
    
    private DatagramSocket udpSocket;
    protected int udpSocket_timeout = 1000;
    private boolean active = true;  // If the thread should run. Set to false to kill it.
    
    Pattern pattern_rdf_id_rx = Pattern.compile("RDF:.*ID_RX=(\\d+)"); // Pattern do extract the radio IF for RDF packet
    
    public UDPserver(RDFWindow wnd) {
        // Initialize
        rdfWindow = wnd;
        rdfWindow.setStatusText("UDP server: initializing...");

    }
    
    public void shutdown() {
//        System.out.println("UDP Server: shutdown");
        active = false;
        
        this.closeSocket();

        rdfWindow.setStatusText("UDP server shut down.");
        rdfWindow.setConnectionState(false);
        rdfWindow.setPortText("-");
        this.interrupt();
    }
    
    /*
    * Threads main loop
    *
    * This waits and processes data.
    */
    public void run() {
        while(active) {

            boolean openSocketResult = openSocket();
            if (openSocketResult) {
                int port = udpSocket.getLocalPort();
//                System.out.println("UDP Server: port established: "+port);
                receiveData();
            } else {
                try {
                    // try again later
//                    System.out.println("UDP Server: waiting for socket");
                    UDPserver.sleep(1000);
                    
                } catch (InterruptedException ex) {
                    shutdown();
                }
            }
        }
        
        // End of thread / shutdown requested
        this.shutdown();
    }
    
    /*
    * Open UDP listen socket
    *
    * Usually a UDP server (the plugin in this case) responds to the clients
    * sending source port. Thus, we need to wait for the UDP client to
    * establish a connection first, and then use the local port of that socket.
    *
    * @return boolean, wether the socket could be opened or not
    */
    protected boolean openSocket() {
        
        if (udpSocket != null && !udpSocket.isClosed()) return true;
        
        DatagramSocket localClientSocket = radioGUI.getUDPClient().socket;
        if (localClientSocket != null && !localClientSocket.isClosed()) {
            int port = localClientSocket.getLocalPort();
            rdfWindow.setPortText(String.valueOf(port));
            
            // we reuse the client socket
            udpSocket = localClientSocket;
        
//            // Go and try to open the port
//            try {
//                udpSocket = new DatagramSocket(port);
//                udpSocket.setSoTimeout(udpSocket_timeout);
//                active    = true;
//                
//                System.out.println("UDP Server: socket opened");
//                return true;
//                
//            } catch (SocketException ex) {
//                rdfWindow.setStatusText("could not open port "+port+": "+ex.getMessage());
//                rdfWindow.setConnectionState(false);
//            }
        } else {
//            System.out.println("UDP Server: waiting for connection");
            rdfWindow.setStatusText("UDP client not connected, waiting for udp client connection...");
        }
        
        return false;
    }
    
    public void closeSocket() {
        /*     No need: we share the socket with the local udp client
        if (udpSocket != null) {
            this.udpSocket.close();
            this.udpSocket = null;
        }
        */
    }
    
    public void receiveData() {
        byte[] buffer = new byte[1024];
        DatagramPacket request = new DatagramPacket(buffer, buffer.length);
        
        try {
//            System.out.println("UDP Server: waiting for data");
            rdfWindow.setStatusText("waiting for data at port "+udpSocket.getLocalPort()+"...");
            rdfWindow.setConnectionState(true);
            udpSocket.receive(request); // blocking operation
            String data = new String(request.getData());
            
            rdfWindow.setStatusText("data: "+data);
            this.parseData(data);
            
  
        } catch(IOException ex) {
            rdfWindow.setStatusText("error receiving packet: "+ex.getMessage());
            rdfWindow.setConnectionState(false);
        }
    }
    
    /**
     * Unescape UDP field
     * @param field
     * @return escaped Field ('a\,b\=c' => 'a,b=c')
     */
    public static String unescapeUDP(String field) {
        return field
                .replace("\\,", ",")
                .replace("\\=", "=");
    }
    
    /**
     * Parses RDF data received from UDP.
     * 
     * The actual format is described in plugin.spec.md.
     * Test with: `echo "RDF:CS_TX=Test,FRQ=123.45,DIR=180.5,VRT=12.5,QLY=0.98,ID_RX=1" | netcat -q0 -u localhost <port>`
     * 
     * @param data 
     */
    protected void parseData(String data) {
//        System.out.println("UDP Server: parsing data: "+data);

        Matcher match = pattern_rdf_id_rx.matcher(data);
        if (match.find()) {
//            System.out.println("UDP Server:   matched: "+match.group(1));
            int rdf_idx = Integer.parseInt(match.group(1));
//            System.out.println("UDP Server:   matched: int="+String.valueOf(rdf_idx));
            try {
                Radio r = radioGUI.getState().getRadios().get(rdf_idx-1);
                r.parseRDF(data);
            } catch(IndexOutOfBoundsException ex) {
//                System.out.println("UDP Server:   ERROR: radio not in backend");
            }
        } else {
//            System.out.println("UDP Server:   NOT matched: "+data+" (re='"+pattern_rdf_id_rx+"')");
        }
        
        rdfWindow.updateFromState();
    }
}