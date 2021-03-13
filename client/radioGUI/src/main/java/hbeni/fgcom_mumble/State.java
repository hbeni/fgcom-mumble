/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hbeni.fgcom_mumble;

import java.util.List;
import java.util.Vector;

/**
* State class, tracking the current identity/radio configuration
*/
public class State {
   protected String callsign;
   protected double latitude;
   protected double longitude;
   protected float  height;    // ft AGL
   protected Vector<Radio> radios;
   protected boolean isSimConnectSlave;
   protected String statusmessage = ""; // additional status message prefix
   
   public State() {
       radios = new Vector<>();
   }

   public void setCallsign(String cs) {
       callsign = cs;
   }
   public void setLocation(double lat, double lon, float h) {
       setLatitude(lat);
       setLongitude(lon);
       setHeight(h);
   }
   public void setLatitude(double lat) {
       latitude = lat;
   }
   public void setLongitude(double lon) {
       longitude = lon;
   }
   
   /*
    * set Altitude in ft above ground-level
    */
   public void setHeight(float h) {
       height = h;
   }
   
   public String getCallsign() {
       return callsign;
   }
   public double getLatitutde() {
       return latitude;
   }
   public double getLongitude() {
       return longitude;
   }
   
   /*
    * get Altitude in ft above ground-level
    */
   public float getHeight() {
       return height;
   }
   
   public List<Radio> getRadios() {
       return radios;
   }
   
   /**
    * SimConnect slave status
    */
   public boolean isSimConnectSlave() {
       return isSimConnectSlave;
   }
   public void setSimConnectSlaving(boolean b) {
       isSimConnectSlave = b;
   }
   
}
