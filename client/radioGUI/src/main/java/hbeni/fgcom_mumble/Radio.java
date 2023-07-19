/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hbeni.fgcom_mumble;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
* Simple model of a single radio
*/
public class Radio {
    protected String  frq;
    protected float   volume;
    protected float   power;
    protected float   squelch;
    protected boolean ptt;     // tx-pwr in Watts
    protected boolean pwrbtn;
    protected float   channelWidth;
    
    protected boolean  rdf;
    protected boolean  rdf_parsed;
    protected String   rdf_cs_tx;
    protected float    rdf_frq;
    protected float    rdf_dir;
    protected float    rdf_vrt;
    protected float    rdf_qly;
    protected int      rdf_id_rx;
    Pattern pattern_udp_fields = Pattern.compile("^(?:RDF:)?(\\w+)=(.+)"); // key=value

    public Radio() {
        setFrequency("");
        setPower(10.0f);
        setVolume(1.0f);
        setSquelch(0.1f);
        setPTT(false);
        setPwrBtn(true);
        setChannelWidth(-1);
        setRDF(false);
        
        parseRDF(null);
    }
    public Radio(String frq) {
        this();
        setFrequency(frq);
    }

    public synchronized void setFrequency(String f) {
        frq = f;
        
        // set default channel width depending on band, if not set yet
        try {
            double frq_numeric = Float.parseFloat(frq);
            if (frq_numeric > 30.0 && frq_numeric <= 300) {
                if (this.getChannelWidth() == -1) this.setChannelWidth(8.33f);    // VHF default: 8.33
            } else {
                this.setChannelWidth(-1);  // let default apply
            }
        } catch (NumberFormatException nfe) {
            // let default apply
        }
    }
    public synchronized void setVolume(float v) {
        volume = v;
    }
    public synchronized void setPower(float p) {
        power = p;
    }
    public synchronized void setSquelch(float s) {
        squelch = s;
    }
    public synchronized void setPwrBtn(boolean b) {
        pwrbtn = b;
    }
    public synchronized void setChannelWidth(float kHz) {
        channelWidth = kHz;
    }
    public synchronized void setRDF(boolean p) {
        rdf = p;
        
        // reset parsed marker and fields
        if (rdf_parsed && !p) {
            rdf_parsed = false;
            parseRDF(null);
        }  
    }

    public synchronized String getFrequency() {
        return frq;
    }
    public synchronized float getVolume() {
        return volume;
    }
    public synchronized float getPower() {
        return power;
    }
    public synchronized float getSquelch() {
        return squelch;
    }
    public synchronized boolean getPwrBtn() {
        return pwrbtn;
    }
    public float getChannelWidth() {
        return channelWidth;
    }
    public boolean getRDF() {
        return rdf;
    }
    public boolean getRDFParsed() {
        return rdf_parsed;
    }
    
    /**
     * Set if the PTT is currently pushed
     * @param pushed 
     */
    public synchronized void setPTT(boolean pushed) {
        ptt = pushed;
    }
    public synchronized boolean getPTT() {
        return ptt;
    }
    
    /**
    * Parses RDF strig data
    */
    public void parseRDF(String data) {
        if (!rdf || data == null) {
            rdf_cs_tx = "";
            rdf_frq = 0.0f;
            rdf_dir = 0.0f;
            rdf_vrt = 0.0f;
            rdf_qly = 0.0f;
            rdf_id_rx = -1;
            return;
        }
        
//        System.out.println("Radio: got RDF data: "+data);
        
        String fields[] = data.split(",");
//        System.out.println("  fields: "+fields.length);
        for (int i=0; i<fields.length; i++) {
            Matcher match = pattern_udp_fields.matcher(fields[i]);
            try {
                if (match.find()) {
//                    System.out.println("Radio: parsed field="+match.group(1)+"; value="+match.group(2));
                    switch (match.group(1)) {
                        case "FRQ":
                            rdf_frq = Float.parseFloat(match.group(2));
                            break;
                        case "DIR":
                            rdf_dir = Float.parseFloat(match.group(2));
                            break;
                        case "VRT":
                            rdf_vrt = Float.parseFloat(match.group(2));
                            break;
                        case "QLY":
                            rdf_qly = Float.parseFloat(match.group(2));
                            break;
                        case "CS_TX":
                            rdf_cs_tx = match.group(2);
                            break;
                        case "ID_RX":
                            rdf_id_rx = Integer.parseInt(match.group(2));
                            break;
                    }
                }
                
            } catch(Exception ex) {
//                System.out.println("RDF data parse error: "+ex.getMessage());
            }

            
        }
            
        rdf_parsed = true; // remember that we once got valid data
    }

    public int getRDF_ID_RX() {
        return rdf_id_rx;
    }

    public float getRDF_DIR() {
        return rdf_dir;
    }

    public float getRDF_VRT() {
        return rdf_vrt;
    }

    public float getRDF_FRQ() {
        return rdf_frq;
    }

    public float getRDF_QLY() {
        return rdf_qly;
    }
    
    public String getRDF_CS_TX() {
        return rdf_cs_tx;
    }
}
