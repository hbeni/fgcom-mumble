/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hbeni.fgcom_mumble;

import jdk.nashorn.internal.runtime.JSType;

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

    public Radio() {
        setFrequency("");
        setPower(10.0f);
        setVolume(1.0f);
        setSquelch(0.1f);
        setPTT(false);
        setPwrBtn(true);
        setChannelWidth(-1);
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
}
