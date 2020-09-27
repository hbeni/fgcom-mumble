/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hbeni.fgcom_mumble;

/*
* Simple model of a single radio
*/
public class Radio {
    protected String  frq;
    protected float   volume;
    protected float   power;
    protected float   squelch;
    protected boolean ptt;

    public Radio() {
        setFrequency("");
        setPower(10.0f);
        setVolume(1.0f);
        setSquelch(0.1f);
        setPTT(false);
    }
    public Radio(String frq) {
        this();
        setFrequency(frq);
    }

    public synchronized void setFrequency(String f) {
        frq = f;
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
