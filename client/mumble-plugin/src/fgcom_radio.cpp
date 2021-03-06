/*******************************************************************//**
 * @file        fgcom_radio.cpp
 * @brief       Defines fgcom_radio class
 * @authors    	Benedikt Hallinger & mill-j
 * @copyright   (C) 2021 under GNU GPL v3 
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
 * 
 * @todo Move definition into header
 */

#ifndef _FGCOM_RADIO__
#define _FGCOM_RADIO__

#include <string>
/**
 * @class fgcom_radio
 * @brief This represents the state of a radio
 * @todo 8.33hz to 25hz converter
 */
class fgcom_radio {
private:
	float  frequency = 0.0; 	 ///< tuned frequency (real carrier frequency)
	std::string  dialedFRQ = ""; ///< dialed frequency (aka "channel"; what was supplied from the COMn_FRQ= field)
	bool  power_btn = true; 	 ///< true if switched on
	float volts = 12;  			 ///< how much electric power it has (>0 = on)
	bool  serviceable = true;    ///< false if broken
	bool  ptt = false;           ///< true if PTT is pushed
	float volume = 1.0;        	 ///< volume, 0.0->1.0
	float watts = 10;            ///< tx power in watts
	float squelch = 0.1;       	 ///< squelch setting (cutoff signal below this quality)
	bool  rdfEnabled = false;    ///< if radio can receive RDF information
	float channelWidth = -1;  	 ///< channel width in kHz
public:
	bool isPowered();
	bool isServiceable();
	bool isPTT();
	bool isRDF();
	
	float getFrequency();
	std::string getDialedFrequency();
	std::string getPTT();
	float getVolts();
	float getVolume();
	float getWatts();
	float getSquelch();
	float getChannelWidth();
	
	void setPowered(bool Powered);
	void setServiceable(bool Serviceable);
	void setPTT(bool PTT);
	void setRDF(bool RDF);
	void setFrequency(float Freq);
	void setDialedFrequency(std::string Freq);
	void setVolts(float Volts);
	void setVolume(float Volume);
	void setWatts(float Watts);
	void setSquelch(float Squelch);
	void setChannelWidth(float Width);
	
	void update(
		bool Power, 
		bool Serviceable, 
		bool PTT, 
		bool RDF,
		std::string DialedFreq,
		float Volts,
		float Volume,
		float Watts,
		float Squelch,
		float ChannelWidth
	);
};

///Returns whither the radio is powered on
bool fgcom_radio::isPowered(){return power_btn;}
///Returns whither the radio is in working order
bool fgcom_radio::isServiceable(){return serviceable;}
///Returns whither the radio's ptt is toggled
bool fgcom_radio::isPTT(){return ptt;}
///Returns whither the radio has RDF enabled
bool fgcom_radio::isRDF(){return rdfEnabled;}

///Returns whither the radio's ptt is toggled as a string
std::string fgcom_radio::getPTT() {
	if(ptt) 
		return "1";
	return "0";
}


///Returns the frequency that this radio is tuned to.
float fgcom_radio::getFrequency(){return frequency;}
///Returns the frequency string from udp data
std::string fgcom_radio::getDialedFrequency(){return dialedFRQ;}
///Returns radio voltage
float fgcom_radio::getVolts(){return volts;}
///Returns radio volume
float fgcom_radio::getVolume(){return volume;}
///Returns radio watts
float fgcom_radio::getWatts(){return watts;}
///Returns radio squelch
float fgcom_radio::getSquelch(){return squelch;}
///Returns radio channel width
float fgcom_radio::getChannelWidth(){return channelWidth;}

///Sets power button state
void fgcom_radio::setPowered(bool Powered) { power_btn = Powered;}
///Sets serviceable state
void fgcom_radio::setServiceable(bool Serviceable) {serviceable = Serviceable;}
///Sets PTT status
void fgcom_radio::setPTT(bool PTT) { ptt = PTT;}
///Changes RDF status
void fgcom_radio::setRDF(bool RDF) { rdfEnabled = RDF;}
///Sets the radio's frequency as a float. @see setDialedFrequency()
void fgcom_radio::setFrequency(float Freq) { frequency = Freq;}
///Sets the radio's frequency as a string. @see setFrequency()
void fgcom_radio::setDialedFrequency(std::string Freq) { dialedFRQ = Freq;}
///Sets the radio's voltage
void fgcom_radio::setVolts(float Volts) {volts = Volts;}
///Sets the radio's volume
void fgcom_radio::setVolume(float Volume) { volume = Volume;}
///Sets the radio's wattage
void fgcom_radio::setWatts(float Watts) { watts = Watts;}
///Sets the radio's squelch
void fgcom_radio::setSquelch(float Squelch) { squelch = Squelch;}
///Sets the radio's channel with in hertz
void fgcom_radio::setChannelWidth(float Width) { channelWidth = Width;}


/**
 * Updates the internal state of the radio in one function
 */

void fgcom_radio::update(bool Power, bool Serviceable, bool PTT,  bool RDF,
	        std::string DialedFreq, float Volts, float Volume, float Watts,
				float Squelch, float ChannelWidth) {
	power_btn = Power;
	serviceable = Serviceable;
	ptt = PTT;
	rdfEnabled = RDF;
	dialedFRQ = DialedFreq;
	volts = Volts;
	volume = Volume;
	watts = Watts;
	squelch = Squelch;
	channelWidth = ChannelWidth;
}

#endif
