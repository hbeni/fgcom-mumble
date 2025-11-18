# Optional Improvements 

## Teamspeak Porting

**Porting FGCom-mumble to Teamspeak**
- **Target Platform**: Teamspeak 3/5 client integration
- **Benefits**: Alternative voice platform for users who prefer Teamspeak over Mumble
- **Implementation**: Teamspeak plugin development for radio simulation
- **Features**: Same radio propagation, frequency management, and realistic communication features
- **Compatibility**: Maintain feature parity with Mumble version

## For automatic generation of ATIS recordings:

**Piper - Best for Speed**
- Quality: Very good, natural-sounding
- Features: 40+ languages, low resource usage
- Download from https://github.com/rhasspy/piper
- Usage: `./piper --model en_US-lessac-medium --output_file output.wav < input.txt`

## Security Enhancement Recommendation

**RECOMMENDED ADDITION:** A user registration system with web-based account creation and email verification would significantly improve the security posture of FGCom-mumble. This would provide:

- **User Account Management:** Secure user registration and authentication
- **Email Verification:** Account validation through verified email addresses
- **Enhanced Security:** Proper user identity verification and access control
- **Audit Trail:** User activity tracking and accountability
- **Access Control:** Granular permissions and role-based access

### Implementation Benefits:

- Replace API key-based authentication with proper user accounts
- Enable secure multi-user environments
- Provide user activity logging and monitoring
- Support role-based permissions for different user types
- Enhance overall system security and accountability

This enhancement would transform FGCom-mumble from a technical tool into a production-ready system suitable for entertainment and educational environments.

## Cold war era voice encryption:

### Soviet/East Bloc Systems:

**Yachta T-219**
- Analog voice scrambler (Yachta or Yakhta means 'Boat' in Russian)
- **Frequency Range:** 3 MHz to 30 MHz (HF band)
- **Modulation:** Upper Sideband (USB)
- **Bandwidth:** 2.7 kHz
- **Audio Response:** 300 to 2700 Hz
- **Unique Design:** FSK sync signal (100 baud, 150 Hz shift) transmitted centrally
- **Signal Structure:** Scrambled voice stream split above and below FSK signal
- **Scrambling Method:** Voice divided into unequal time segments, subchannels swapped and inverted
- **FSK Sequence:** Based on M-sequence from polynomial x^52 + x^49 + 1
- **Key Card System:** Uses coding key cards for encryption
- **Operational Use:** Russian military tactical communications, time-sensitive information
- **Distinctive Sound:** Classic Soviet "warbled" or "Donald Duck" sound
- **Current Status:** Still in use as recently as 2025, being replaced by CIS-12 mode
- **Test Equipment:** KU-27 and KU-27M test setups for maintenance and alignment

**Other East Bloc options:**
- **RU-1 scrambler** - similar frequency inversion
- **Vega scrambler** - band-splitting scrambler

**Legenda System**
- Soviet digital secure voice (1970s-80s)
- Used in strategic communications
- Linear predictive coding vocoder

### NATO Systems:

**VINSON (KY-57/KY-58)**
- US/NATO standard secure voice system (1980s)
- **Digital Vocoder:** CVSD (Continuously Variable Slope Delta) codec at 16 kbps
- **Modulation:** FSK (Frequency Shift Keying)
- **Frequency Range:** VHF/UHF tactical bands
- **Security:** Type 1 encryption (NSA approved)
- **Key Management:** Electronic key loading system
- **Audio Quality:** Characteristic robotic, buzzy sound due to CVSD compression
- **Usage:** Tactical radios, field communications
- **Interoperability:** NATO standard for secure voice communications

**ANDVT (KY-75)**
- Advanced digital voice terminal
- LPC vocoder
- Also FSK modulation

**STANAG 4197**
- NATO QPSK OFDM signal used in Advanced Narrowband Digital Voice Terminal (ANDVT or AN/DVT) modems
- Transmits encrypted digital voice over HF
- Includes ANDVT MINTERM KY-99A modem
- Defined as "Modulation and coding characteristics that must be common to assure interoperability of 2400 bps linear predictive encoded digital speech transmitted over HF radio facilities"
- Utilizes similar waveforms to MIL-STD-188-110A/B Appendix B waveform but without the 393.75 Hz pilot tone
- Has unique preamble that differs from App. B waveform
- Preamble starts similarly to 110A/B App. B 39-Tone OFDM but begins with 16 tone data header before 39 tone data payload
- Predominantly used for digital voice, so encrypted digital voice is the payload in the 39 tone segment

**Russian Equivalent of STANAG 4197**
- Modern Russian HF digital voice systems
- Designed for secure HF radio communications
- Comparable to NATO STANAG 4197 standards

### European systems:

- **BRENT (UK)** - digital vocoder
- Various national systems

**SPECOM (Speech Communications)**
- British system, 1970s
- Linear predictive vocoder
- Used in PTARMIGAN military system

**AUTOSEVOCOM**
- French secure voice system
- Used by French military during Cold War

**DARC (Digital Audio Reconstruction Circuit)**
- NATO compatible system
- Used in various European forces

**ELCRODAT**
- Swedish secure voice system
- Ericsson-developed

### Non-Aligned / Other:

**Indian HF Systems**
- Various Indian secure HF voice systems
- Cold War era development

## Most Distinctive/Recognizable Sounds:

### For Maximum Authenticity:

- **T-219/Yachta** - Classic Soviet "warbled" sound
  - Most distinctive Cold War encryption sound
  - FSK sync signal with voice scrambling creates unique "Donald Duck" effect
  - Still in use today, making it highly recognizable

- **VINSON (KY-57)** - NATO tactical radio sound
  - CVSD codec creates characteristic buzzy, robotic quality
  - Standard NATO tactical radio encryption sound
  - Widely used in military communications

- **Granit** - Unique time-scrambling effect
  - Soviet time-domain scrambling system
  - Creates distinctive temporal distortion effects
  - Less common but highly recognizable when encountered
