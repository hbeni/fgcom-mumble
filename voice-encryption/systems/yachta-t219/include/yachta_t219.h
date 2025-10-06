/**
 * @file yachta_t219.h
 * @brief Yachta T-219 Soviet Analog Voice Scrambler Implementation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains the complete implementation of the Soviet Yachta T-219
 * analog voice scrambler system used for tactical military communications
 * during the Cold War era.
 * 
 * @details
 * The Yachta T-219 was a sophisticated analog voice scrambler that provided
 * secure voice communication over HF radio links. It featured distinctive
 * audio characteristics including "warbled" and "Donald Duck" sounds that
 * made it recognizable to both friendly and enemy forces.
 * 
 * @see https://github.com/Supermagnum/fgcom-mumble
 * @see docs/YACHTA_T219_DOCUMENTATION.md
 */

#ifndef YACHTA_T219_H
#define YACHTA_T219_H

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <complex>
#include <random>

namespace fgcom {
namespace yachta {

/**
 * @class YachtaT219
 * @brief Soviet Yachta T-219 Analog Voice Scrambler Implementation
 * 
 * @details
 * The YachtaT219 class implements the complete Soviet analog voice scrambler
 * system with authentic audio characteristics and encryption methods.
 * 
 * ## Technical Specifications
 * - **Frequency Range**: 3 MHz to 30 MHz (HF band)
 * - **Modulation**: Upper Sideband (USB)
 * - **Bandwidth**: 2.7 kHz
 * - **Audio Response**: 300 to 2700 Hz
 * - **FSK Sync Signal**: 100 baud, 150 Hz shift
 * - **Scrambling Method**: Voice divided into unequal time segments
 * - **M-Sequence**: Based on polynomial x^52 + x^49 + 1
 * - **Key Card System**: Uses coding key cards for encryption
 * - **Distinctive Sound**: Classic Soviet "warbled" or "Donald Duck" sound
 * 
 * ## Usage Example
 * @code
 * #include "yachta_t219.h"
 * 
 * // Create Yachta T-219 instance
 * YachtaT219 yachta;
 * 
 * // Initialize with audio parameters
 * yachta.initialize(44100.0f, 1); // 44.1 kHz, mono
 * 
 * // Set encryption key
 * yachta.setKey(12345, "encryption_key_data");
 * 
 * // Encrypt audio
 * std::vector<float> input_audio = loadAudioData();
 * std::vector<float> encrypted_audio = yachta.encrypt(input_audio);
 * @endcode
 * 
 * @note This implementation provides authentic simulation of the original
 * Soviet system with all distinctive audio characteristics.
 * 
 * @warning The system requires proper key management for secure operation.
 * 
 * @since 1.0.0
 * @version 1.0.0
 */
class YachtaT219 {
private:
    /**
     * @struct Config
     * @brief Configuration parameters for Yachta T-219 system
     * 
     * @details
     * This structure contains all the configuration parameters needed
     * to operate the Yachta T-219 voice scrambler system.
     * 
     * @var float sample_rate Audio sample rate in Hz (typically 44100)
     * @var uint32_t channels Number of audio channels (typically 1 for mono)
     * @var float bandwidth Audio bandwidth in Hz (2700 for T-219)
     * @var float audio_response_min Minimum audio frequency in Hz (300 for T-219)
     * @var float audio_response_max Maximum audio frequency in Hz (2700 for T-219)
     * @var uint32_t fsk_baud_rate FSK baud rate (100 for T-219)
     * @var float fsk_shift_frequency FSK frequency shift in Hz (150 for T-219)
     * @var float fsk_center_frequency FSK center frequency in Hz (1000 for T-219)
     * @var uint32_t m_sequence_length M-sequence length in bits (52 for T-219)
     * @var uint64_t polynomial M-sequence polynomial (x^52 + x^49 + 1 for T-219)
     * @var std::vector<uint32_t> time_segments Time segment durations in milliseconds
     * @var std::vector<bool> channel_swap_pattern Channel swapping pattern
     * @var std::vector<bool> channel_inversion_pattern Channel inversion pattern
     * @var float scrambling_factor Scrambling intensity (0.0-1.0)
     * @var bool use_key_card Whether to use key card system
     * @var std::string key_card_data Key card data in hexadecimal format
     */
    struct Config {
        float sample_rate;                    ///< Audio sample rate in Hz
        uint32_t channels;                   ///< Number of audio channels
        float bandwidth;                      ///< Audio bandwidth in Hz
        float audio_response_min;             ///< Minimum audio frequency in Hz
        float audio_response_max;             ///< Maximum audio frequency in Hz
        uint32_t fsk_baud_rate;              ///< FSK baud rate
        float fsk_shift_frequency;           ///< FSK frequency shift in Hz
        float fsk_center_frequency;          ///< FSK center frequency in Hz
        uint32_t m_sequence_length;          ///< M-sequence length in bits
        uint64_t polynomial;                 ///< M-sequence polynomial
        std::vector<uint32_t> time_segments; ///< Time segment durations in ms
        std::vector<bool> channel_swap_pattern;      ///< Channel swapping pattern
        std::vector<bool> channel_inversion_pattern; ///< Channel inversion pattern
        float scrambling_factor;             ///< Scrambling intensity (0.0-1.0)
        bool use_key_card;                   ///< Whether to use key card system
        std::string key_card_data;           ///< Key card data in hex format
    };
    
    Config config_;                          ///< System configuration parameters
    
    // M-sequence generator for FSK sync
    std::vector<bool> m_sequence_;           ///< Generated M-sequence for FSK sync
    size_t m_sequence_index_;                ///< Current position in M-sequence
    
    // Audio processing buffers
    std::vector<float> input_buffer_;        ///< Input audio buffer
    std::vector<float> output_buffer_;       ///< Output audio buffer
    std::vector<std::complex<float>> fft_buffer_; ///< FFT processing buffer
    
    // FSK modulator/demodulator
    std::vector<float> fsk_sync_signal_;     ///< Generated FSK sync signal
    float fsk_phase_;                        ///< Current FSK phase
    float fsk_frequency_;                    ///< Current FSK frequency
    
    // Voice scrambling state
    std::vector<std::vector<float>> time_segments_; ///< Time segment buffers
    uint32_t current_segment_;               ///< Current time segment index
    uint32_t segment_counter_;               ///< Segment processing counter
    
    // Key card system
    std::vector<uint8_t> key_card_bytes_;    ///< Parsed key card data
    size_t key_card_index_;                  ///< Current key card position
    
    // Random number generator for scrambling
    std::mt19937 rng_;                       ///< Random number generator
    std::uniform_real_distribution<float> dist_; ///< Uniform distribution for scrambling
    
    // State flags
    bool initialized_;                     ///< System initialization status
    bool encryption_active_;                 ///< Encryption active status
    bool fsk_sync_active_;                   ///< FSK sync active status
    
    // Audio processing parameters
    uint32_t fft_size_;                      ///< FFT buffer size
    uint32_t hop_size_;                      ///< FFT hop size
    uint32_t window_size_;                   ///< Audio window size
    
    // Frequency response filters
    std::vector<float> lowpass_filter_;      ///< Low-pass filter coefficients
    std::vector<float> highpass_filter_;     ///< High-pass filter coefficients
    std::vector<float> bandpass_filter_;    ///< Band-pass filter coefficients
    
    // FSK processing
    std::vector<float> fsk_filter_;          ///< FSK filter coefficients
    float fsk_previous_sample_;              ///< Previous FSK sample
    float fsk_integration_;                  ///< FSK integration value
    
    // Scrambling processing
    std::vector<float> scrambling_buffer_;   ///< Scrambling processing buffer
    uint32_t scrambling_delay_;              ///< Scrambling delay in samples
    float scrambling_modulation_;             ///< Scrambling modulation value
    
public:
    /**
     * @brief Default constructor
     * 
     * @details
     * Initializes the Yachta T-219 system with default parameters.
     * The system must be initialized with initialize() before use.
     */
    YachtaT219();
    
    /**
     * @brief Virtual destructor
     * 
     * @details
     * Cleans up all resources used by the Yachta T-219 system.
     */
    virtual ~YachtaT219();
    
    // Initialization and configuration
    
    /**
     * @brief Initialize the Yachta T-219 system
     * 
     * @param sample_rate Audio sample rate in Hz (typically 44100)
     * @param channels Number of audio channels (typically 1 for mono)
     * @return true if initialization successful, false otherwise
     * 
     * @details
     * This method initializes the Yachta T-219 system with the specified
     * audio parameters. It sets up all internal buffers, filters, and
     * processing components.
     * 
     * @note The system must be initialized before any other operations.
     * 
     * @see setKey()
     * @see loadKeyCard()
     */
    bool initialize(float sample_rate, uint32_t channels);
    
    /**
     * @brief Set encryption key
     * 
     * @param key_id Key identifier
     * @param key_data Key data string
     * @return true if key set successfully, false otherwise
     * 
     * @details
     * Sets the encryption key for the Yachta T-219 system. The key data
     * is used to modify scrambling parameters and M-sequence generation.
     * 
     * @note The system must be initialized before setting keys.
     * 
     * @see initialize()
     * @see loadKeyCard()
     */
    bool setKey(uint32_t key_id, const std::string& key_data);
    
    /**
     * @brief Load key card data
     * 
     * @param key_card_data Hexadecimal key card data string
     * @return true if key card loaded successfully, false otherwise
     * 
     * @details
     * Loads key card data in hexadecimal format. The key card data
     * is parsed and used to modify scrambling parameters and channel
     * operations.
     * 
     * @note Key card data should be in format "01 23 45 67 89 AB CD EF"
     * 
     * @see setKey()
     * @see initialize()
     */
    bool loadKeyCard(const std::string& key_card_data);
    
    // Audio processing
    
    /**
     * @brief Encrypt audio data
     * 
     * @param input Input audio samples
     * @return Encrypted audio samples
     * 
     * @details
     * Encrypts the input audio using the Yachta T-219 scrambling algorithm.
     * The process includes:
     * - Frequency response filtering (300-2700 Hz)
     * - Upper sideband modulation
     * - Voice scrambling with time segments
     * - FSK sync signal addition
     * - Soviet audio characteristics (warbled, Donald Duck sound)
     * 
     * @note The system must be initialized and have a key set.
     * 
     * @see decrypt()
     * @see initialize()
     * @see setKey()
     */
    std::vector<float> encrypt(const std::vector<float>& input);
    
    /**
     * @brief Decrypt audio data
     * 
     * @param input Encrypted audio samples
     * @return Decrypted audio samples
     * 
     * @details
     * Decrypts the input audio using the Yachta T-219 descrambling algorithm.
     * This is a simplified reversal of the encryption process.
     * 
     * @note The system must be initialized and have the same key as encryption.
     * 
     * @see encrypt()
     * @see initialize()
     * @see setKey()
     */
    std::vector<float> decrypt(const std::vector<float>& input);
    
    // Configuration methods
    void setFSKParameters(uint32_t baud_rate, float shift_freq);
    void setScramblingParameters(const std::vector<uint32_t>& segments, float factor);
    void setAudioResponse(float min_freq, float max_freq);
    void setBandwidth(float bandwidth);
    void setKeyCardData(const std::string& key_card_data);
    
    // Status and diagnostics
    bool isActive() const;
    bool isFSKSyncActive() const;
    bool isKeyCardLoaded() const;
    std::string getEncryptionStatus() const;
    std::string getAudioCharacteristics() const;
    std::vector<float> getFrequencyResponse() const;
    std::vector<bool> getCurrentMSequence() const;
    
    // Test and maintenance functions
    void runSelfTest();
    void calibrateFSK();
    void alignAudioResponse();
    void testKeyCard();
    void generateTestSignal();
    
    // Audio processing utilities
    void applyLowpassFilter(std::vector<float>& audio, float cutoff_freq);
    void applyHighpassFilter(std::vector<float>& audio, float cutoff_freq);
    void applyBandpassFilter(std::vector<float>& audio, float low_freq, float high_freq);
    void applyTimeScrambling(std::vector<float>& audio);
    void applyChannelSwapping(std::vector<float>& audio);
    void applyChannelInversion(std::vector<float>& audio);
    
    // FSK processing
    void generateFSKSignal(const std::vector<bool>& data, std::vector<float>& output);
    void demodulateFSK(const std::vector<float>& input, std::vector<bool>& output);
    void applyFSKFilter(std::vector<float>& audio);
    
    // M-sequence utilities
    void generateMSequence(uint64_t polynomial, uint32_t length);
    bool getNextMSequenceBit();
    void resetMSequence();
    
    // Key card processing
    void processKeyCard();
    uint8_t getNextKeyByte();
    void resetKeyCard();
    
    // Audio characteristic generation
    void generateWarbledEffect(std::vector<float>& audio);
    void generateDonaldDuckSound(std::vector<float>& audio);
    void applySovietAudioCharacteristics(std::vector<float>& audio);
    
private:
    // Internal processing methods
    void initializeFilters();
    void initializeFSK();
    void initializeScrambling();
    void processAudioBlock(std::vector<float>& audio);
    void applySovietCharacteristics(std::vector<float>& audio);
    void updateFSKState();
    void updateScramblingState();
    void processKeyCardData();
    
    // Mathematical utilities
    float sinc(float x);
    float bessel(float x, int order);
    float chebyshev(float x, int order);
    std::complex<float> complexExp(float phase);
    
    // Signal processing utilities
    void applyWindow(std::vector<float>& audio, const std::string& window_type);
    void applyFFT(std::vector<std::complex<float>>& data);
    void applyIFFT(std::vector<std::complex<float>>& data);
    void applyFrequencyShift(std::vector<float>& audio, float shift);
    void applyAmplitudeModulation(std::vector<float>& audio, float modulation);
    
    // Yachta T-219 specific processing
    void applyYachtaScrambling(std::vector<float>& audio);
    void applyT219Characteristics(std::vector<float>& audio);
    void generateSovietWarbledSound(std::vector<float>& audio);
    void applyFSKSyncSignal(std::vector<float>& audio);
    void processTimeSegments(std::vector<float>& audio);
    void processChannelOperations(std::vector<float>& audio);
};

/**
 * @namespace YachtaUtils
 * @brief Utility functions for Yachta T-219 system
 * 
 * @details
 * This namespace contains utility functions for the Yachta T-219 system,
 * including M-sequence generation, FSK signal processing, audio scrambling,
 * and key card management.
 * 
 * @since 1.0.0
 */
namespace YachtaUtils {
    
    /**
     * @brief Generate M-sequence from polynomial
     * 
     * @param polynomial M-sequence polynomial (e.g., x^52 + x^49 + 1)
     * @param length Sequence length in bits
     * @return Generated M-sequence as vector of bools
     * 
     * @details
     * Generates a maximum-length sequence (M-sequence) using the specified
     * polynomial. M-sequences are used for FSK synchronization in the
     * Yachta T-219 system.
     * 
     * @note The polynomial should be primitive for maximum sequence length.
     * 
     * @see https://en.wikipedia.org/wiki/Maximum_length_sequence
     */
    std::vector<bool> generateMSequence(uint64_t polynomial, uint32_t length);
    
    /**
     * @brief Generate FSK signal
     * 
     * @param data Binary data to encode
     * @param sample_rate Audio sample rate in Hz
     * @param baud_rate FSK baud rate
     * @param shift_frequency Frequency shift in Hz
     * @return Generated FSK signal as audio samples
     * 
     * @details
     * Generates a Frequency Shift Keying (FSK) signal from binary data.
     * Used for synchronization in the Yachta T-219 system.
     * 
     * @note Higher frequencies represent '1', lower frequencies represent '0'.
     */
    std::vector<float> generateFSKSignal(const std::vector<bool>& data, 
                                       float sample_rate, 
                                       uint32_t baud_rate, 
                                       float shift_frequency);
    
    /**
     * @brief Apply audio scrambling
     * 
     * @param audio Audio samples to scramble
     * @param segments Time segment durations in milliseconds
     * @param scrambling_factor Scrambling intensity (0.0-1.0)
     * 
     * @details
     * Applies time-based audio scrambling using the specified segments.
     * This simulates the voice scrambling used in the Yachta T-219 system.
     * 
     * @note The scrambling factor controls the intensity of the effect.
     */
    void applyAudioScrambling(std::vector<float>& audio, 
                             const std::vector<uint32_t>& segments,
                             float scrambling_factor);
    
    /**
     * @brief Generate Soviet "warbled" effect
     * 
     * @param audio Audio samples to process
     * @param intensity Effect intensity (0.0-1.0)
     * 
     * @details
     * Applies the distinctive Soviet "warbled" audio effect that was
     * characteristic of the Yachta T-219 system.
     * 
     * @note This creates the classic "warbled" sound that made Soviet
     * radio communications recognizable.
     */
    void generateWarbledEffect(std::vector<float>& audio, float intensity);
    
    /**
     * @brief Generate "Donald Duck" sound
     * 
     * @param audio Audio samples to process
     * @param intensity Effect intensity (0.0-1.0)
     * 
     * @details
     * Applies the distinctive "Donald Duck" audio effect that was
     * characteristic of the Yachta T-219 system.
     * 
     * @note This creates the classic "Donald Duck" sound that made Soviet
     * radio communications recognizable.
     */
    void generateDonaldDuckSound(std::vector<float>& audio, float intensity);
    
    /**
     * @brief Apply frequency response filtering
     * 
     * @param audio Audio samples to filter
     * @param sample_rate Audio sample rate in Hz
     * @param min_freq Minimum frequency in Hz
     * @param max_freq Maximum frequency in Hz
     * 
     * @details
     * Applies bandpass filtering to limit the audio frequency response
     * to the specified range. Used to simulate the 300-2700 Hz response
     * of the Yachta T-219 system.
     */
    void applyFrequencyResponse(std::vector<float>& audio, 
                               float sample_rate,
                               float min_freq, 
                               float max_freq);
    
    /**
     * @brief Apply upper sideband modulation
     * 
     * @param audio Audio samples to modulate
     * @param sample_rate Audio sample rate in Hz
     * 
     * @details
     * Applies upper sideband (USB) modulation to the audio signal.
     * This simulates the modulation used in the Yachta T-219 system.
     */
    void applyUpperSideband(std::vector<float>& audio, float sample_rate);
    
    /**
     * @brief Generate test tone
     * 
     * @param frequency Tone frequency in Hz
     * @param sample_rate Audio sample rate in Hz
     * @param duration Tone duration in seconds
     * @return Generated test tone as audio samples
     * 
     * @details
     * Generates a pure sine wave test tone for testing and calibration.
     */
    std::vector<float> generateTestTone(float frequency, float sample_rate, float duration);
    
    /**
     * @brief Generate noise signal
     * 
     * @param sample_rate Audio sample rate in Hz
     * @param duration Noise duration in seconds
     * @return Generated noise as audio samples
     * 
     * @details
     * Generates white noise for testing and calibration.
     */
    std::vector<float> generateNoise(float sample_rate, float duration);
    
    /**
     * @brief Generate chirp signal
     * 
     * @param start_freq Starting frequency in Hz
     * @param end_freq Ending frequency in Hz
     * @param sample_rate Audio sample rate in Hz
     * @param duration Chirp duration in seconds
     * @return Generated chirp as audio samples
     * 
     * @details
     * Generates a frequency sweep (chirp) signal for testing and calibration.
     */
    std::vector<float> generateChirp(float start_freq, float end_freq, float sample_rate, float duration);
    
    /**
     * @brief Parse key card data
     * 
     * @param key_card_data Hexadecimal key card data string
     * @return Parsed key bytes
     * 
     * @details
     * Parses hexadecimal key card data string into byte array.
     * Expected format: "01 23 45 67 89 AB CD EF"
     * 
     * @note Returns empty vector if parsing fails.
     */
    std::vector<uint8_t> parseKeyCardData(const std::string& key_card_data);
    
    /**
     * @brief Generate key card data
     * 
     * @param key_bytes Key bytes to encode
     * @return Hexadecimal key card data string
     * 
     * @details
     * Converts byte array to hexadecimal key card data string.
     * Output format: "01 23 45 67 89 AB CD EF"
     */
    std::string generateKeyCardData(const std::vector<uint8_t>& key_bytes);
    
    /**
     * @brief Validate key card format
     * 
     * @param key_card_data Key card data string to validate
     * @return true if format is valid, false otherwise
     * 
     * @details
     * Validates that the key card data string is in the correct
     * hexadecimal format with proper spacing.
     * 
     * @note Valid format: "01 23 45 67 89 AB CD EF"
     */
    bool validateKeyCardFormat(const std::string& key_card_data);
}

} // namespace yachta
} // namespace fgcom

#endif // YACHTA_T219_H
