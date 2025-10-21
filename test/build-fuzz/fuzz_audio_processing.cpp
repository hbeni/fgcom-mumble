#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>

// Include FGCom-mumble audio processing headers
#include "../../client/mumble-plugin/lib/audio_professional.h"
#include "../../client/mumble-plugin/lib/audio.h"
#include "../../client/mumble-plugin/lib/bfo_simulation.h"

// Fuzzing target for audio processing functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Need minimum data
    
    // Systematically consume input bytes
    size_t offset = 0;
    
    // Extract audio processing parameters
    uint32_t sample_rate = 44100;
    uint32_t sample_count = 1024;
    float frequency = 1000.0f;
    float amplitude = 0.5f;
    
    if (offset + 4 <= Size) {
        std::memcpy(&sample_rate, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&sample_count, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&frequency, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&amplitude, Data + offset, 4);
        offset += 4;
    }
    
    // Limit sample count to reasonable size
    sample_count = std::min(sample_count, static_cast<uint32_t>(4096));
    if (sample_count == 0) sample_count = 1024;
    
    try {
        // Generate audio samples from input data
        std::vector<float> audio_samples(sample_count);
        for (size_t i = 0; i < sample_count && offset + 4 <= Size; ++i) {
            std::memcpy(&audio_samples[i], Data + offset, 4);
            offset += 4;
        }
        
        // Fill remaining samples with generated data if needed
        for (size_t i = offset / 4; i < sample_count; ++i) {
            float t = static_cast<float>(i) / static_cast<float>(sample_rate);
            audio_samples[i] = amplitude * std::sin(2.0f * M_PI * frequency * t);
        }
        
        // Test IIR1 filter
        FGComAudio::IIR1Filter filter;
        filter.setLowPass(3000.0f, static_cast<float>(sample_rate));
        
        std::vector<float> filtered_samples = audio_samples;
        for (auto& sample : filtered_samples) {
            sample = filter.process(sample);
        }
        
        // Test different filter types
        filter.setHighPass(300.0f, static_cast<float>(sample_rate));
        for (auto& sample : filtered_samples) {
            sample = filter.process(sample);
        }
        
        filter.setBandPass(300.0f, 3000.0f, static_cast<float>(sample_rate));
        for (auto& sample : filtered_samples) {
            sample = filter.process(sample);
        }
        
        // Test BiquadFilter
        FGComAudio::BiquadFilter biquad;
        biquad.setLowPass(3000.0f, static_cast<float>(sample_rate), 0.707f);
        
        std::vector<float> biquad_filtered = audio_samples;
        for (auto& sample : biquad_filtered) {
            sample = biquad.process(sample);
        }
        
        biquad.setHighPass(300.0f, static_cast<float>(sample_rate), 0.707f);
        for (auto& sample : biquad_filtered) {
            sample = biquad.process(sample);
        }
        
        biquad.setBandPass(300.0f, 3000.0f, static_cast<float>(sample_rate), 0.707f);
        for (auto& sample : biquad_filtered) {
            sample = biquad.process(sample);
        }
        
        biquad.setNotch(1000.0f, static_cast<float>(sample_rate), 10.0f);
        for (auto& sample : biquad_filtered) {
            sample = biquad.process(sample);
        }
        
        // Test ProfessionalAudioEngine
        FGComAudio::ProfessionalAudioEngine engine;
        engine.setSampleRate(static_cast<float>(sample_rate));
        engine.setGain(amplitude);
        
        std::vector<float> processed_samples = audio_samples;
        engine.processAudio(processed_samples);
        
        // Test with different gain values
        engine.setGain(amplitude * 2.0f);
        engine.processAudio(processed_samples);
        
        engine.setGain(amplitude * 0.1f);
        engine.processAudio(processed_samples);
        
        // Test with extreme gain values
        engine.setGain(100.0f);
        engine.processAudio(processed_samples);
        
        engine.setGain(0.001f);
        engine.processAudio(processed_samples);
        
        // Test with negative gain
        engine.setGain(-1.0f);
        engine.processAudio(processed_samples);
        
        // Test audio effects
        engine.enableEcho(true);
        engine.setEchoDelay(0.1f);
        engine.setEchoDecay(0.5f);
        engine.processAudio(processed_samples);
        
        engine.enableReverb(true);
        engine.setReverbRoomSize(0.8f);
        engine.setReverbDamping(0.5f);
        engine.processAudio(processed_samples);
        
        engine.enableDistortion(true);
        engine.setDistortionAmount(0.5f);
        engine.processAudio(processed_samples);
        
        // Test with NaN and infinity values
        if (sample_count > 0) {
            audio_samples[0] = std::numeric_limits<float>::quiet_NaN();
            engine.processAudio(audio_samples);
            
            audio_samples[0] = std::numeric_limits<float>::infinity();
            engine.processAudio(audio_samples);
            
            audio_samples[0] = -std::numeric_limits<float>::infinity();
            engine.processAudio(audio_samples);
        }
        
        // Test with clipped samples
        for (auto& sample : audio_samples) {
            sample = (sample > 1.0f) ? 1.0f : (sample < -1.0f) ? -1.0f : sample;
        }
        engine.processAudio(audio_samples);
        
        // Test with very small samples
        for (auto& sample : audio_samples) {
            sample *= 0.0001f;
        }
        engine.processAudio(audio_samples);
        
        // Test with very large samples
        for (auto& sample : audio_samples) {
            sample *= 1000.0f;
        }
        engine.processAudio(audio_samples);
        
        // Test empty audio buffer
        std::vector<float> empty_buffer;
        engine.processAudio(empty_buffer);
        
        // Test single sample
        std::vector<float> single_sample = {0.5f};
        engine.processAudio(single_sample);
        
        // Test with different sample rates
        engine.setSampleRate(8000.0f);
        engine.processAudio(audio_samples);
        
        engine.setSampleRate(48000.0f);
        engine.processAudio(audio_samples);
        
        engine.setSampleRate(96000.0f);
        engine.processAudio(audio_samples);
        
        // Test with invalid sample rates
        engine.setSampleRate(0.0f);
        engine.processAudio(audio_samples);
        
        engine.setSampleRate(-44100.0f);
        engine.processAudio(audio_samples);
        
        // Test filter reset
        filter.reset();
        biquad.reset();
        
        // Test with extreme frequency values
        filter.setLowPass(0.1f, static_cast<float>(sample_rate));
        for (auto& sample : audio_samples) {
            sample = filter.process(sample);
        }
        
        filter.setLowPass(20000.0f, static_cast<float>(sample_rate));
        for (auto& sample : audio_samples) {
            sample = filter.process(sample);
        }
        
        // Test with extreme Q values
        biquad.setLowPass(1000.0f, static_cast<float>(sample_rate), 0.01f);
        for (auto& sample : audio_samples) {
            sample = biquad.process(sample);
        }
        
        biquad.setLowPass(1000.0f, static_cast<float>(sample_rate), 100.0f);
        for (auto& sample : audio_samples) {
            sample = biquad.process(sample);
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        // Fuzzing should continue even if exceptions occur
        return 0;
    } catch (...) {
        // Handle any other exceptions
        return 0;
    }
}
