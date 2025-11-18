#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <limits>

// Include FGCom audio processing headers
// #include "../../client/mumble-plugin/lib/audio_professional.h"
// #include "../../client/mumble-plugin/lib/agc_squelch.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    FuzzedDataProvider fdp(Data, Size);
    
    try {
        // Timeout protection
        auto start = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(20);
        
        // Extract audio processing parameters
        int sample_rate = fdp.ConsumeIntegralInRange<int>(8000, 48000);
        size_t audio_size = fdp.ConsumeIntegralInRange<size_t>(128, 4096);
        float squelch_threshold = fdp.ConsumeFloatingPointInRange<float>(-100.0f, 0.0f);
        float agc_gain = fdp.ConsumeFloatingPointInRange<float>(0.0f, 100.0f);
        float agc_attack = fdp.ConsumeFloatingPointInRange<float>(0.1f, 1000.0f);
        float agc_release = fdp.ConsumeFloatingPointInRange<float>(1.0f, 5000.0f);
        
        // Generate audio buffer
        std::vector<int16_t> audio_buffer(audio_size);
        for (size_t i = 0; i < audio_size && fdp.remaining_bytes() >= 2; i++) {
            audio_buffer[i] = fdp.ConsumeIntegral<int16_t>();
        }
        
        // Fill remaining samples with generated data
        for (size_t i = audio_buffer.size(); i < audio_size; ++i) {
            float t = static_cast<float>(i) / static_cast<float>(sample_rate);
            audio_buffer[i] = static_cast<int16_t>(32767.0f * 0.5f * std::sin(2.0f * M_PI * 1000.0f * t));
        }
        
        // Test AGC (Automatic Gain Control)
        float current_gain = 1.0f;
        for (size_t i = 0; i < audio_buffer.size(); ++i) {
            float sample = static_cast<float>(audio_buffer[i]) / 32767.0f;
            float target_level = 0.5f;
            
            // Simple AGC algorithm
            if (std::abs(sample) > target_level) {
                current_gain *= 0.99f; // Reduce gain
            } else if (std::abs(sample) < target_level * 0.1f) {
                current_gain *= 1.01f; // Increase gain
            }
            
            // Clamp gain
            current_gain = std::max(0.1f, std::min(current_gain, 10.0f));
            
            // Apply gain
            sample *= current_gain;
            audio_buffer[i] = static_cast<int16_t>(sample * 32767.0f);
        }
        
        // Test squelch detection
        float avg_power = 0.0f;
        for (int16_t sample : audio_buffer) {
            float normalized = static_cast<float>(sample) / 32767.0f;
            avg_power += normalized * normalized;
        }
        avg_power = std::sqrt(avg_power / audio_buffer.size());
        
        bool squelch_open = avg_power > std::pow(10.0f, squelch_threshold / 20.0f);
        
        // Test CTCSS (Continuous Tone-Coded Squelch System)
        float ctcss_freq = fdp.ConsumeFloatingPointInRange<float>(67.0f, 254.1f);
        bool ctcss_detected = false;
        
        // Simple CTCSS detection (tone detection)
        float tone_amplitude = 0.0f;
        for (size_t i = 0; i < audio_buffer.size(); ++i) {
            float t = static_cast<float>(i) / static_cast<float>(sample_rate);
            float expected_tone = 0.1f * std::sin(2.0f * M_PI * ctcss_freq * t);
            float actual_sample = static_cast<float>(audio_buffer[i]) / 32767.0f;
            tone_amplitude += expected_tone * actual_sample;
        }
        tone_amplitude /= audio_buffer.size();
        ctcss_detected = tone_amplitude > 0.1f;
        
        // Test audio filtering (simple low-pass filter)
        float cutoff_freq = fdp.ConsumeFloatingPointInRange<float>(100.0f, 8000.0f);
        float rc = 1.0f / (2.0f * M_PI * cutoff_freq);
        float dt = 1.0f / static_cast<float>(sample_rate);
        float alpha = dt / (rc + dt);
        
        float filtered_sample = 0.0f;
        for (size_t i = 0; i < audio_buffer.size(); ++i) {
            float sample = static_cast<float>(audio_buffer[i]) / 32767.0f;
            filtered_sample = alpha * sample + (1.0f - alpha) * filtered_sample;
            audio_buffer[i] = static_cast<int16_t>(filtered_sample * 32767.0f);
        }
        
        // Test noise floor calculation
        float noise_floor = 0.0f;
        for (int16_t sample : audio_buffer) {
            float normalized = static_cast<float>(sample) / 32767.0f;
            noise_floor += normalized * normalized;
        }
        noise_floor = 10.0f * std::log10(noise_floor / audio_buffer.size() + 1e-10f);
        
        // Test audio compression
        float compression_ratio = fdp.ConsumeFloatingPointInRange<float>(1.0f, 10.0f);
        float compression_threshold = fdp.ConsumeFloatingPointInRange<float>(-20.0f, 0.0f);
        
        for (size_t i = 0; i < audio_buffer.size(); ++i) {
            float sample = static_cast<float>(audio_buffer[i]) / 32767.0f;
            float db_sample = 20.0f * std::log10(std::abs(sample) + 1e-10f);
            
            if (db_sample > compression_threshold) {
                float excess = db_sample - compression_threshold;
                float compressed_excess = excess / compression_ratio;
                float new_db = compression_threshold + compressed_excess;
                sample = std::copysign(std::pow(10.0f, new_db / 20.0f), sample);
            }
            
            audio_buffer[i] = static_cast<int16_t>(sample * 32767.0f);
        }
        
        // Test edge cases
        if (sample_rate <= 0) return 0;
        if (audio_size == 0) return 0;
        if (std::isnan(avg_power) || std::isinf(avg_power)) return 0;
        if (std::isnan(noise_floor) || std::isinf(noise_floor)) return 0;
        
        // Timeout check
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            return 0;
        }
        
    } catch (const std::exception& e) {
        return 0;
    } catch (...) {
        return 0;
    }
    
    return 0;
}
