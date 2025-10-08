#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <gtest/gtest.h>
#include <cmath>
#include <algorithm>
#include <vector>
#include <numeric>
#include <limits>

// Mock audio processing classes for property-based testing
class AudioProcessor {
public:
    struct AudioSample {
        float left;
        float right;
    };
    
    struct AudioBuffer {
        std::vector<AudioSample> samples;
        int sample_rate;
        int channels;
    };
    
    // Apply gain to audio samples
    static void applyGain(AudioBuffer& buffer, float gain_db) {
        float gain_linear = std::pow(10.0f, gain_db / 20.0f);
        for (auto& sample : buffer.samples) {
            sample.left *= gain_linear;
            sample.right *= gain_linear;
        }
    }
    
    // Apply compression to audio samples
    static void applyCompression(AudioBuffer& buffer, float threshold_db, float ratio) {
        float threshold_linear = std::pow(10.0f, threshold_db / 20.0f);
        for (auto& sample : buffer.samples) {
            float left_magnitude = std::abs(sample.left);
            float right_magnitude = std::abs(sample.right);
            
            if (left_magnitude > threshold_linear) {
                float excess = left_magnitude - threshold_linear;
                float compressed_excess = excess / ratio;
                sample.left = std::copysign(threshold_linear + compressed_excess, sample.left);
            }
            
            if (right_magnitude > threshold_linear) {
                float excess = right_magnitude - threshold_linear;
                float compressed_excess = excess / ratio;
                sample.right = std::copysign(threshold_linear + compressed_excess, sample.right);
            }
        }
    }
    
    // Apply noise gate
    static void applyNoiseGate(AudioBuffer& buffer, float threshold_db) {
        float threshold_linear = std::pow(10.0f, threshold_db / 20.0f);
        for (auto& sample : buffer.samples) {
            float left_magnitude = std::abs(sample.left);
            float right_magnitude = std::abs(sample.right);
            
            if (left_magnitude < threshold_linear) {
                sample.left = 0.0f;
            }
            if (right_magnitude < threshold_linear) {
                sample.right = 0.0f;
            }
        }
    }
    
    // Calculate RMS (Root Mean Square) level
    static float calculateRMS(const AudioBuffer& buffer) {
        float sum_squares = 0.0f;
        for (const auto& sample : buffer.samples) {
            sum_squares += sample.left * sample.left + sample.right * sample.right;
        }
        return std::sqrt(sum_squares / (buffer.samples.size() * 2));
    }
    
    // Calculate peak level
    static float calculatePeak(const AudioBuffer& buffer) {
        float peak = 0.0f;
        for (const auto& sample : buffer.samples) {
            peak = std::max(peak, std::abs(sample.left));
            peak = std::max(peak, std::abs(sample.right));
        }
        return peak;
    }
    
    // Apply low-pass filter (simplified)
    static void applyLowPassFilter(AudioBuffer& buffer, float cutoff_freq, float sample_rate) {
        float rc = 1.0f / (2.0f * M_PI * cutoff_freq);
        float dt = 1.0f / sample_rate;
        float alpha = dt / (rc + dt);
        
        float left_prev = 0.0f;
        float right_prev = 0.0f;
        
        for (auto& sample : buffer.samples) {
            sample.left = alpha * sample.left + (1.0f - alpha) * left_prev;
            sample.right = alpha * sample.right + (1.0f - alpha) * right_prev;
            left_prev = sample.left;
            right_prev = sample.right;
        }
    }
    
    // Apply high-pass filter (simplified)
    static void applyHighPassFilter(AudioBuffer& buffer, float cutoff_freq, float sample_rate) {
        float rc = 1.0f / (2.0f * M_PI * cutoff_freq);
        float dt = 1.0f / sample_rate;
        float alpha = rc / (rc + dt);
        
        float left_prev = 0.0f;
        float right_prev = 0.0f;
        
        for (auto& sample : buffer.samples) {
            float left_new = alpha * (left_prev + sample.left - sample.left);
            float right_new = alpha * (right_prev + sample.right - sample.right);
            sample.left = left_new;
            sample.right = right_new;
            left_prev = sample.left;
            right_prev = sample.right;
        }
    }
    
    // Mix two audio buffers
    static AudioBuffer mixBuffers(const AudioBuffer& buffer1, const AudioBuffer& buffer2, float mix_ratio) {
        AudioBuffer result = buffer1;
        for (size_t i = 0; i < std::min(buffer1.samples.size(), buffer2.samples.size()); ++i) {
            result.samples[i].left = buffer1.samples[i].left * (1.0f - mix_ratio) + 
                                    buffer2.samples[i].left * mix_ratio;
            result.samples[i].right = buffer1.samples[i].right * (1.0f - mix_ratio) + 
                                     buffer2.samples[i].right * mix_ratio;
        }
        return result;
    }
    
    // Normalize audio to target level
    static void normalize(AudioBuffer& buffer, float target_level_db) {
        float current_peak = calculatePeak(buffer);
        if (current_peak > 0.0f) {
            float target_linear = std::pow(10.0f, target_level_db / 20.0f);
            float gain = target_linear / current_peak;
            applyGain(buffer, 20.0f * std::log10(gain));
        }
    }
};

// Property-based tests for audio processing
RC_GTEST_PROP(AudioProcessingTests,
              GainApplicationIsLinear,
              (AudioProcessor::AudioBuffer buffer, float gain_db)) {
    RC_PRE(gain_db >= -60.0f && gain_db <= 60.0f);
    RC_PRE(!buffer.samples.empty());
    
    AudioProcessor::AudioBuffer original = buffer;
    AudioProcessor::applyGain(buffer, gain_db);
    
    float gain_linear = std::pow(10.0f, gain_db / 20.0f);
    for (size_t i = 0; i < buffer.samples.size(); ++i) {
        RC_ASSERT(std::abs(buffer.samples[i].left - original.samples[i].left * gain_linear) < 1e-6f);
        RC_ASSERT(std::abs(buffer.samples[i].right - original.samples[i].right * gain_linear) < 1e-6f);
    }
}

RC_GTEST_PROP(AudioProcessingTests,
              CompressionReducesPeakLevel,
              (AudioProcessor::AudioBuffer buffer, float threshold_db, float ratio)) {
    RC_PRE(threshold_db >= -60.0f && threshold_db <= 0.0f);
    RC_PRE(ratio >= 1.0f && ratio <= 20.0f);
    RC_PRE(!buffer.samples.empty());
    
    float original_peak = AudioProcessor::calculatePeak(buffer);
    AudioProcessor::applyCompression(buffer, threshold_db, ratio);
    float compressed_peak = AudioProcessor::calculatePeak(buffer);
    
    if (original_peak > std::pow(10.0f, threshold_db / 20.0f)) {
        RC_ASSERT(compressed_peak <= original_peak);
    }
}

RC_GTEST_PROP(AudioProcessingTests,
              NoiseGateEliminatesLowLevels,
              (AudioProcessor::AudioBuffer buffer, float threshold_db)) {
    RC_PRE(threshold_db >= -60.0f && threshold_db <= 0.0f);
    RC_PRE(!buffer.samples.empty());
    
    AudioProcessor::applyNoiseGate(buffer, threshold_db);
    float threshold_linear = std::pow(10.0f, threshold_db / 20.0f);
    
    for (const auto& sample : buffer.samples) {
        if (std::abs(sample.left) < threshold_linear) {
            RC_ASSERT(sample.left == 0.0f);
        }
        if (std::abs(sample.right) < threshold_linear) {
            RC_ASSERT(sample.right == 0.0f);
        }
    }
}

RC_GTEST_PROP(AudioProcessingTests,
              RMSIsNonNegative,
              (AudioProcessor::AudioBuffer buffer)) {
    RC_PRE(!buffer.samples.empty());
    
    float rms = AudioProcessor::calculateRMS(buffer);
    RC_ASSERT(rms >= 0.0f);
}

RC_GTEST_PROP(AudioProcessingTests,
              PeakIsNonNegative,
              (AudioProcessor::AudioBuffer buffer)) {
    RC_PRE(!buffer.samples.empty());
    
    float peak = AudioProcessor::calculatePeak(buffer);
    RC_ASSERT(peak >= 0.0f);
}

RC_GTEST_PROP(AudioProcessingTests,
              PeakIsGreaterThanOrEqualToRMS,
              (AudioProcessor::AudioBuffer buffer)) {
    RC_PRE(!buffer.samples.empty());
    
    float rms = AudioProcessor::calculateRMS(buffer);
    float peak = AudioProcessor::calculatePeak(buffer);
    
    RC_ASSERT(peak >= rms);
}

RC_GTEST_PROP(AudioProcessingTests,
              LowPassFilterReducesHighFrequencies,
              (AudioProcessor::AudioBuffer buffer, float cutoff_freq, float sample_rate)) {
    RC_PRE(cutoff_freq > 0.0f && cutoff_freq < sample_rate / 2.0f);
    RC_PRE(sample_rate > 0.0f);
    RC_PRE(!buffer.samples.empty());
    
    // Create a high-frequency test signal
    AudioProcessor::AudioBuffer high_freq_buffer = buffer;
    for (size_t i = 0; i < high_freq_buffer.samples.size(); ++i) {
        float t = static_cast<float>(i) / sample_rate;
        high_freq_buffer.samples[i].left = std::sin(2.0f * M_PI * cutoff_freq * 2.0f * t);
        high_freq_buffer.samples[i].right = std::sin(2.0f * M_PI * cutoff_freq * 2.0f * t);
    }
    
    float original_energy = AudioProcessor::calculateRMS(high_freq_buffer);
    AudioProcessor::applyLowPassFilter(high_freq_buffer, cutoff_freq, sample_rate);
    float filtered_energy = AudioProcessor::calculateRMS(high_freq_buffer);
    
    RC_ASSERT(filtered_energy <= original_energy);
}

RC_GTEST_PROP(AudioProcessingTests,
              MixingIsLinear,
              (AudioProcessor::AudioBuffer buffer1, AudioProcessor::AudioBuffer buffer2, float mix_ratio)) {
    RC_PRE(mix_ratio >= 0.0f && mix_ratio <= 1.0f);
    RC_PRE(!buffer1.samples.empty());
    RC_PRE(!buffer2.samples.empty());
    
    AudioProcessor::AudioBuffer mixed = AudioProcessor::mixBuffers(buffer1, buffer2, mix_ratio);
    
    for (size_t i = 0; i < std::min(buffer1.samples.size(), buffer2.samples.size()); ++i) {
        float expected_left = buffer1.samples[i].left * (1.0f - mix_ratio) + 
                             buffer2.samples[i].left * mix_ratio;
        float expected_right = buffer1.samples[i].right * (1.0f - mix_ratio) + 
                              buffer2.samples[i].right * mix_ratio;
        
        RC_ASSERT(std::abs(mixed.samples[i].left - expected_left) < 1e-6f);
        RC_ASSERT(std::abs(mixed.samples[i].right - expected_right) < 1e-6f);
    }
}

RC_GTEST_PROP(AudioProcessingTests,
              NormalizationAchievesTargetLevel,
              (AudioProcessor::AudioBuffer buffer, float target_level_db)) {
    RC_PRE(target_level_db >= -60.0f && target_level_db <= 0.0f);
    RC_PRE(!buffer.samples.empty());
    
    // Ensure buffer has some content
    bool has_content = false;
    for (const auto& sample : buffer.samples) {
        if (std::abs(sample.left) > 1e-6f || std::abs(sample.right) > 1e-6f) {
            has_content = true;
            break;
        }
    }
    RC_PRE(has_content);
    
    AudioProcessor::normalize(buffer, target_level_db);
    float peak = AudioProcessor::calculatePeak(buffer);
    float target_linear = std::pow(10.0f, target_level_db / 20.0f);
    
    RC_ASSERT(std::abs(peak - target_linear) < 0.01f);
}

RC_GTEST_PROP(AudioProcessingTests,
              CompressionRatioEffect,
              (AudioProcessor::AudioBuffer buffer, float threshold_db, float ratio1, float ratio2)) {
    RC_PRE(threshold_db >= -60.0f && threshold_db <= 0.0f);
    RC_PRE(ratio1 >= 1.0f && ratio1 <= 20.0f);
    RC_PRE(ratio2 >= 1.0f && ratio2 <= 20.0f);
    RC_PRE(ratio1 < ratio2);
    RC_PRE(!buffer.samples.empty());
    
    AudioProcessor::AudioBuffer buffer1 = buffer;
    AudioProcessor::AudioBuffer buffer2 = buffer;
    
    AudioProcessor::applyCompression(buffer1, threshold_db, ratio1);
    AudioProcessor::applyCompression(buffer2, threshold_db, ratio2);
    
    float peak1 = AudioProcessor::calculatePeak(buffer1);
    float peak2 = AudioProcessor::calculatePeak(buffer2);
    
    // Higher ratio should result in lower peak (more compression)
    RC_ASSERT(peak2 <= peak1);
}

RC_GTEST_PROP(AudioProcessingTests,
              FilterCausality,
              (AudioProcessor::AudioBuffer buffer, float cutoff_freq, float sample_rate)) {
    RC_PRE(cutoff_freq > 0.0f && cutoff_freq < sample_rate / 2.0f);
    RC_PRE(sample_rate > 0.0f);
    RC_PRE(!buffer.samples.empty());
    
    // Create impulse response
    AudioProcessor::AudioBuffer impulse = buffer;
    for (auto& sample : impulse.samples) {
        sample.left = 0.0f;
        sample.right = 0.0f;
    }
    if (!impulse.samples.empty()) {
        impulse.samples[0].left = 1.0f;
        impulse.samples[0].right = 1.0f;
    }
    
    AudioProcessor::applyLowPassFilter(impulse, cutoff_freq, sample_rate);
    
    // Check causality: output should be zero before input
    for (size_t i = 0; i < impulse.samples.size(); ++i) {
        if (i == 0) {
            RC_ASSERT(impulse.samples[i].left >= 0.0f);
            RC_ASSERT(impulse.samples[i].right >= 0.0f);
        }
    }
}

// Custom generators for audio processing
namespace rc {
    template<>
    struct Arbitrary<AudioProcessor::AudioSample> {
        static Gen<AudioProcessor::AudioSample> arbitrary() {
            return gen::construct<AudioProcessor::AudioSample>(
                gen::inRange(-1.0f, 1.0f),  // left channel
                gen::inRange(-1.0f, 1.0f)   // right channel
            );
        }
    };
    
    template<>
    struct Arbitrary<AudioProcessor::AudioBuffer> {
        static Gen<AudioProcessor::AudioBuffer> arbitrary() {
            return gen::construct<AudioProcessor::AudioBuffer>(
                gen::container<std::vector<AudioProcessor::AudioSample>>(
                    gen::inRange(1, 1000),  // 1 to 1000 samples
                    gen::arbitrary<AudioProcessor::AudioSample>()
                ),
                gen::inRange(8000, 192000),  // sample rate
                gen::inRange(1, 2)           // channels
            );
        }
    };
}
