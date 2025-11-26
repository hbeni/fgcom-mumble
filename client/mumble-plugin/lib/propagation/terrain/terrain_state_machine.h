#ifndef TERRAIN_STATE_MACHINE_H
#define TERRAIN_STATE_MACHINE_H

#include <atomic>
#include <mutex>
#include <string>
#include <chrono>

namespace FGCom_TerrainEnvironmental {

    /**
     * @brief Thread-safe state machine for terrain operations
     * 
     * Provides predictable state management with defined transitions
     * and atomic state changes to prevent race conditions.
     */
    enum class TerrainProviderState {
        UNINITIALIZED,    // Initial state
        INITIALIZING,     // Starting up
        READY,           // Ready for operations
        ERROR,           // Error state
        SHUTDOWN,        // Shutting down
        SHUTDOWN_COMPLETE // Shutdown complete
    };

    /**
     * @brief State machine for terrain data provider
     * 
     * Ensures predictable state transitions and prevents race conditions.
     * All state changes are atomic and thread-safe.
     */
    class TerrainStateMachine {
    public:
        TerrainStateMachine();
        ~TerrainStateMachine() = default;

        // Non-copyable, non-movable
        TerrainStateMachine(const TerrainStateMachine&) = delete;
        TerrainStateMachine& operator=(const TerrainStateMachine&) = delete;
        TerrainStateMachine(TerrainStateMachine&&) = delete;
        TerrainStateMachine& operator=(TerrainStateMachine&&) = delete;

        /**
         * @brief Get current state
         * 
         * @return TerrainProviderState Current state
         */
        TerrainProviderState getCurrentState() const noexcept;

        /**
         * @brief Transition to initializing state
         * 
         * @return bool True if transition successful
         */
        bool transitionToInitializing();

        /**
         * @brief Transition to ready state
         * 
         * @return bool True if transition successful
         */
        bool transitionToReady();

        /**
         * @brief Transition to error state
         * 
         * @param errorMessage Error message for logging
         * @return bool True if transition successful
         */
        bool transitionToError(const std::string& errorMessage);

        /**
         * @brief Transition to shutdown state
         * 
         * @return bool True if transition successful
         */
        bool transitionToShutdown();

        /**
         * @brief Transition to shutdown complete state
         * 
         * @return bool True if transition successful
         */
        bool transitionToShutdownComplete();

        /**
         * @brief Check if state allows operations
         * 
         * @return bool True if operations are allowed
         */
        bool canPerformOperations() const noexcept;

        /**
         * @brief Get state name as string
         * 
         * @return std::string State name
         */
        std::string getStateName() const;

        /**
         * @brief Get last error message
         * 
         * @return std::string Last error message
         */
        std::string getLastErrorMessage() const;

        /**
         * @brief Get time in current state
         * 
         * @return std::chrono::milliseconds Time in current state
         */
        std::chrono::milliseconds getTimeInCurrentState() const;

        /**
         * @brief Reset state machine to uninitialized
         * 
         * @return bool True if reset successful
         */
        bool reset();

    private:
        mutable std::mutex state_mutex_;
        std::atomic<TerrainProviderState> current_state_;
        std::string last_error_message_;
        std::chrono::steady_clock::time_point state_change_time_;

        /**
         * @brief Validate state transition
         * 
         * @param from Current state
         * @param to Target state
         * @return bool True if transition is valid
         */
        bool isValidTransition(TerrainProviderState from, TerrainProviderState to) const noexcept;

        /**
         * @brief Update state change timestamp
         */
        void updateStateChangeTime();
    };

    /**
     * @brief State machine guard for RAII state management
     * 
     * Automatically manages state transitions using RAII principles.
     */
    class TerrainStateGuard {
    public:
        explicit TerrainStateGuard(TerrainStateMachine& stateMachine);
        ~TerrainStateGuard();

        // Non-copyable, non-movable
        TerrainStateGuard(const TerrainStateGuard&) = delete;
        TerrainStateGuard& operator=(const TerrainStateGuard&) = delete;
        TerrainStateGuard(TerrainStateGuard&&) = delete;
        TerrainStateGuard& operator=(TerrainStateGuard&&) = delete;

        /**
         * @brief Check if guard is valid
         * 
         * @return bool True if guard is valid
         */
        bool isValid() const noexcept;

    private:
        TerrainStateMachine& state_machine_;
        bool valid_;
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_STATE_MACHINE_H
