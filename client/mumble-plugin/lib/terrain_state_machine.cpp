#include "terrain_state_machine.h"
#include "terrain_exceptions.h"
#include <stdexcept>

namespace FGCom_TerrainEnvironmental {

    // TerrainStateMachine implementation
    TerrainStateMachine::TerrainStateMachine()
        : current_state_(TerrainProviderState::UNINITIALIZED),
          last_error_message_(""),
          state_change_time_(std::chrono::steady_clock::now()) {
    }

    TerrainProviderState TerrainStateMachine::getCurrentState() const noexcept {
        return current_state_.load();
    }

    bool TerrainStateMachine::transitionToInitializing() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TerrainProviderState current = current_state_.load();
        
        if (current != TerrainProviderState::UNINITIALIZED) {
            return false;
        }
        
        current_state_ = TerrainProviderState::INITIALIZING;
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::transitionToReady() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TerrainProviderState current = current_state_.load();
        
        if (current != TerrainProviderState::INITIALIZING) {
            return false;
        }
        
        current_state_ = TerrainProviderState::READY;
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::transitionToError(const std::string& errorMessage) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TerrainProviderState current = current_state_.load();
        
        if (current == TerrainProviderState::SHUTDOWN || 
            current == TerrainProviderState::SHUTDOWN_COMPLETE) {
            return false;
        }
        
        last_error_message_ = errorMessage;
        current_state_ = TerrainProviderState::ERROR;
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::transitionToShutdown() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TerrainProviderState current = current_state_.load();
        
        if (current == TerrainProviderState::SHUTDOWN_COMPLETE) {
            return false;
        }
        
        current_state_ = TerrainProviderState::SHUTDOWN;
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::transitionToShutdownComplete() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TerrainProviderState current = current_state_.load();
        
        if (current != TerrainProviderState::SHUTDOWN) {
            return false;
        }
        
        current_state_ = TerrainProviderState::SHUTDOWN_COMPLETE;
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::canPerformOperations() const noexcept {
        return current_state_.load() == TerrainProviderState::READY;
    }

    std::string TerrainStateMachine::getStateName() const {
        TerrainProviderState state = current_state_.load();
        switch (state) {
            case TerrainProviderState::UNINITIALIZED:
                return "UNINITIALIZED";
            case TerrainProviderState::INITIALIZING:
                return "INITIALIZING";
            case TerrainProviderState::READY:
                return "READY";
            case TerrainProviderState::ERROR:
                return "ERROR";
            case TerrainProviderState::SHUTDOWN:
                return "SHUTDOWN";
            case TerrainProviderState::SHUTDOWN_COMPLETE:
                return "SHUTDOWN_COMPLETE";
            default:
                return "UNKNOWN";
        }
    }

    std::string TerrainStateMachine::getLastErrorMessage() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return last_error_message_;
    }

    std::chrono::milliseconds TerrainStateMachine::getTimeInCurrentState() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - state_change_time_);
        return duration;
    }

    bool TerrainStateMachine::reset() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        current_state_ = TerrainProviderState::UNINITIALIZED;
        last_error_message_ = "";
        updateStateChangeTime();
        return true;
    }

    bool TerrainStateMachine::isValidTransition(TerrainProviderState from, TerrainProviderState to) const noexcept {
        switch (from) {
            case TerrainProviderState::UNINITIALIZED:
                return to == TerrainProviderState::INITIALIZING;
            case TerrainProviderState::INITIALIZING:
                return to == TerrainProviderState::READY || to == TerrainProviderState::ERROR;
            case TerrainProviderState::READY:
                return to == TerrainProviderState::SHUTDOWN || to == TerrainProviderState::ERROR;
            case TerrainProviderState::ERROR:
                return to == TerrainProviderState::SHUTDOWN || to == TerrainProviderState::UNINITIALIZED;
            case TerrainProviderState::SHUTDOWN:
                return to == TerrainProviderState::SHUTDOWN_COMPLETE;
            case TerrainProviderState::SHUTDOWN_COMPLETE:
                return false; // Terminal state
            default:
                return false;
        }
    }

    void TerrainStateMachine::updateStateChangeTime() {
        state_change_time_ = std::chrono::steady_clock::now();
    }

    // TerrainStateGuard implementation
    TerrainStateGuard::TerrainStateGuard(TerrainStateMachine& stateMachine)
        : state_machine_(stateMachine), valid_(false) {
        // Attempt to transition to initializing state
        if (state_machine_.transitionToInitializing()) {
            valid_ = true;
        }
    }

    TerrainStateGuard::~TerrainStateGuard() {
        if (valid_) {
            // Transition to shutdown when guard is destroyed
            state_machine_.transitionToShutdown();
        }
    }

    bool TerrainStateGuard::isValid() const noexcept {
        return valid_;
    }

} // namespace FGCom_TerrainEnvironmental
