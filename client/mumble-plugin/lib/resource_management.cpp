#include "resource_management.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

// ThreadRAII Implementation
ThreadRAII::ThreadRAII(std::function<void()> thread_function, std::function<void()> cleanup)
    : should_stop_(false), cleanup_function_(cleanup) {
    if (thread_function) {
        thread_ = std::thread([thread_function]() {
            try {
                thread_function();
            } catch (const std::exception& e) {
                std::cerr << "[ThreadRAII] Exception in thread: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "[ThreadRAII] Unknown exception in thread" << std::endl;
            }
        });
    }
}

/**
 * ThreadRAII Destructor - Ensures proper thread cleanup
 * 
 * This destructor implements the RAII (Resource Acquisition Is Initialization)
 * pattern for thread management. It ensures that threads are properly
 * terminated and resources are cleaned up even if exceptions occur.
 * 
 * Thread Cleanup Process:
 * 1. Signal thread to stop via should_stop_ flag
 * 2. Wait for thread to complete via join() (blocks until thread finishes)
 * 3. Execute custom cleanup function if provided
 * 4. Handle any exceptions during cleanup gracefully
 * 
 * Thread Safety Notes:
 * - join() is called only if thread is joinable (not already joined/detached)
 * - Cleanup function is executed in the destructor thread context
 * - Exceptions in cleanup are caught and logged, preventing termination
 * 
 * Critical: This destructor must not throw exceptions to maintain
 * RAII guarantees and prevent undefined behavior.
 */
ThreadRAII::~ThreadRAII() {
    // Signal thread to stop gracefully
    stop();
    
    // Wait for thread to complete execution
    // join() blocks until the thread function returns
    if (thread_.joinable()) {
        thread_.join();
    }
    
    // Execute custom cleanup function if provided
    // This allows for thread-specific resource cleanup
    if (cleanup_function_) {
        try {
            cleanup_function_();
        } catch (const std::exception& e) {
            std::cerr << "[ThreadRAII] Exception in cleanup: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[ThreadRAII] Unknown exception in cleanup" << std::endl;
        }
    }
}

/**
 * ThreadRAII Move Constructor
 * 
 * Transfers ownership of thread resources from another ThreadRAII object.
 * This is essential for efficient thread management in containers and
 * when passing thread objects between functions.
 * 
 * Move Semantics:
 * - Transfers thread ownership without copying (threads cannot be copied)
 * - Transfers atomic stop flag state
 * - Transfers cleanup function ownership
 * - Leaves source object in valid but empty state
 * 
 * Thread Safety:
 * - Atomic load of should_stop_ flag ensures thread-safe state transfer
 * - Source object's stop flag is reset to prevent accidental termination
 * - No thread operations are performed during move (thread continues running)
 */
ThreadRAII::ThreadRAII(ThreadRAII&& other) noexcept
    : thread_(std::move(other.thread_)), should_stop_(other.should_stop_.load()),
      cleanup_function_(std::move(other.cleanup_function_)) {
    other.should_stop_ = false;
}

/**
 * ThreadRAII Move Assignment Operator
 * 
 * Transfers ownership of thread resources from another ThreadRAII object.
 * This operator ensures proper cleanup of existing resources before
 * transferring new ones.
 * 
 * Resource Management:
 * 1. Stop current thread gracefully
 * 2. Wait for current thread to complete (join)
 * 3. Transfer new thread ownership
 * 4. Transfer stop flag and cleanup function
 * 5. Reset source object to safe state
 * 
 * Thread Safety:
 * - Self-assignment is handled to prevent undefined behavior
 * - Current thread is properly terminated before transfer
 * - Atomic operations ensure thread-safe state transfer
 * - Exception safety is guaranteed (noexcept)
 */
ThreadRAII& ThreadRAII::operator=(ThreadRAII&& other) noexcept {
    if (this != &other) {
        // Stop current thread gracefully
        stop();
        if (thread_.joinable()) {
            thread_.join();
        }
        
        // Transfer new thread resources
        thread_ = std::move(other.thread_);
        should_stop_ = other.should_stop_.load();
        cleanup_function_ = std::move(other.cleanup_function_);
        
        // Reset source object to safe state
        other.should_stop_ = false;
    }
    return *this;
}

void ThreadRAII::stop() {
    should_stop_ = true;
}

void ThreadRAII::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

bool ThreadRAII::joinable() const {
    return thread_.joinable();
}

std::thread::id ThreadRAII::get_id() const {
    return thread_.get_id();
}

bool ThreadRAII::shouldStop() const {
    return should_stop_.load();
}

// MutexRAII Implementation
MutexRAII::MutexRAII(std::mutex& mutex) : mutex_(mutex), locked_(false) {
    lock();
}

MutexRAII::~MutexRAII() {
    if (locked_) {
        unlock();
    }
}

void MutexRAII::lock() {
    if (!locked_) {
        mutex_.lock();
        locked_ = true;
    }
}

void MutexRAII::unlock() {
    if (locked_) {
        mutex_.unlock();
        locked_ = false;
    }
}

bool MutexRAII::try_lock() {
    if (!locked_) {
        locked_ = mutex_.try_lock();
    }
    return locked_;
}

bool MutexRAII::owns_lock() const {
    return locked_;
}

// SharedMutexRAII Implementation
SharedMutexRAII::SharedMutexRAII(std::shared_mutex& mutex, bool shared)
    : mutex_(mutex), locked_(false), is_shared_(shared) {
    lock();
}

SharedMutexRAII::~SharedMutexRAII() {
    if (locked_) {
        unlock();
    }
}

void SharedMutexRAII::lock() {
    if (!locked_) {
        if (is_shared_) {
            mutex_.lock_shared();
        } else {
            mutex_.lock();
        }
        locked_ = true;
    }
}

void SharedMutexRAII::unlock() {
    if (locked_) {
        if (is_shared_) {
            mutex_.unlock_shared();
        } else {
            mutex_.unlock();
        }
        locked_ = false;
    }
}

bool SharedMutexRAII::try_lock() {
    if (!locked_) {
        if (is_shared_) {
            locked_ = mutex_.try_lock_shared();
        } else {
            locked_ = mutex_.try_lock();
        }
    }
    return locked_;
}

bool SharedMutexRAII::owns_lock() const {
    return locked_;
}

// ResourcePool Implementation
template<typename T>
ResourcePool<T>::ResourcePool(size_t max_size, std::function<std::unique_ptr<T>()> factory)
    : factory_function_(factory), max_pool_size_(max_size), current_pool_size_(0) {
}

template<typename T>
ResourcePool<T>::~ResourcePool() {
    clear();
}

template<typename T>
ResourcePool<T>::ResourcePool(ResourcePool&& other) noexcept
    : available_resources_(std::move(other.available_resources_)),
      in_use_resources_(std::move(other.in_use_resources_)),
      factory_function_(std::move(other.factory_function_)),
      max_pool_size_(other.max_pool_size_),
      current_pool_size_(other.current_pool_size_.load()) {
    other.current_pool_size_ = 0;
}

template<typename T>
ResourcePool<T>& ResourcePool<T>::operator=(ResourcePool&& other) noexcept {
    if (this != &other) {
        clear();
        
        available_resources_ = std::move(other.available_resources_);
        in_use_resources_ = std::move(other.in_use_resources_);
        factory_function_ = std::move(other.factory_function_);
        max_pool_size_ = other.max_pool_size_;
        current_pool_size_ = other.current_pool_size_.load();
        
        other.current_pool_size_ = 0;
    }
    return *this;
}

template<typename T>
std::unique_ptr<T> ResourcePool<T>::acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    
    // Wait for available resource or timeout
    if (!resource_available_.wait_for(lock, timeout, [this]() {
        return !available_resources_.empty() || current_pool_size_ < max_pool_size_;
    })) {
        return nullptr; // Timeout
    }
    
    std::unique_ptr<T> resource;
    
    if (!available_resources_.empty()) {
        // Use existing resource
        resource = std::move(available_resources_.back());
        available_resources_.pop_back();
    } else if (current_pool_size_ < max_pool_size_ && factory_function_) {
        // Create new resource
        resource = factory_function_();
        current_pool_size_++;
    }
    
    if (resource) {
        in_use_resources_.push_back(std::move(resource));
        return in_use_resources_.back(); // Remove std::move to allow RVO
    }
    
    return nullptr;
}

template<typename T>
void ResourcePool<T>::release(std::unique_ptr<T> resource) {
    if (!resource) return;
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    // Find and remove from in_use_resources_
    auto it = std::find_if(in_use_resources_.begin(), in_use_resources_.end(),
        [&resource](const std::unique_ptr<T>& ptr) {
            return ptr.get() == resource.get();
        });
    
    if (it != in_use_resources_.end()) {
        in_use_resources_.erase(it);
        available_resources_.push_back(std::move(resource));
        resource_available_.notify_one();
    }
}

template<typename T>
size_t ResourcePool<T>::getAvailableCount() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return available_resources_.size();
}

template<typename T>
size_t ResourcePool<T>::getInUseCount() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return in_use_resources_.size();
}

template<typename T>
size_t ResourcePool<T>::getTotalCount() const {
    return current_pool_size_.load();
}

template<typename T>
void ResourcePool<T>::clear() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    available_resources_.clear();
    in_use_resources_.clear();
    current_pool_size_ = 0;
}

template<typename T>
void ResourcePool<T>::setFactory(std::function<std::unique_ptr<T>()> factory) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    factory_function_ = factory;
}

// MemoryPool Implementation
MemoryPool::MemoryPool(size_t block_size, size_t max_blocks)
    : block_size_(block_size), max_blocks_(max_blocks), allocated_blocks_(0) {
    blocks_.reserve(max_blocks);
}

MemoryPool::~MemoryPool() {
    clear();
}

MemoryPool::MemoryPool(MemoryPool&& other) noexcept
    : blocks_(std::move(other.blocks_)), block_size_(other.block_size_),
      max_blocks_(other.max_blocks_), allocated_blocks_(other.allocated_blocks_.load()) {
    other.allocated_blocks_ = 0;
}

MemoryPool& MemoryPool::operator=(MemoryPool&& other) noexcept {
    if (this != &other) {
        clear();
        
        blocks_ = std::move(other.blocks_);
        block_size_ = other.block_size_;
        max_blocks_ = other.max_blocks_;
        allocated_blocks_ = other.allocated_blocks_.load();
        
        other.allocated_blocks_ = 0;
    }
    return *this;
}

void* MemoryPool::allocate(size_t size) {
    if (size > block_size_) {
        return nullptr; // Requested size too large
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    // Find available block
    for (auto& block : blocks_) {
        if (!block.in_use) {
            block.in_use = true;
            block.allocation_time = std::chrono::system_clock::now();
            allocated_blocks_++;
            return block.data;
        }
    }
    
    // Create new block if possible
    if (blocks_.size() < max_blocks_) {
        MemoryBlock new_block;
        new_block.data = std::malloc(block_size_);
        if (new_block.data) {
            new_block.size = block_size_;
            new_block.in_use = true;
            new_block.allocation_time = std::chrono::system_clock::now();
            blocks_.push_back(new_block);
            allocated_blocks_++;
            return new_block.data;
        }
    }
    
    return nullptr; // No available memory
}

void MemoryPool::deallocate(void* ptr) {
    if (!ptr) return;
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    for (auto& block : blocks_) {
        if (block.data == ptr && block.in_use) {
            block.in_use = false;
            allocated_blocks_--;
            break;
        }
    }
}

size_t MemoryPool::getAvailableBlocks() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return blocks_.size() - allocated_blocks_.load();
}

size_t MemoryPool::getAllocatedBlocks() const {
    return allocated_blocks_.load();
}

size_t MemoryPool::getTotalBlocks() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return blocks_.size();
}

void MemoryPool::clear() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    for (auto& block : blocks_) {
        if (block.data) {
            std::free(block.data);
        }
    }
    
    blocks_.clear();
    allocated_blocks_ = 0;
}

void MemoryPool::defragment() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    // Remove unused blocks
    blocks_.erase(
        std::remove_if(blocks_.begin(), blocks_.end(),
            [](const MemoryBlock& block) {
                if (!block.in_use && block.data) {
                    std::free(block.data);
                    return true;
                }
                return false;
            }),
        blocks_.end()
    );
}

// FileHandle Implementation
FileHandle::FileHandle(const std::string& filename, const std::string& mode)
    : filename_(filename), owned_(true) {
    file_ = std::fopen(filename.c_str(), mode.c_str());
    if (!file_) {
        std::cerr << "[FileHandle] Failed to open file: " << filename << std::endl;
    }
}

FileHandle::FileHandle(FILE* file, bool take_ownership)
    : file_(file), owned_(take_ownership) {
}

FileHandle::~FileHandle() {
    close();
}

FileHandle::FileHandle(FileHandle&& other) noexcept
    : file_(other.file_), filename_(std::move(other.filename_)), owned_(other.owned_) {
    other.file_ = nullptr;
    other.owned_ = false;
}

FileHandle& FileHandle::operator=(FileHandle&& other) noexcept {
    if (this != &other) {
        close();
        
        file_ = other.file_;
        filename_ = std::move(other.filename_);
        owned_ = other.owned_;
        
        other.file_ = nullptr;
        other.owned_ = false;
    }
    return *this;
}

void FileHandle::close() {
    if (file_ && owned_) {
        std::fclose(file_);
        file_ = nullptr;
    }
}

bool FileHandle::reopen(const std::string& mode) {
    if (file_ && owned_) {
        std::fclose(file_);
    }
    
    file_ = std::fopen(filename_.c_str(), mode.c_str());
    return file_ != nullptr;
}

// SocketHandle Implementation
SocketHandle::SocketHandle(int fd, bool take_ownership)
    : socket_fd_(fd), owned_(take_ownership) {
}

SocketHandle::~SocketHandle() {
    close();
}

SocketHandle::SocketHandle(SocketHandle&& other) noexcept
    : socket_fd_(other.socket_fd_), owned_(other.owned_) {
    other.socket_fd_ = -1;
    other.owned_ = false;
}

SocketHandle& SocketHandle::operator=(SocketHandle&& other) noexcept {
    if (this != &other) {
        close();
        
        socket_fd_ = other.socket_fd_;
        owned_ = other.owned_;
        
        other.socket_fd_ = -1;
        other.owned_ = false;
    }
    return *this;
}

void SocketHandle::close() {
    if (socket_fd_ >= 0 && owned_) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
}

bool SocketHandle::setNonBlocking(bool non_blocking) {
    if (socket_fd_ < 0) return false;
    
    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags < 0) return false;
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    return fcntl(socket_fd_, F_SETFL, flags) >= 0;
}

bool SocketHandle::setReuseAddress(bool reuse) {
    if (socket_fd_ < 0) return false;
    
    int opt = reuse ? 1 : 0;
    return setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) >= 0;
}

// TimerRAII Implementation
TimerRAII::TimerRAII(const std::string& operation_name, std::function<void(const std::string&, double)> callback)
    : start_time_(std::chrono::high_resolution_clock::now()),
      operation_name_(operation_name), callback_(callback) {
}

TimerRAII::~TimerRAII() {
    if (callback_) {
        double elapsed = getElapsedTimeMs();
        try {
            callback_(operation_name_, elapsed);
        } catch (const std::exception& e) {
            std::cerr << "[TimerRAII] Exception in callback: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[TimerRAII] Unknown exception in callback" << std::endl;
        }
    }
}

TimerRAII::TimerRAII(TimerRAII&& other) noexcept
    : start_time_(other.start_time_), operation_name_(std::move(other.operation_name_)),
      callback_(std::move(other.callback_)) {
}

TimerRAII& TimerRAII::operator=(TimerRAII&& other) noexcept {
    if (this != &other) {
        start_time_ = other.start_time_;
        operation_name_ = std::move(other.operation_name_);
        callback_ = std::move(other.callback_);
    }
    return *this;
}

double TimerRAII::getElapsedTimeMs() const {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
    return duration.count() / 1000.0;
}

void TimerRAII::reset() {
    start_time_ = std::chrono::high_resolution_clock::now();
}

// ResourceManager Implementation
ResourceManager::ResourceManager() : shutdown_requested_(false) {
}

ResourceManager::~ResourceManager() {
    cleanupAllResources();
}

void ResourceManager::registerResource(const std::string& name, std::function<void()> cleanup_function) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    cleanup_functions_[name] = cleanup_function;
}

void ResourceManager::unregisterResource(const std::string& name) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    cleanup_functions_.erase(name);
}

void ResourceManager::cleanupResource(const std::string& name) {
    std::function<void()> cleanup_function;
    
    {
        std::lock_guard<std::mutex> lock(manager_mutex_);
        auto it = cleanup_functions_.find(name);
        if (it != cleanup_functions_.end()) {
            cleanup_function = it->second;
            cleanup_functions_.erase(it);
        }
    }
    
    if (cleanup_function) {
        try {
            cleanup_function();
        } catch (const std::exception& e) {
            std::cerr << "[ResourceManager] Exception cleaning up resource " << name << ": " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[ResourceManager] Unknown exception cleaning up resource " << name << std::endl;
        }
    }
}

void ResourceManager::cleanupAllResources() {
    std::map<std::string, std::function<void()>> cleanup_functions;
    
    {
        std::lock_guard<std::mutex> lock(manager_mutex_);
        cleanup_functions = std::move(cleanup_functions_);
    }
    
    for (auto& pair : cleanup_functions) {
        try {
            pair.second();
        } catch (const std::exception& e) {
            std::cerr << "[ResourceManager] Exception cleaning up resource " << pair.first << ": " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[ResourceManager] Unknown exception cleaning up resource " << pair.first << std::endl;
        }
    }
}

void ResourceManager::shutdown() {
    shutdown_requested_ = true;
    cleanupAllResources();
}

size_t ResourceManager::getResourceCount() const {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    return cleanup_functions_.size();
}

std::vector<std::string> ResourceManager::getResourceNames() const {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    std::vector<std::string> names;
    names.reserve(cleanup_functions_.size());
    
    for (const auto& pair : cleanup_functions_) {
        names.push_back(pair.first);
    }
    
    return names;
}

// Global resource manager instance
ResourceManager g_resource_manager;

// Memory management utilities
namespace MemoryUtils {
    template<typename T>
    std::unique_ptr<T[]> allocateArray(size_t count) {
        try {
            return std::make_unique<T[]>(count);
        } catch (const std::bad_alloc& e) {
            std::cerr << "[MemoryUtils] Failed to allocate array of size " << count << ": " << e.what() << std::endl;
            return nullptr;
        }
    }
    
    template<typename T>
    void deallocateArray(T* ptr) {
        delete[] ptr;
    }
    
    size_t getCurrentMemoryUsage() {
        // Platform-specific implementation would go here
        return 0;
    }
    
    size_t getPeakMemoryUsage() {
        // Platform-specific implementation would go here
        return 0;
    }
    
    void resetMemoryUsage() {
        // Platform-specific implementation would go here
    }
    
    void enableLeakDetection() {
        // Platform-specific implementation would go here
    }
    
    void disableLeakDetection() {
        // Platform-specific implementation would go here
    }
    
    void reportLeaks() {
        // Platform-specific implementation would go here
    }
    
    void optimizeMemory() {
        // Platform-specific implementation would go here
    }
    
    void defragmentMemory() {
        // Platform-specific implementation would go here
    }
    
    void clearMemoryCache() {
        // Platform-specific implementation would go here
    }
}



