#ifndef FGCOM_RESOURCE_MANAGEMENT_H
#define FGCOM_RESOURCE_MANAGEMENT_H

#include <memory>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>
#include <string>
#include <functional>
#include <chrono>
#include <thread>
#include <condition_variable>

// RAII wrapper for thread management
class ThreadRAII {
private:
    std::thread thread_;
    std::atomic<bool> should_stop_;
    std::function<void()> cleanup_function_;
    
public:
    ThreadRAII(std::function<void()> thread_function, std::function<void()> cleanup = nullptr);
    ~ThreadRAII();
    
    // Non-copyable
    ThreadRAII(const ThreadRAII&) = delete;
    ThreadRAII& operator=(const ThreadRAII&) = delete;
    
    // Movable
    ThreadRAII(ThreadRAII&& other) noexcept;
    ThreadRAII& operator=(ThreadRAII&& other) noexcept;
    
    void stop();
    void join();
    bool joinable() const;
    std::thread::id get_id() const;
    bool shouldStop() const;
};

// RAII wrapper for mutex management
class MutexRAII {
private:
    std::mutex& mutex_;
    bool locked_;
    
public:
    explicit MutexRAII(std::mutex& mutex);
    ~MutexRAII();
    
    // Non-copyable, non-movable
    MutexRAII(const MutexRAII&) = delete;
    MutexRAII& operator=(const MutexRAII&) = delete;
    MutexRAII(MutexRAII&&) = delete;
    MutexRAII& operator=(MutexRAII&&) = delete;
    
    void lock();
    void unlock();
    bool try_lock();
    bool owns_lock() const;
};

// RAII wrapper for shared mutex management
class SharedMutexRAII {
private:
    std::shared_mutex& mutex_;
    bool locked_;
    bool is_shared_;
    
public:
    explicit SharedMutexRAII(std::shared_mutex& mutex, bool shared = false);
    ~SharedMutexRAII();
    
    // Non-copyable, non-movable
    SharedMutexRAII(const SharedMutexRAII&) = delete;
    SharedMutexRAII& operator=(const SharedMutexRAII&) = delete;
    SharedMutexRAII(SharedMutexRAII&&) = delete;
    SharedMutexRAII& operator=(SharedMutexRAII&&) = delete;
    
    void lock();
    void unlock();
    bool try_lock();
    bool owns_lock() const;
};

// Smart pointer wrapper with custom deleter
template<typename T>
class SmartPtr {
private:
    std::unique_ptr<T, std::function<void(T*)>> ptr_;
    
public:
    SmartPtr() = default;
    
    explicit SmartPtr(T* ptr, std::function<void(T*)> deleter = [](T* p) { delete p; })
        : ptr_(ptr, deleter) {}
    
    SmartPtr(std::unique_ptr<T>&& ptr, std::function<void(T*)> deleter = [](T* p) { delete p; })
        : ptr_(ptr.release(), deleter) {}
    
    T* get() const { return ptr_.get(); }
    T& operator*() const { return *ptr_; }
    T* operator->() const { return ptr_.get(); }
    
    bool operator==(std::nullptr_t) const { return ptr_ == nullptr; }
    bool operator!=(std::nullptr_t) const { return ptr_ != nullptr; }
    
    void reset(T* ptr = nullptr, std::function<void(T*)> deleter = [](T* p) { delete p; }) {
        ptr_.reset(ptr, deleter);
    }
    
    T* release() { return ptr_.release(); }
};

// Resource pool for managing limited resources
template<typename T>
class ResourcePool {
private:
    std::vector<std::unique_ptr<T>> available_resources_;
    std::vector<std::unique_ptr<T>> in_use_resources_;
    std::mutex pool_mutex_;
    std::condition_variable resource_available_;
    std::function<std::unique_ptr<T>()> factory_function_;
    size_t max_pool_size_;
    std::atomic<size_t> current_pool_size_;
    
public:
    explicit ResourcePool(size_t max_size = 100, std::function<std::unique_ptr<T>()> factory = nullptr);
    ~ResourcePool();
    
    // Non-copyable
    ResourcePool(const ResourcePool&) = delete;
    ResourcePool& operator=(const ResourcePool&) = delete;
    
    // Movable
    ResourcePool(ResourcePool&& other) noexcept;
    ResourcePool& operator=(ResourcePool&& other) noexcept;
    
    std::unique_ptr<T> acquire(std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));
    void release(std::unique_ptr<T> resource);
    size_t getAvailableCount() const;
    size_t getInUseCount() const;
    size_t getTotalCount() const;
    void clear();
    void setFactory(std::function<std::unique_ptr<T>()> factory);
};

// Memory pool for efficient memory management
class MemoryPool {
private:
    struct MemoryBlock {
        void* data;
        size_t size;
        bool in_use;
        std::chrono::system_clock::time_point allocation_time;
    };
    
    std::vector<MemoryBlock> blocks_;
    std::mutex pool_mutex_;
    size_t block_size_;
    size_t max_blocks_;
    std::atomic<size_t> allocated_blocks_;
    
public:
    explicit MemoryPool(size_t block_size = 1024, size_t max_blocks = 1000);
    ~MemoryPool();
    
    // Non-copyable
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    
    // Movable
    MemoryPool(MemoryPool&& other) noexcept;
    MemoryPool& operator=(MemoryPool&& other) noexcept;
    
    void* allocate(size_t size);
    void deallocate(void* ptr);
    size_t getAvailableBlocks() const;
    size_t getAllocatedBlocks() const;
    size_t getTotalBlocks() const;
    void clear();
    void defragment();
};

// File handle RAII wrapper
class FileHandle {
private:
    FILE* file_;
    std::string filename_;
    bool owned_;
    
public:
    explicit FileHandle(const std::string& filename, const std::string& mode);
    explicit FileHandle(FILE* file, bool take_ownership = false);
    ~FileHandle();
    
    // Non-copyable
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    
    // Movable
    FileHandle(FileHandle&& other) noexcept;
    FileHandle& operator=(FileHandle&& other) noexcept;
    
    FILE* get() const { return file_; }
    bool isOpen() const { return file_ != nullptr; }
    const std::string& getFilename() const { return filename_; }
    
    void close();
    bool reopen(const std::string& mode);
};

// Network socket RAII wrapper
class SocketHandle {
private:
    int socket_fd_;
    bool owned_;
    
public:
    explicit SocketHandle(int fd = -1, bool take_ownership = true);
    ~SocketHandle();
    
    // Non-copyable
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    
    // Movable
    SocketHandle(SocketHandle&& other) noexcept;
    SocketHandle& operator=(SocketHandle&& other) noexcept;
    
    int get() const { return socket_fd_; }
    bool isValid() const { return socket_fd_ >= 0; }
    
    void close();
    bool setNonBlocking(bool non_blocking);
    bool setReuseAddress(bool reuse);
};

// Timer RAII wrapper
class TimerRAII {
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::string operation_name_;
    std::function<void(const std::string&, double)> callback_;
    
public:
    explicit TimerRAII(const std::string& operation_name, 
                      std::function<void(const std::string&, double)> callback = nullptr);
    ~TimerRAII();
    
    // Non-copyable
    TimerRAII(const TimerRAII&) = delete;
    TimerRAII& operator=(const TimerRAII&) = delete;
    
    // Movable
    TimerRAII(TimerRAII&& other) noexcept;
    TimerRAII& operator=(TimerRAII&& other) noexcept;
    
    double getElapsedTimeMs() const;
    void reset();
    const std::string& getOperationName() const { return operation_name_; }
};

// Resource manager for tracking and cleaning up resources
class ResourceManager {
private:
    std::map<std::string, std::function<void()>> cleanup_functions_;
    std::mutex manager_mutex_;
    std::atomic<bool> shutdown_requested_;
    
public:
    ResourceManager();
    ~ResourceManager();
    
    // Non-copyable
    ResourceManager(const ResourceManager&) = delete;
    ResourceManager& operator=(const ResourceManager&) = delete;
    
    void registerResource(const std::string& name, std::function<void()> cleanup_function);
    void unregisterResource(const std::string& name);
    void cleanupResource(const std::string& name);
    void cleanupAllResources();
    void shutdown();
    
    size_t getResourceCount() const;
    std::vector<std::string> getResourceNames() const;
};

// Global resource manager instance
extern ResourceManager g_resource_manager;

// Utility macros for automatic resource management
#define FGCOM_SCOPE_LOCK(mutex) MutexRAII _lock(mutex)
#define FGCOM_SCOPE_SHARED_LOCK(mutex) SharedMutexRAII _lock(mutex, true)
#define FGCOM_SCOPE_TIMER(name) TimerRAII _timer(name)
#define FGCOM_SCOPE_RESOURCE(name, cleanup) \
    g_resource_manager.registerResource(name, cleanup); \
    auto _cleanup = [&]() { g_resource_manager.unregisterResource(name); }; \
    std::unique_ptr<void, decltype(_cleanup)> _scope_guard(nullptr, _cleanup)

// Smart pointer aliases
template<typename T>
using UniquePtr = SmartPtr<T>;

template<typename T>
using SharedPtr = std::shared_ptr<T>;

template<typename T>
using WeakPtr = std::weak_ptr<T>;

// Resource pool aliases
template<typename T>
using ThreadPool = ResourcePool<T>;

template<typename T>
using ConnectionPool = ResourcePool<T>;

// Memory management utilities
namespace MemoryUtils {
    // Safe memory allocation with error checking
    template<typename T>
    std::unique_ptr<T[]> allocateArray(size_t count);
    
    // Safe memory deallocation
    template<typename T>
    void deallocateArray(T* ptr);
    
    // Memory usage tracking
    size_t getCurrentMemoryUsage();
    size_t getPeakMemoryUsage();
    void resetMemoryUsage();
    
    // Memory leak detection
    void enableLeakDetection();
    void disableLeakDetection();
    void reportLeaks();
    
    // Memory optimization
    void optimizeMemory();
    void defragmentMemory();
    void clearMemoryCache();
}

#endif // FGCOM_RESOURCE_MANAGEMENT_H



