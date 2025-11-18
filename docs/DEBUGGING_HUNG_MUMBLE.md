# Getting a Backtrace from Hung Mumble Process

This guide explains how to capture backtraces from a hung or frozen Mumble process to diagnose deadlocks, hangs, and other threading issues.

## Prerequisites

### Enable Debug Output in Mumble

Before capturing backtraces, enable debug output to see plugin messages:

```bash
# Run Mumble with verbose debug output
mumble -v -debug

# Or with explicit debug flag
mumble --verbose --debug
```

This will show all `pluginDbg()` and `pluginLog()` messages from the FGCom plugin, which helps identify where the hang occurs.

### Compile Plugin with Debug Symbols

For meaningful backtraces with function names and line numbers, compile the plugin with debug symbols:

```bash
cd client/mumble-plugin

# The Makefile is already configured to include -g by default
make plugin

# Verify debug symbols are present
file fgcom-mumble.so | grep debug
# Should show: "with debug_info, not stripped"
```

---

## Method 1: Using GDB (Most Detailed)

### Step 1: Find the Process ID

```bash
# Find Mumble's process ID
ps aux | grep mumble

# Or more specifically:
pidof mumble
```

### Step 2: Attach GDB to Running Process

```bash
# Replace <PID> with the actual process ID
sudo gdb -p <PID>
```

### Step 3: Get All Thread Backtraces

Once GDB attaches, run these commands:

```gdb
# Get info about all threads
info threads

# Get backtrace of all threads (THIS IS KEY!)
thread apply all bt

# For even more detail:
thread apply all bt full

# To save output to file:
set logging file mumble_backtrace.txt
set logging on
thread apply all bt full
set logging off
```

### Step 4: Look for Specific Threads

```gdb
# Switch to a specific thread (e.g., thread 3)
thread 3

# Get detailed backtrace of that thread
bt full

# Show local variables
info locals

# Show current frame details
frame
```

### Step 5: Detach and Exit

```gdb
detach
quit
```

---

## Method 2: Using pstack (Simpler, Linux only)

```bash
# Install pstack if needed
sudo apt-get install pstack

# Get process ID
pidof mumble

# Generate backtrace
sudo pstack <PID> > mumble_backtrace.txt
```

---

## Method 3: Using gcore + gdb (If process is completely frozen)

```bash
# Get core dump without killing process
sudo gcore <PID>

# Analyze core dump
gdb /path/to/mumble core.<PID>

# Inside gdb:
thread apply all bt full
```

---

## Method 4: Send SIGQUIT Signal (Creates backtrace in logs)

```bash
# This makes the process dump its state
kill -QUIT <PID>

# Check system logs or stderr output
journalctl -f | grep mumble
```

---

## Method 5: Batch Mode (Quick One-Liner)

For quick backtrace capture without interactive GDB:

```bash
# Get process ID
MUMBLE_PID=$(pidof mumble)

# Capture backtrace to file
sudo gdb -batch -ex "info threads" -ex "thread apply all bt" -p $MUMBLE_PID 2>&1 | tee debug/backtrace_${MUMBLE_PID}.txt

# With full details (variables, registers, etc.)
sudo gdb -batch -ex "info threads" -ex "thread apply all bt full" -p $MUMBLE_PID 2>&1 | tee debug/backtrace_full_${MUMBLE_PID}.txt
```

---

## What to Look For in the Backtrace

### 1. **Mutex/Lock Functions**

Look for threads stuck in:

- `pthread_mutex_lock`
- `std::mutex::lock`
- `std::lock_guard`
- `__lll_lock_wait`
- `futex_wait` (Linux futex system call)

### 2. **Blocking I/O**

- `recvfrom` (UDP server waiting)
- `read`, `write`
- `select`, `poll`, `epoll_wait`

### 3. **API Calls**

- `mumAPI.log` (mentioned as blocking in code)
- Any Mumble API functions

### 4. **Multiple Threads Waiting**

If you see multiple threads all waiting on locks, that's likely your deadlock.

### 5. **Plugin Functions**

Look for FGCom plugin functions in the stack:
- `fgcom_handlePTT()`
- `fgcom_notifyThread()`
- `fgcom_udp_parseMsg()`
- `mumble_onAudioSourceFetched()`
- `fgcom_updateClientComment()`

---

## Example Deadlock Pattern

```
Thread 1:
#0  futex_wait (private=0, expected=2, futex_word=0x762358483380 <fgcom_localcfg_mtx>) at ../sysdeps/nptl/futex-internal.h:146
#1  __GI___lll_lock_wait (futex=futex@entry=0x762358483380 <fgcom_localcfg_mtx>, private=0) at ./nptl/lowlevellock.c:49
#2  0x00007623816a0101 in lll_mutex_lock_optimized (mutex=0x762358483380 <fgcom_localcfg_mtx>) at ./nptl/pthread_mutex_lock.c:48
#3  ___pthread_mutex_lock (mutex=0x762358483380 <fgcom_localcfg_mtx>) at ./nptl/pthread_mutex_lock.c:93
#4  0x0000762358411bbe in fgcom_updateClientComment() () at /home/haaken/.local/share/Mumble/Mumble/Plugins/fgcom-mumble.so
#5  0x00007623584121d2 in fgcom_setPluginActive(bool) () at /home/haaken/.local/share/Mumble/Mumble/Plugins/fgcom-mumble.so

Thread 2:
#0  futex_wait (private=0, expected=2, futex_word=0x762358483380 <fgcom_localcfg_mtx>) at ../sysdeps/nptl/futex-internal.h:146
#1  __GI___lll_lock_wait (futex=futex@entry=0x762358483380 <fgcom_localcfg_mtx>, private=0) at ./nptl/lowlevellock.c:49
#2  0x00007623816a0101 in lll_mutex_lock_optimized (mutex=0x762358483380 <fgcom_localcfg_mtx>) at ./nptl/pthread_mutex_lock.c:48
#3  ___pthread_mutex_lock (mutex=0x762358483380 <fgcom_localcfg_mtx>) at ./nptl/pthread_mutex_lock.c:93
#4  0x00007623582b6edd in fgcom_notifyThread() () at /home/haaken/.local/share/Mumble/Mumble/Plugins/fgcom-mumble.so
```

This shows **both threads waiting on the same mutex** (`fgcom_localcfg_mtx`), which indicates a deadlock where:
- Thread 1 is trying to call `fgcom_updateClientComment()` from `fgcom_setPluginActive()`
- Thread 2 is trying to call `fgcom_notifyThread()`
- Both are blocked waiting for `fgcom_localcfg_mtx`

**Solution**: Use `std::unique_lock` with `std::try_to_lock` instead of blocking `std::lock_guard` in background threads.

---

## Compiling with Debug Symbols (For Better Backtraces)

If backtraces show `??` or missing function names, recompile with debug symbols:

```bash
cd client/mumble-plugin

# The Makefile already includes -g by default (DEBUG=-g)
# Just rebuild:
make clean
make plugin

# Verify debug symbols
file fgcom-mumble.so | grep debug
# Should show: "with debug_info, not stripped"

# Copy to Mumble plugin directory
cp fgcom-mumble.so ~/.local/share/Mumble/Mumble/Plugins/
```

**Note**: The plugin Makefile is configured to always include debug symbols (`DEBUG=-g` in the Makefile).

---

## Quick Reference Commands

```bash
# One-liner to get backtrace
sudo gdb -batch -ex "thread apply all bt" -p $(pidof mumble) 2>&1 | tee backtrace.txt

# With full details (variables, registers, etc.)
sudo gdb -batch -ex "info threads" -ex "thread apply all bt full" -p $(pidof mumble) 2>&1 | tee backtrace_full.txt

# Save to debug directory
mkdir -p debug
MUMBLE_PID=$(pidof mumble)
sudo gdb -batch -ex "info threads" -ex "thread apply all bt full" -p $MUMBLE_PID 2>&1 | tee debug/backtrace_${MUMBLE_PID}.txt
```

---

## After Getting the Backtrace

1. **Save the output** to a file (e.g., `debug/backtrace_<PID>.txt`)

2. **Look for the patterns** described above:
   - Multiple threads waiting on the same mutex
   - Threads stuck in blocking operations
   - Plugin functions in the call stack

3. **Share relevant sections** with developers or AI assistants:
   - Include the thread that's stuck
   - Include any threads waiting on mutexes
   - Include line numbers from your source code (if available)

4. **Check debug output** from `mumble -v -debug`:
   - Look for the last `pluginDbg()` or `pluginLog()` message
   - This shows where the plugin was executing before the hang

The backtrace will tell you **exactly** where each thread is stuck, which is what static analysis can't do!

---

## Common Deadlock Scenarios in FGCom Plugin

### Scenario 1: Audio Callback Blocking on Mutex

**Symptom**: Mumble freezes when audio is playing/receiving

**Backtrace shows**:
- `mumble_onAudioSourceFetched()` waiting on `fgcom_localcfg_mtx` or `fgcom_remotecfg_mtx`
- Background thread (UDP server, notification thread) holding the same mutex

**Fix**: Use `std::unique_lock` with `std::try_to_lock` in audio callbacks

### Scenario 2: Background Thread Blocking on Mutex

**Symptom**: Mumble freezes during plugin initialization or when receiving UDP data

**Backtrace shows**:
- `fgcom_udp_parseMsg()` or `fgcom_notifyThread()` waiting on `fgcom_localcfg_mtx`
- Main thread or audio callback holding the same mutex

**Fix**: Use `std::unique_lock` with `std::try_to_lock` in background threads

### Scenario 3: Plugin Shutdown Deadlock

**Symptom**: Mumble hangs when disabling/unloading the plugin

**Backtrace shows**:
- `mumble_shutdown()` → `fgcom_setPluginActive(false)` → `fgcom_updateClientComment()` waiting on mutex
- Background thread still holding the mutex

**Fix**: Ensure all background threads can be interrupted and use non-blocking locks during shutdown

---

## Related Documentation

- [Plugin Issues and Fixes](plugin-issues.md) - Known issues and their solutions
- [Installation Guide](INSTALLATION_GUIDE.md) - Plugin installation instructions
- [Plugin Specification](client/mumble-plugin/plugin.spec.md) - Technical plugin documentation

