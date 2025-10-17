# TLE Updater CMakeLists.txt
# Build configuration for TLE automatic updater

cmake_minimum_required(VERSION 3.10)
project(TLEUpdater)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Find libcurl
pkg_check_modules(CURL REQUIRED libcurl)

# Include directories
include_directories(${CURL_INCLUDE_DIRS})

# Source files
set(TLE_UPDATER_SOURCES
    tle_updater.cpp
)

# Create TLE updater executable
add_executable(tle_updater ${TLE_UPDATER_SOURCES})

# Link libraries
target_link_libraries(tle_updater
    ${CURL_LIBRARIES}
    Threads::Threads
)

# Compiler flags
target_compile_options(tle_updater PRIVATE ${CURL_CFLAGS_OTHER})

# Install target
install(TARGETS tle_updater
    RUNTIME DESTINATION bin
)

# Create installation script
install(FILES
    ../../scripts/satellites/start_tle_updater.sh
    ../../scripts/satellites/backup_tle_files.sh
    ../../scripts/satellites/fgcom-tle-updater.service
    DESTINATION bin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

