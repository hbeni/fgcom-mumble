# Copyright 2020 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

cmake_minimum_required(VERSION 3.0)

set(version "0.0.1")

project(FgcomPlugin
	VERSION "${version}"
	DESCRIPTION "A Mumble based radio simulation for flight simulators"
	LANGUAGES "CXX"
)

# Cpp17 or later is required in order to use the wrapper
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# In order to use additional parts of the plugin interface, you have to enable the respective optiopn
# e.g. set(positional-audio ON)
set(server-event-callbacks ON CACHE BOOL "" FORCE)
set(plugin-data-callbacks ON CACHE BOOL "" FORCE)

# We need the wrapper as a depency
add_subdirectory(./mumble "${CMAKE_CURRENT_BINARY_DIR}/wrapper")

add_library(fgcom-mumble SHARED
	fgcom-mumble.cpp
)

target_link_libraries(fgcom-mumble PRIVATE mumble_plugin_cpp_wrapper)
