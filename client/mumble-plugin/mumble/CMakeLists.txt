# Copyright 2020 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# source tree.

cmake_minimum_required(VERSION 3.0)

set(version "1.0.0")

project(MumblePluginCppWrapper
	VERSION "${version}"
	DESCRIPTION "C++ wrapper of Mumble's C plugin API"
	LANGUAGES "CXX"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(positional-audio "Include functions for positional audio" OFF)
option(server-event-callbacks "Include callback functions for server-events" OFF)
option(audio-callbacks "Include callback audio functions" OFF)
option(plugin-data-callbacks "Include functions for receiving network messages from other plugins" OFF)
option(key-event-callbacks "Include callback functions for key-events" OFF)
option(plugin-update "Include functions for self-updating the plugin" OFF)

option(all-callbacks "Include event callback functions" OFF)
option(all-features "Shortcut for enabling all plugin features" OFF)

add_library(mumble_plugin_cpp_wrapper INTERFACE)
add_library(mumble_plugin_cpp_wrapper_api INTERFACE)

set(WRAPPER_SOURCES
	src/MumblePluginDefaultImpl.cpp
	src/plugin.cpp
)

set(API_SOURCES
	src/MumbleAPI.cpp
)

target_link_libraries(mumble_plugin_cpp_wrapper INTERFACE mumble_plugin_cpp_wrapper_api)

# Set all source files as absolute paths
foreach(CURRENT_SOURCE IN LISTS WRAPPER_SOURCES)
	get_filename_component(ABS_SOURCE_PATH "${CURRENT_SOURCE}" REALPATH BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
	target_sources(mumble_plugin_cpp_wrapper
		INTERFACE
			"${ABS_SOURCE_PATH}"
	)
endforeach()

foreach(CURRENT_SOURCE IN LISTS API_SOURCES)
	get_filename_component(ABS_SOURCE_PATH "${CURRENT_SOURCE}" REALPATH BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
	target_sources(mumble_plugin_cpp_wrapper_api
		INTERFACE
			"${ABS_SOURCE_PATH}"
	)
endforeach()

set(WRAPPER_INCLUDES
	"./include"
)

set(API_INCLUDES
	"./include"
)

# Set all include-dirs as absolute paths
foreach(CURRENT_INCLUDE IN LISTS WRAPPER_INCLUDES)
	get_filename_component(ABS_INCLUDE_PATH "${CURRENT_INCLUDE}" ABSOLUTE "${CMAKE_CURRENT_SOURCE_DIR}")
	target_include_directories(mumble_plugin_cpp_wrapper
		INTERFACE
		"${ABS_INCLUDE_PATH}"
	)
endforeach()

foreach(CURRENT_INCLUDE IN LISTS API_INCLUDES)
	get_filename_component(ABS_INCLUDE_PATH "${CURRENT_INCLUDE}" ABSOLUTE "${CMAKE_CURRENT_SOURCE_DIR}")
	target_include_directories(mumble_plugin_cpp_wrapper_api
		INTERFACE
		"${ABS_INCLUDE_PATH}"
	)
endforeach()

if (positional-audio OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_POSITIONAL_AUDIO"
	)
endif()

if (server-event-callbacks OR all-callbacks OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_SERVER_EVENT_CALLBACKS"
	)
endif()

if (audio-callbacks OR all-callbacks OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_AUDIO_CALLBACKS"
	)
endif()

if (plugin-data-callbacks OR all-callbacks OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_DATA_FRAMEWORK_CALLBACKS"
	)
endif()

if (key-event-callbacks OR all-callbacks OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_KEY_EVENT_CALLBACKS"
	)
endif()

if (plugin-update OR all-callbacks OR all-features)
	target_compile_definitions(mumble_plugin_cpp_wrapper
		INTERFACE
			"MUMBLE_PLUGIN_WRAPPER_USE_PLUGIN_UPDATES"
	)
endif()
