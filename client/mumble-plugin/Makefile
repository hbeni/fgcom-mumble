.PHONY : all debug all-debug plugin-debug plugin libs test tools clean clean-all debug-on
CC=g++
DEBUG=-g
THREADS_UNIX=-pthread
THREADS_WIN=-Wl,-Bstatic -lstdc++ -lpthread -lws2_32
override CFLAGS+=-Wall -O3 -I. -I./lib -DENABLE_OPENINFRAMAP $(DEBUG)

# DSP IIR Realtime C++ filter library support
# Professional audio processing is now built-in using modern DSP algorithms
$(info Professional audio processing enabled - Using DSP IIR Realtime C++ filter library)
override CFLAGS_WIN+=-Wl,--subsystem,windows -static-libgcc -static-libstdc++ $(CFLAGS)
SSLFLAGS+=-I./lib/openssl/include/ -L./lib/openssl/ -lssl -lcrypto -DSSLFLAGS
SSLFLAGS_WIN+=-I./lib/openssl/include/ -L./lib/openssl/ -static -lssl -lcrypto -lws2_32 -lcrypt32 -DSSLFLAGS -D_WIN32
# Note on flags: -D_WIN32 is needed by httplib on Windows

# Modular structure: propagation, noise, audio, maps, security
# Each module can be built and tested independently
PROPAGATION_CORE_OBJS := lib/propagation/core/propagation_physics.o lib/propagation/core/atmospheric_ducting.o lib/propagation/core/enhanced_multipath.o
PROPAGATION_TERRAIN_OBJS := lib/propagation/terrain/terrain_elevation.o lib/propagation/terrain/terrain_cache.o lib/propagation/terrain/terrain_data_access.o lib/propagation/terrain/terrain_state_machine.o lib/propagation/terrain/terrain_statistics.o lib/propagation/terrain/terrain_environmental_api.o
PROPAGATION_WEATHER_OBJS := lib/propagation/weather/solar_data.o
PROPAGATION_OBJS := $(PROPAGATION_CORE_OBJS) $(PROPAGATION_TERRAIN_OBJS) $(PROPAGATION_WEATHER_OBJS)
MAPS_OBJS := lib/maps/openinframap_data_source.o
NOISE_OBJS := lib/noise/atmospheric_noise.o lib/noise/noise_floor_utils.o
AUDIO_OBJS := lib/audio/audio.o lib/audio/audio_professional.o
# Note: audio_modern.cpp is an alternative implementation - include only if needed
SECURITY_CORE_OBJS := lib/security/core/security.o
SECURITY_WORK_UNIT_OBJS := lib/security/work_unit/work_unit_security.o
SECURITY_OBJS := $(SECURITY_CORE_OBJS) $(SECURITY_WORK_UNIT_OBJS)
WORK_UNIT_SHARING_OBJS := lib/work_unit/work_unit_sharing.o
WORK_UNIT_OBJS := lib/work_unit_distributor.o lib/client_work_unit_coordinator.o $(WORK_UNIT_SHARING_OBJS)
SPACE_MOON_OBJS := lib/space/moon/moon_position_tracker.o
SPACE_SATELLITES_OBJS := lib/space/satellites/satellite_tracker.o
SPACE_OBJS := $(SPACE_MOON_OBJS) $(SPACE_SATELLITES_OBJS)

lib_OBJS := lib/radio_model.o $(AUDIO_OBJS) lib/io_plugin.o lib/io_UDPServer.o lib/io_UDPClient.o lib/garbage_collector.o lib/amateur_radio.o $(PROPAGATION_OBJS) lib/power_management.o lib/frequency_offset.o $(NOISE_OBJS) lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/agc_squelch.o lib/agc_squelch_api.o lib/ctcss_system.o lib/preset_channel_api.o lib/soviet_vhf_equipment.o lib/nato_vhf_equipment.o lib/preset_channel_config_loader.o lib/radio_model_config_loader.o lib/gpu_resource_limiting.o lib/radio_config.o $(MAPS_OBJS) lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o lib/radio_model_string_impl.o lib/radio_model_hf_impl.o lib/radio_model_amateur_impl.o lib/radio_model_uhf_impl.o $(WORK_UNIT_OBJS) $(SPACE_OBJS)

# Module-level build targets for incremental development and testing
.PHONY: module-propagation module-noise module-audio module-maps module-security module-work-unit module-space test-module-propagation test-module-noise test-module-audio test-module-security test-module-work-unit test-module-space

# Build individual modules
module-propagation: $(PROPAGATION_OBJS)
	@echo "Propagation module built: $(PROPAGATION_OBJS)"

module-noise: $(NOISE_OBJS) $(MAPS_OBJS)
	@echo "Noise module built: $(NOISE_OBJS) (requires maps: $(MAPS_OBJS))"

module-audio: $(AUDIO_OBJS)
	@echo "Audio module built: $(AUDIO_OBJS)"

module-maps: $(MAPS_OBJS)
	@echo "Maps module built: $(MAPS_OBJS)"

module-security: $(SECURITY_OBJS)
	@echo "Security module built: $(SECURITY_OBJS)"

module-work-unit: $(WORK_UNIT_OBJS)
	@echo "Work Unit module built: $(WORK_UNIT_OBJS)"

module-space: $(SPACE_OBJS)
	@echo "Space module built: $(SPACE_OBJS)"

# Test individual modules (placeholder - can be extended with module-specific tests)
test-module-propagation: module-propagation
	@echo "Testing propagation module..."
	@echo "  - Core: propagation_physics, atmospheric_ducting, enhanced_multipath"
	@echo "  - Terrain: terrain_elevation, terrain_cache, terrain_data_access, etc."
	@echo "  - Weather: solar_data"
	@echo "Run: make module-propagation && make plugin (to test integration)"

test-module-noise: module-noise
	@echo "Testing noise module..."
	@echo "  - Core: atmospheric_noise, noise_floor_utils"
	@echo "  - Dependencies: maps module (for infrastructure data)"
	@echo "Run: make module-noise && make plugin (to test integration)"

test-module-audio: module-audio
	@echo "Testing audio module..."
	@echo "  - Core: audio, audio_professional"
	@echo "Run: make module-audio && make plugin (to test integration)"

test-module-security: module-security
	@echo "Testing security module..."
	@echo "  - Core: security (encryption, hashing, authentication)"
	@echo "  - Work Unit: work_unit_security (AES256, RSA, digital signatures)"
	@echo "Run: make module-security && make plugin (to test integration)"

test-module-work-unit: module-work-unit
	@echo "Testing work unit module..."
	@echo "  - Distributor: work_unit_distributor (work unit distribution)"
	@echo "  - Coordinator: client_work_unit_coordinator (client coordination)"
	@echo "  - Sharing: work_unit_sharing (modular sharing strategies)"
	@echo "Run: make module-work-unit && make plugin (to test integration)"

test-module-space: module-space
	@echo "Testing space module..."
	@echo "  - Moon: moon_position_tracker (EME communication, moon tracking)"
	@echo "  - Satellites: satellite_tracker (satellite tracking, visibility, Doppler)"
	@echo "Run: make module-space && make plugin (to test integration)"

# Notice: Special calls
#
# `make DEBUG+="-DDEBUG"`                  enable debug code (use `make DEBUG+="-g3 -DDEBUG -Og"` for additional gdb symbols)
# `make CFLAGS+="-DNO_UPDATER" SSLFLAGS=`  skip auto-updater code, and do not link against OpenSSL
#  More CFLAGS: -DNO_UDPCLIENT             no RDF data sending thread
#               -DNO_UDPSERVER             no UDP server thread
#               -DNO_NOTIFY                no pluginIO notification thread
#               -DNO_GC                    no garbage collector thread
#               -DNO_CFG                   no config file parsing
#               -DNO_COMMENT               no mumble GUI comment adjustments
# `make ... outname=<name> ...`            change name of resulting binary lib
# `make ... mingwprefix=<...>`             Change mingw prefix; CC variable will be appended to this

# FOR PRERELEASES: make always debug builds
#ifneq (,$(findstring 0,$(VERSION_V)))
#    DEBUG+=-g3 -DDEBUG
#endif

# If SSLFLAGS was set to empty, empty the win version too
ifndef SSLFLAGS
    SSLFLAGS_WIN=
endif


# Compile all that stuff
all: plugin tools clean

# DEBUG MODE
#   convinience invocation for debug build fpr GDB
#   -g3:     gdb debugging symbols
#   -O0:     no optimizations, so we get better dbg output (but slows don code significantly)
#   -DDEBUG: makes debug code active (prints internal state to stdout every sec)
debug: all-debug
all-debug:
	make DEBUG+="-g3 -Og -DDEBUG" all

# build just the linux plugin in debug mode
plugin-debug:
	make DEBUG+="-g3 -Og -DDEBUG" plugin

# make the plugin
plugin: outname=fgcom-mumble.so
plugin: libs
	$(CC) -shared -fPIC -o $(outname) $(lib_OBJS) fgcom-mumble.cpp $(SSLFLAGS) $(CFLAGS) $(THREADS_UNIX) -lcurl

# make all the libs
libs:  $(lib_OBJS)

# Object file compilation rules
# Unix/Linux/macOS (default)
%.o : %.cpp
	@if echo "$(CC)" | grep -q "mingw"; then \
		if echo "$(CC)" | grep -q "i686"; then \
			$(CC) -fPIC -c -o $@ $< $(CFLAGS_WIN) -m32 -DMINGW_WIN32; \
		else \
			$(CC) -fPIC -c -o $@ $< $(CFLAGS_WIN) -DMINGW_WIN64; \
		fi; \
	else \
		$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(THREADS_UNIX); \
	fi

# Compile testing tools
# Note: tools need stub symbols from fgcom-mumble-tools-stub.cpp for audio.cpp dependencies
tools: libs
	$(CC) -fPIC -c -o fgcom-mumble-tools-stub.o fgcom-mumble-tools-stub.cpp $(CFLAGS) $(THREADS_UNIX)
	$(CC) -o test/geotest lib/radio_model.o $(AUDIO_OBJS) lib/amateur_radio.o $(PROPAGATION_WEATHER_OBJS) lib/power_management.o lib/frequency_offset.o $(NOISE_OBJS) lib/pattern_interpolation.o lib/antenna_pattern_mapping.o $(PROPAGATION_CORE_OBJS) lib/radio_config.o $(MAPS_OBJS) lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o lib/radio_model_string_impl.o lib/radio_model_hf_impl.o lib/radio_model_amateur_impl.o lib/radio_model_uhf_impl.o fgcom-mumble-tools-stub.o test/geotest.cpp $(CFLAGS) -lcurl
	$(CC) -o test/frqtest lib/radio_model.o $(AUDIO_OBJS) lib/amateur_radio.o $(PROPAGATION_WEATHER_OBJS) lib/power_management.o lib/frequency_offset.o $(NOISE_OBJS) lib/pattern_interpolation.o lib/antenna_pattern_mapping.o $(PROPAGATION_CORE_OBJS) lib/radio_config.o $(MAPS_OBJS) lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o lib/radio_model_string_impl.o lib/radio_model_hf_impl.o lib/radio_model_amateur_impl.o lib/radio_model_uhf_impl.o fgcom-mumble-tools-stub.o test/frqtest.cpp $(CFLAGS) -lcurl
	$(CC) -o test/updater-test test/updater-test.cpp $(CFLAGS)
	


# catch2 unit tests linking against main
# Note: test needs fgcom-mumble.cpp for audio.cpp dependencies (cached_radio_infos_mtx, fgcom_cfg, etc.)
test: libs test/catch2/tests-main.o test/catch2/radioModelTest.o
	$(CC) -fPIC -c -o fgcom-mumble-test.o fgcom-mumble.cpp $(CFLAGS) $(THREADS_UNIX)
	$(CC) -o test/catch2/radioModelTest.catch2 test/catch2/tests-main.o test/catch2/radioModelTest.o $(lib_OBJS) fgcom-mumble-test.o $(CFLAGS) $(THREADS_UNIX) -lcurl && test/catch2/radioModelTest.catch2
# ^ add more

# clean compile results
clean:
	rm -f *.o *.rc lib/*.o test/catch2/*.catch2 test/catch2/*.o fgcom-mumble-test.o fgcom-mumble-tools-stub.o

# clean compile results and binarys
clean-all: clean
	rm -f test/geotest test/frqtest
	rm -f fgcom-mumble*.so
	rm -f *.exe test/*.exe *.dll lib/*.dll
	rm -f test/catch2/*.o



# Build all win64 stuff
#   apt-get install mingw-w64
all-win: plugin-win64 tools-win64 clean

# build win64 test tools
# Note: tools need stub symbols from fgcom-mumble-tools-stub.cpp for audio.cpp dependencies
tools-win64: CC=x86_64-w64-mingw32-g++-posix
tools-win64: libs-win64 tools-win64-stub
	$(CC) -o test/geotest.exe lib/radio_model.o lib/audio.o lib/amateur_radio.o lib/solar_data.o lib/power_management.o lib/frequency_offset.o lib/atmospheric_noise.o lib/noise_floor_utils.o lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/propagation_physics.o lib/radio_config.o lib/atmospheric_ducting.o lib/enhanced_multipath.o lib/openinframap_data_source.o lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o lib/radio_model_string_impl.o lib/radio_model_hf_impl.o lib/radio_model_amateur_impl.o lib/radio_model_uhf_impl.o fgcom-mumble-tools-stub.o test/geotest.cpp $(CFLAGS_WIN) -static-libgcc -static-libstdc++ -lcurl
	$(CC) -o test/frqtest.exe lib/radio_model.o lib/audio.o lib/amateur_radio.o lib/solar_data.o lib/power_management.o lib/frequency_offset.o lib/atmospheric_noise.o lib/noise_floor_utils.o lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/propagation_physics.o lib/radio_config.o lib/atmospheric_ducting.o lib/enhanced_multipath.o lib/openinframap_data_source.o lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o lib/radio_model_string_impl.o lib/radio_model_hf_impl.o lib/radio_model_amateur_impl.o lib/radio_model_uhf_impl.o fgcom-mumble-tools-stub.o test/frqtest.cpp $(CFLAGS_WIN) -static-libgcc -static-libstdc++ -lcurl

# Build Windows object files
libs-win64: CC=x86_64-w64-mingw32-g++-posix
libs-win64: $(lib_OBJS)

# Build Windows stub
tools-win64-stub: CC=x86_64-w64-mingw32-g++-posix
tools-win64-stub:
	$(CC) -fPIC -c -o fgcom-mumble-tools-stub.o fgcom-mumble-tools-stub.cpp $(CFLAGS_WIN) -DMINGW_WIN64

# build win64 plugin-dll and openssl
plugin-win64: openssl-win plugin-win64-only

plugin-win32: openssl-win32 plugin-win32-only

# just the windows plugin, no ssl in case we want to build repetively but want to avoid building openssl each time
plugin-win64-only: outname=fgcom-mumble.dll
plugin-win64-only: mingwprefix=x86_64-w64-mingw32-
plugin-win64-only: CC=$(mingwprefix)g++-posix
plugin-win64-only: plugin-win-dllresource libs-win64
	# Build plugin win64 with all library object files
	$(CC) -fPIC --shared -DMINGW_WIN64 -o $(outname) dllResource.o $(lib_OBJS) fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN) -lcurl

plugin-win32-only: outname=fgcom-mumble-x86_32.dll
plugin-win32-only: mingwprefix=i686-w64-mingw32-
plugin-win32-only: CC=$(mingwprefix)g++-posix
plugin-win32-only: plugin-win-dllresource libs-win32
	# Build plugin win32 with all library object files
	$(CC) -m32 -fPIC --shared -DMINGW_WIN32 -o $(outname) dllResource.o $(lib_OBJS) fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN) -lcurl

# Build Windows 32-bit object files
libs-win32: CC=i686-w64-mingw32-g++-posix
libs-win32: $(lib_OBJS)

GITVER:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
PLUGIN_VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH fgcom-mumble.h |grep -E -o '[0-9]+')
plugin-win-dllresource:
	# Build DLL resource file
	@echo "1 VERSIONINFO" > dllResource.rc
	@echo "FILEVERSION     $(PLUGIN_VERSION_V),$(PLUGIN_VERSION_M),$(PLUGIN_VERSION_P),0" >> dllResource.rc
	@echo "PRODUCTVERSION  $(PLUGIN_VERSION_V),$(PLUGIN_VERSION_M),$(PLUGIN_VERSION_P),0" >> dllResource.rc
	@echo "BEGIN" >> dllResource.rc
	@echo "  BLOCK \"StringFileInfo\"" >> dllResource.rc
	@echo "  BEGIN" >> dllResource.rc
	@echo "    BLOCK \"040904E4\"" >> dllResource.rc
	@echo "    BEGIN" >> dllResource.rc
	@echo "      VALUE \"CompanyName\", \"B. Hallinger (https://github.com/hbeni/fgcom-mumble)\"" >> dllResource.rc
	@echo "      VALUE \"Comments\", \"Project page: https://github.com/hbeni/fgcom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"FileDescription\", \"FGCom-mumble plugin for Mumble\"" >> dllResource.rc
	@echo "      VALUE \"FileVersion\", \"$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)\"" >> dllResource.rc
	@echo "      VALUE \"InternalName\", \"fgcom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"LegalCopyright\", \"(c) B. Hallinger, GPLv3 license\"" >> dllResource.rc
	@echo "      VALUE \"OriginalFilename\", \"$(outname)\"" >> dllResource.rc
	@echo "      VALUE \"ProductName\", \"FGCom-mumble\"" >> dllResource.rc
	@echo "      VALUE \"ProductVersion\", \"$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)\"" >> dllResource.rc
	@echo "      VALUE \"LastChange\", \"$(GITDATE) ($(GITVER))\"" >> dllResource.rc
	@echo "    END" >> dllResource.rc
	@echo "  END" >> dllResource.rc
	@echo "  BLOCK \"VarFileInfo\"" >> dllResource.rc
	@echo "  BEGIN" >> dllResource.rc
	@echo "    VALUE \"Translation\", 0x409, 1252" >> dllResource.rc
	@echo "  END" >> dllResource.rc
	@echo "END" >> dllResource.rc
	$(mingwprefix)windres dllResource.rc dllResource.o

# shortcut for building natively on macOS
plugin-macOS: CC=g++
plugin-macOS: outname=fgcom-mumble-macOS.bundle
plugin-macOS: openssl-macOS
	make CC=$(CC) outname=$(outname) CFLAGS+="-std=c++17 -arch x86_64 -arch arm64 -mmacosx-version-min=10.13" plugin

# OpenSSL
# The sources are located under lib/openssl as git submodule, and supposed to point to the latest stable head
# Info on configure options: https://wiki.openssl.org/index.php/Compilation_and_Installation
openssl-win: openSSLBuildOpts=mingw64 -static
openssl-win: openSSLCrossCompileOpts=--cross-compile-prefix=x86_64-w64-mingw32-
openssl-win: openssl

openssl-win32: openSSLBuildOpts=mingw -static
openssl-win32: openSSLCrossCompileOpts=--cross-compile-prefix=i686-w64-mingw32-
openssl-win32: openssl

openssl-macOS:
ifdef SSLFLAGS
	@echo "BUILD OpenSSL"
	git submodule init
	git submodule update
	cd lib/openssl/ && git reset --hard

	# Create separate build directories for arm64 and x86_64, since openssl's configure doesn't support universal binaries out of the box
	mkdir -p lib/openssl/build_arm64
	mkdir -p lib/openssl/build_x86_64

	# Build for arm64
	cd lib/openssl && \
	CFLAGS="-arch arm64" ./Configure darwin64-arm64-cc no-shared no-weak-ssl-ciphers no-ssl3 no-idea no-dtls1 && \
	make clean && make -j4 && \
	cp libcrypto.a build_arm64/libcrypto.a && cp libssl.a build_arm64/libssl.a

	# Build for x86_64
	cd lib/openssl && \
	make distclean && \
	CFLAGS="-arch x86_64" ./Configure darwin64-x86_64-cc no-shared no-weak-ssl-ciphers no-ssl3 no-idea no-dtls1 && \
	make clean && make -j4 && \
	cp libcrypto.a build_x86_64/libcrypto.a && cp libssl.a build_x86_64/libssl.a

	# Merge into universal binaries
	lipo -create \
		lib/openssl/build_arm64/libssl.a \
		lib/openssl/build_x86_64/libssl.a \
		-output lib/openssl/libssl.a

	lipo -create \
		lib/openssl/build_arm64/libcrypto.a \
		lib/openssl/build_x86_64/libcrypto.a \
		-output lib/openssl/libcrypto.a
else
	@echo "Skipping building OpenSSL"
endif

openssl:
ifdef SSLFLAGS
	@echo "BUILD OpenSSL"
	git submodule init
	git submodule update
	cd lib/openssl/ && git reset --hard
	cd lib/openssl/ && ./Configure $(openSSLBuildOpts) no-pinshared no-weak-ssl-ciphers no-ssl3 no-idea no-dtls1 $(openSSLCrossCompileOpts) && make clean && make -j4
else
	@echo "Skipping building OpenSSL"
endif

# Test band segments CSV loading
test-band-segments: test/test_band_segments_csv.cpp lib/amateur_radio.o
	$(CC) $(CFLAGS) -o test_band_segments_csv test/test_band_segments_csv.cpp lib/amateur_radio.o
	./test_band_segments_csv
	rm -f test_band_segments_csv

test-preset-channels: test/test_preset_channels_simple.cpp lib/preset_channel_api.o lib/nato_vhf_equipment.o
	$(CC) $(CFLAGS) -o test_preset_channels test/test_preset_channels_simple.cpp lib/preset_channel_api.o lib/nato_vhf_equipment.o
	./test_preset_channels
	rm -f test_preset_channels

test-terrain-compliance: test/test_terrain_api_compliance.cpp lib/terrain_state_machine.o lib/terrain_data_access.o lib/terrain_cache.o lib/terrain_statistics.o lib/terrain_environmental_api.o
	$(CC) $(CFLAGS) -o test_terrain_compliance test/test_terrain_api_compliance.cpp lib/terrain_state_machine.o lib/terrain_data_access.o lib/terrain_cache.o lib/terrain_statistics.o lib/terrain_environmental_api.o $(THREADS_UNIX)
	./test_terrain_compliance
	rm -f test_terrain_compliance
