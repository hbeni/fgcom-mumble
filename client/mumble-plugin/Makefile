.PHONY : all debug all-debug plugin-debug plugin libs test tools clean clean-all debug-on
CC=g++
DEBUG=
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

lib_OBJS := lib/radio_model.o lib/audio.o lib/io_plugin.o lib/io_UDPServer.o lib/io_UDPClient.o lib/garbage_collector.o lib/amateur_radio.o lib/solar_data.o lib/power_management.o lib/frequency_offset.o lib/atmospheric_noise.o lib/noise_floor_utils.o lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/propagation_physics.o lib/agc_squelch.o lib/agc_squelch_api.o lib/ctcss_system.o lib/terrain_elevation.o lib/preset_channel_api.o lib/soviet_vhf_equipment.o lib/nato_vhf_equipment.o lib/preset_channel_config_loader.o lib/radio_model_config_loader.o lib/gpu_resource_limiting.o lib/terrain_state_machine.o lib/terrain_data_access.o lib/terrain_cache.o lib/terrain_statistics.o lib/terrain_environmental_api.o lib/radio_config.o lib/atmospheric_ducting.o lib/enhanced_multipath.o lib/openinframap_data_source.o lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o

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

%.o : %.cpp
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(THREADS_UNIX)

# Compile testing tools
tools: libs
	$(CC) -o test/geotest lib/radio_model.o lib/audio.o lib/amateur_radio.o lib/solar_data.o lib/power_management.o lib/frequency_offset.o lib/atmospheric_noise.o lib/noise_floor_utils.o lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/propagation_physics.o lib/radio_config.o lib/atmospheric_ducting.o lib/enhanced_multipath.o lib/openinframap_data_source.o lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o test/geotest.cpp $(CFLAGS) -lcurl
	$(CC) -o test/frqtest lib/radio_model.o lib/audio.o lib/amateur_radio.o lib/solar_data.o lib/power_management.o lib/frequency_offset.o lib/atmospheric_noise.o lib/noise_floor_utils.o lib/pattern_interpolation.o lib/antenna_pattern_mapping.o lib/propagation_physics.o lib/radio_config.o lib/atmospheric_ducting.o lib/enhanced_multipath.o lib/openinframap_data_source.o lib/radio_model_vhf.o lib/radio_model_uhf.o lib/radio_model_aviation_hf.o lib/radio_model_maritime_hf.o lib/radio_model_config.o lib/non_amateur_hf.o test/frqtest.cpp $(CFLAGS) -lcurl
	$(CC) -o test/updater-test test/updater-test.cpp $(CFLAGS)
	


# catch2 unit tests linking against main
test: libs test/catch2/tests-main.o test/catch2/tests-main.o test/catch2/radioModelTest.o
	$(CC) -o test/catch2/radioModelTest.catch2 test/catch2/tests-main.o lib/radio_model.o lib/audio.o test/catch2/radioModelTest.o $(CFLAGS) && test/catch2/radioModelTest.catch2
# ^ add more

# clean compile results
clean:
	rm -f *.o *.rc lib/*.o test/catch2/*.catch2 test/catch2/*.o

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
tools-win64: CC=x86_64-w64-mingw32-g++-posix
tools-win64:
	$(CC) -o test/geotest.exe lib/radio_model.cpp lib/audio.cpp test/geotest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)
	$(CC) -o test/frqtest.exe lib/radio_model.cpp lib/audio.cpp test/frqtest.cpp -static-libgcc -static-libstdc++ $(CFLAGS)

# build win64 plugin-dll and openssl
plugin-win64: openssl-win plugin-win64-only

plugin-win32: openssl-win32 plugin-win32-only

# just the windows plugin, no ssl in case we want to build repetively but want to avoid building openssl each time
plugin-win64-only: outname=fgcom-mumble.dll
plugin-win64-only: mingwprefix=x86_64-w64-mingw32-
plugin-win64-only: CC=$(mingwprefix)g++-posix
plugin-win64-only: plugin-win-dllresource
	# Build plugin win64
	$(CC) -fPIC --shared -DMINGW_WIN64 -o $(outname) dllResource.o lib/io_plugin.cpp lib/radio_model.cpp lib/audio.cpp lib/io_UDPServer.cpp lib/io_UDPClient.cpp lib/garbage_collector.cpp fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN)

plugin-win32-only: outname=fgcom-mumble-x86_32.dll
plugin-win32-only: mingwprefix=i686-w64-mingw32-
plugin-win32-only: CC=$(mingwprefix)g++-posix
plugin-win32-only: plugin-win-dllresource
	# Build plugin win32
	$(CC) -m32 -fPIC --shared -DMINGW_WIN32 -o $(outname) dllResource.o lib/io_plugin.cpp lib/radio_model.cpp lib/audio.cpp lib/io_UDPServer.cpp lib/io_UDPClient.cpp lib/garbage_collector.cpp fgcom-mumble.cpp $(SSLFLAGS_WIN) $(CFLAGS_WIN) $(THREADS_WIN)

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
