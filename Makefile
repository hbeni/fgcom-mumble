
# Version ID for generated release bundles
#   note: set this to the releases package version (at least version of the most recent subcomponent)
BUNDLE_VER:=1.3.1

# Build configuration options
# Set to 'false' to skip jsimconnect dependency (useful for clients that don't need MSFS2020 integration)
ENABLE_JSIMCONNECT:=true


# The subpackages versions are sourced from there
GITVER:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
PLUGIN_VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VER:=$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)
SERVER_VER:= $(shell grep VERSION server/VERSION | cut -d" " -f2)
RADIOGUI_VER := $(shell grep "VERSION of the Application" client/radioGUI/pom.xml | sed 's/\s*<\/\?version>//g' | sed 's/\s*<!.*$\//')
FGFSADDON_VER:= $(shell grep -i '<version.*>.*</version>' client/fgfs-addon/addon-metadata.xml |sed 's/\s*<.*>\(.*\)<.*>\s*/\1/g')



# make a final release distribution file set
release:
	$(MAKE) build
	$(MAKE) bundle
	$(MAKE) package

# build the binary stuff
build: build-plugin build-server build-radioGUI build-fgcom-addon

# build for headless server (no GUI components)
build-headless: build-plugin build-server build-fgcom-addon

# bundle component's zip packages
bundle: bundle-plugin bundle-server bundle-radioGUI bundle-fgcom-addon

# bundle for headless server (no GUI components)
bundle-headless: bundle-plugin bundle-server bundle-fgcom-addon

# package up everything already built into a single release client zip
package:
	# Generate combined release zip files
	rm -rf fgcom-mumble-$(BUNDLE_VER)/
	mkdir fgcom-mumble-$(BUNDLE_VER)/
	
	# Add docs
	cp LICENSE config/Readme.architecture.md fgcom-mumble-$(BUNDLE_VER)/
	head -n 1 config/README.md > fgcom-mumble-$(BUNDLE_VER)/README.md
	@echo Version: $(BUNDLE_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(BUNDLE_VER)/README.md
	tail +2 config/README.md >> fgcom-mumble-$(BUNDLE_VER)/README.md
	head -n 1 config/README-de_DE.md > fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	@echo Version: $(BUNDLE_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	tail +2 config/README-de_DE.md >> fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	
	# Adjust markdown links in readmes
	sed -i 's?](client/?](?' fgcom-mumble-$(BUNDLE_VER)/Readme.architecture.md
	sed -i 's?\[server/Readme.server.md\](server/Readme.server.md)?Readme.server.md (not included)?' fgcom-mumble-$(BUNDLE_VER)/README.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (not included)?' fgcom-mumble-$(BUNDLE_VER)/README.md
	sed -i 's?\[server/Readme.server-de_DE.md\](server/Readme.server-de_DE.md)?Readme.server.md (nicht enthalten)?' fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (nicht enthalten)?' fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	sed -i 's?](client/?](?' fgcom-mumble-$(BUNDLE_VER)/README.md fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	sed -i 's?](server/?](?' fgcom-mumble-$(BUNDLE_VER)/README.md fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	sed -i 's?\[client/?[?' fgcom-mumble-$(BUNDLE_VER)/README.md fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	sed -i 's?\[server/?[?' fgcom-mumble-$(BUNDLE_VER)/README.md fgcom-mumble-$(BUNDLE_VER)/README-de_DE.md
	
	# Add mumble plugin bundle
	mkdir fgcom-mumble-$(BUNDLE_VER)/mumble-plugin
	cp fgcom-mumble-$(PLUGIN_VER).mumble_plugin fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/
	cp configs/fgcom-mumble.ini fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/
	head -n 1 client/plugin.spec.md > fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/plugin.spec.md
	@echo Version: $(PLUGIN_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/plugin.spec.md
	tail +2 client/plugin.spec.md >> fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/plugin.spec.md
	sed -i 's?](../?](?' fgcom-mumble-$(BUNDLE_VER)/mumble-plugin/plugin.spec.md
	
	# Add radioGUI
	mkdir fgcom-mumble-$(BUNDLE_VER)/radioGUI
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-$(BUNDLE_VER)/radioGUI/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-$(BUNDLE_VER)/radioGUI/Readme.RadioGUI.md
	@echo Version: $(RADIOGUI_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(BUNDLE_VER)/radioGUI/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-$(BUNDLE_VER)/radioGUI/Readme.RadioGUI.md
	
	# Add FlightGear-Addon
	cp -r client/fgfs-addon/ fgcom-mumble-$(BUNDLE_VER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-$(BUNDLE_VER)/fgfs-addon/Readme.md
	@echo Version: $(FGFSADDON_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(BUNDLE_VER)/fgfs-addon/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-$(BUNDLE_VER)/fgfs-addon/Readme.md
	
	
	# package release
	zip -r fgcom-mumble-$(BUNDLE_VER).zip fgcom-mumble-$(BUNDLE_VER)/
	rm -rf fgcom-mumble-$(BUNDLE_VER)/
	
	# print some summary
	@echo "\nRelease $(BUNDLE_VER) built successfully:"
	@echo "GITVER:       $(GITVER) $(GITDATE)"
	@echo "PLUGIN_VER:    $(PLUGIN_VER)"
	@echo "SERVER:       $(SERVER_VER)"
	@echo "RADIOGUI_VER:  $(RADIOGUI_VER)"
	@echo "FGFSADDON_VER: $(FGFSADDON_VER)"
	@ls -alh fgcom-mumble-$(BUNDLE_VER)*.zip fgcom-mumble-$(PLUGIN_VER).mumble_plugin fgcom-mumble-server-*$(SERVER_VER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUI_VER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDON_VER)*.zip
	@md5sum  fgcom-mumble-$(BUNDLE_VER)*.zip fgcom-mumble-$(PLUGIN_VER).mumble_plugin fgcom-mumble-server-*$(SERVER_VER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUI_VER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDON_VER)*.zip


bundle-plugin:
	# Build mumble_plugin bundle from available binary builds
	# Format is described here: https://github.com/mumble-voip/mumble/blob/master/docs/dev/plugins/Bundling.md
	rm -rf fgcom-mumble-plugin-bundle
	mkdir fgcom-mumble-plugin-bundle
	
	# generate manifest header
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > fgcom-mumble-plugin-bundle/manifest.xml
	@echo '<bundle version="1.0.0">' >> fgcom-mumble-plugin-bundle/manifest.xml
	@echo '  <name>FGCom-Mumble</name>' >> fgcom-mumble-plugin-bundle/manifest.xml
	@echo "  <version>$(PLUGIN_VER)</version>" >> fgcom-mumble-plugin-bundle/manifest.xml
	
	# add binary plugin assets and deploy them
	@echo '  <assets>' >> fgcom-mumble-plugin-bundle/manifest.xml
ifneq (,$(wildcard client/mumble-plugin/fgcom-mumble.so))
	cp client/mumble-plugin/fgcom-mumble.so fgcom-mumble-plugin-bundle/
	@echo '    <plugin os="linux" arch="x64">fgcom-mumble.so</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
endif
ifneq (,$(wildcard client/mumble-plugin/fgcom-mumble.dll))
	cp client/mumble-plugin/fgcom-mumble.dll fgcom-mumble-plugin-bundle/
	@echo '    <plugin os="windows" arch="x64">fgcom-mumble.dll</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
endif
ifneq (,$(wildcard client/mumble-plugin/fgcom-mumble-x86_32.dll))
	cp client/mumble-plugin/fgcom-mumble-x86_32.dll fgcom-mumble-plugin-bundle/
	@echo '    <plugin os="windows" arch="x86">fgcom-mumble-x86_32.dll</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
endif
ifneq (,$(wildcard client/mumble-plugin/fgcom-mumble-macOS.bundle))
	cp client/mumble-plugin/fgcom-mumble-macOS.bundle fgcom-mumble-plugin-bundle/
	@echo '    <plugin os="macos" arch="arm64">fgcom-mumble-macOS.bundle</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
	@echo '    <plugin os="macos" arch="x86_64">fgcom-mumble-macOS.bundle</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
endif
	@echo '  </assets>' >> fgcom-mumble-plugin-bundle/manifest.xml
	
	# generate manifest footer
	@echo '</bundle>' >> fgcom-mumble-plugin-bundle/manifest.xml
	
	# bundle up everything
	zip --junk-paths fgcom-mumble-$(PLUGIN_VER).mumble_plugin fgcom-mumble-plugin-bundle/*
	
	# cleanup
	rm -rf fgcom-mumble-plugin-bundle
	@echo "\nPluginbundle $(PLUGIN_VER) built successfully:"
	@ls -alh fgcom-mumble-$(PLUGIN_VER).mumble_plugin
	@md5sum fgcom-mumble-$(PLUGIN_VER).mumble_plugin


bundle-server:
	# Build server components release
	mkdir fgcom-mumble-server-$(SERVER_VER)
	mkdir fgcom-mumble-server-$(SERVER_VER)/recordings
	cp LICENSE fgcom-mumble-server-$(SERVER_VER)
	cp server/recordings/readme.md server/recordings/fgcom.rec.testsample.fgcs fgcom-mumble-server-$(SERVER_VER)/recordings
	head -n 1 server/Readme.server.md > fgcom-mumble-server-$(SERVER_VER)/README.md
	@echo Version: $(SERVER_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-server-$(SERVER_VER)/README.md
	tail +2 server/Readme.server.md >> fgcom-mumble-server-$(SERVER_VER)/README.md
	cp -r server/statuspage/ fgcom-mumble-server-$(SERVER_VER)
	mv fgcom-mumble-server-$(SERVER_VER)/statuspage/Readme.statuspage.md fgcom-mumble-server-$(SERVER_VER)
	cp server/Readme.server-de_DE.md fgcom-mumble-server-$(SERVER_VER)/
	cp server/fgcom-botmanager.sh server/*.bot.lua fgcom-mumble-server-$(SERVER_VER)
	sed '/^\s\+gitver/s/""/"$(GITVER) $(GITDATE)"/' server/fgcom-sharedFunctions.inc.lua > fgcom-mumble-server-$(SERVER_VER)/fgcom-sharedFunctions.inc.lua
	zip -r fgcom-mumble-server-$(SERVER_VER).zip fgcom-mumble-server-$(SERVER_VER)
	rm -rf fgcom-mumble-server-$(SERVER_VER)

bundle-radioGUI:
	# package radioGUI
	mkdir fgcom-mumble-radioGUI-$(RADIOGUI_VER)
	cp LICENSE fgcom-mumble-radioGUI-$(RADIOGUI_VER)
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-radioGUI-$(RADIOGUI_VER)/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-radioGUI-$(RADIOGUI_VER)/Readme.RadioGUI.md
	@echo Version: $(RADIOGUI_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-radioGUI-$(RADIOGUI_VER)/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-radioGUI-$(RADIOGUI_VER)/Readme.RadioGUI.md
	zip -r fgcom-mumble-radioGUI-$(RADIOGUI_VER).zip fgcom-mumble-radioGUI-$(RADIOGUI_VER)
	rm -rf fgcom-mumble-radioGUI-$(RADIOGUI_VER)

bundle-fgcom-addon:
	# package FlightGear-Addon
	cp -r client/fgfs-addon/ fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)
	cp LICENSE fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)/Readme.md
	@echo Version: $(FGFSADDON_VER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)/Readme.md
	zip -r fgcom-mumble-fgfs-addon-$(FGFSADDON_VER).zip fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)
	rm -rf fgcom-mumble-fgfs-addon-$(FGFSADDON_VER)



build-plugin:
	# Plugin: delegate build
	$(MAKE) -C client/mumble-plugin/ clean plugin
	
build-server:
	# Server: nothing to build so far

build-fgcom-addon:
	# FGFS-Addon: nothing to build so far

build-radioGUI:
	# Build radio gui with maven
	mvn install:install-file -Dfile=client/radioGUI/lib/jmapviewer-2.9/JMapViewer.jar \
		-DgroupId=org.openstreetmap.jmapviewer \
		-DartifactId=jmapviewer \
		-Dversion=2.14 \
		-Dpackaging=jar
ifeq ($(ENABLE_JSIMCONNECT),true)
	# Build and install jsimconnect if enabled
	cd client/radioGUI/lib/jsimconnect && mvn clean package
	mvn install:install-file -Dfile=client/radioGUI/lib/jsimconnect/target/jsimconnect-0.8.0.jar \
		-DgroupId=flightsim \
		-DartifactId=jsimconnect \
		-Dversion=0.8.0 \
		-Dpackaging=jar
	@echo "Building radioGUI with jsimconnect support..."
else
	@echo "Building radioGUI without jsimconnect (MSFS2020 integration disabled)..."
endif
	cd client/radioGUI/ && mvn clean animal-sniffer:check package -Denable.jsimconnect=$(ENABLE_JSIMCONNECT)

# Convenience targets for building with/without jsimconnect
build-radioGUI-with-jsimconnect:
	$(MAKE) build-radioGUI ENABLE_JSIMCONNECT=true

build-radioGUI-without-jsimconnect:
	$(MAKE) build-radioGUI ENABLE_JSIMCONNECT=false

showVer:
	@echo "GITCOMMIT:$(GITVER)"
	@echo "GITDATE:$(GITDATE)"
	@echo "BUNDLE:$(BUNDLE_VER)"
	@echo "PLUGIN:$(PLUGIN_VER)"
	@echo "SERVER:$(SERVER_VER)"
	@echo "RADIOGUI:$(RADIOGUI_VER)"
	@echo "FGFSADDON:$(FGFSADDON_VER)"

clean:
	# cleanup packaging
	$(MAKE) -C client/mumble-plugin/ $@

install: build
	@echo "Installing FGCom-mumble components..."
	@mkdir -p $(DESTDIR)/usr/lib/mumble/plugins
	@mkdir -p $(DESTDIR)/usr/share/fgcom-mumble
	@mkdir -p $(DESTDIR)/usr/bin
	@mkdir -p $(DESTDIR)/etc/fgcom-mumble
	# Install mumble plugin
	@if [ -f client/mumble-plugin/fgcom-mumble.so ]; then \
		cp client/mumble-plugin/fgcom-mumble.so $(DESTDIR)/usr/lib/mumble/plugins/; \
		echo "Installed mumble plugin to $(DESTDIR)/usr/lib/mumble/plugins/"; \
	fi
	# Install radio GUI
	@if [ -f client/radioGUI/target/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar ]; then \
		cp client/radioGUI/target/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed radio GUI to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Install configuration files
	@if [ -d configs ]; then \
		cp -r configs/* $(DESTDIR)/etc/fgcom-mumble/; \
		echo "Installed configuration files to $(DESTDIR)/etc/fgcom-mumble/"; \
	fi
	# Install documentation
	@if [ -d docs ]; then \
		cp -r docs $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed documentation to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Install server components
	@if [ -d server ]; then \
		cp -r server $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed server components to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Install scripts
	@if [ -d scripts ]; then \
		cp -r scripts $(DESTDIR)/usr/share/fgcom-mumble/; \
		echo "Installed scripts to $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	@echo "Installation completed successfully!"

uninstall:
	@echo "Uninstalling FGCom-mumble components..."
	# Remove mumble plugin
	@if [ -f $(DESTDIR)/usr/lib/mumble/plugins/fgcom-mumble.so ]; then \
		rm -f $(DESTDIR)/usr/lib/mumble/plugins/fgcom-mumble.so; \
		echo "Removed mumble plugin from $(DESTDIR)/usr/lib/mumble/plugins/"; \
	fi
	# Remove radio GUI
	@if [ -f $(DESTDIR)/usr/share/fgcom-mumble/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar ]; then \
		rm -f $(DESTDIR)/usr/share/fgcom-mumble/fgcom-mumble-radioGUI-$(RADIOGUI_VER).jar; \
		echo "Removed radio GUI from $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Remove configuration files
	@if [ -d $(DESTDIR)/etc/fgcom-mumble ]; then \
		rm -rf $(DESTDIR)/etc/fgcom-mumble; \
		echo "Removed configuration files from $(DESTDIR)/etc/fgcom-mumble/"; \
	fi
	# Remove documentation
	@if [ -d $(DESTDIR)/usr/share/fgcom-mumble/docs ]; then \
		rm -rf $(DESTDIR)/usr/share/fgcom-mumble/docs; \
		echo "Removed documentation from $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Remove server components
	@if [ -d $(DESTDIR)/usr/share/fgcom-mumble/server ]; then \
		rm -rf $(DESTDIR)/usr/share/fgcom-mumble/server; \
		echo "Removed server components from $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Remove scripts
	@if [ -d $(DESTDIR)/usr/share/fgcom-mumble/scripts ]; then \
		rm -rf $(DESTDIR)/usr/share/fgcom-mumble/scripts; \
		echo "Removed scripts from $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	# Remove main share directory if empty
	@if [ -d $(DESTDIR)/usr/share/fgcom-mumble ] && [ -z "$$(ls -A $(DESTDIR)/usr/share/fgcom-mumble 2>/dev/null)" ]; then \
		rmdir $(DESTDIR)/usr/share/fgcom-mumble; \
		echo "Removed empty share directory $(DESTDIR)/usr/share/fgcom-mumble/"; \
	fi
	@echo "Uninstallation completed successfully!"

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target '$@' undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
