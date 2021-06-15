GITVER:=$(shell git log -1 --pretty=format:"%h")
GITDATE:=$(shell git log -1 --pretty=format:"%cd" --date=short)
PLUGIN_VERSION_V:=$(shell grep -m1 FGCOM_VERSION_MAJOR client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_M:=$(shell grep -m1 FGCOM_VERSION_MINOR client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGIN_VERSION_P:=$(shell grep -m1 FGCOM_VERSION_PATCH client/mumble-plugin/fgcom-mumble.h |grep -E -o '[0-9]+')
PLUGINVER:=$(PLUGIN_VERSION_V).$(PLUGIN_VERSION_M).$(PLUGIN_VERSION_P)
RADIOGUIVER := $(shell grep "VERSION of the Application" client/radioGUI/pom.xml | sed 's/\s*<\/\?version>//g' | sed 's/\s*<!.*$\//')
FGFSADDONVER:= $(shell grep -i '<version.*>.*</version>' client/fgfs-addon/addon-metadata.xml |sed 's/\s*<.*>\(.*\)<.*>\s*/\1/g')

# make a final release distribution file set
release:
	$(MAKE) build
	$(MAKE) bundle
	$(MAKE) package

# build the binary stuff
build: build-plugin build-server build-radioGUI build-fgcom-addon

# bundle component's zip packages
bundle: bundle-plugin bundle-server bundle-radioGUI bundle-fgcom-addon

# package up everything already built into a single release client zip
package:
	# Generate combined release zip files
	rm -rf fgcom-mumble-$(PLUGINVER)/
	mkdir fgcom-mumble-$(PLUGINVER)/
	
	# Add docs
	cp LICENSE Readme.architecture.md fgcom-mumble-$(PLUGINVER)/
	head -n 1 README.md > fgcom-mumble-$(PLUGINVER)/README.md
	@echo Version: $(PLUGINVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/README.md
	tail +2 README.md >> fgcom-mumble-$(PLUGINVER)/README.md
	head -n 1 README-de_DE.md > fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	@echo Version: $(PLUGINVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	tail +2 README-de_DE.md >> fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	
	# Adjust markdown links in readmes
	sed -i 's?](client/?](?' fgcom-mumble-$(PLUGINVER)/Readme.architecture.md
	sed -i 's?\[server/Readme.server.md\](server/Readme.server.md)?Readme.server.md (not included)?' fgcom-mumble-$(PLUGINVER)/README.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (not included)?' fgcom-mumble-$(PLUGINVER)/README.md
	sed -i 's?\[server/Readme.server-de_DE.md\](server/Readme.server-de_DE.md)?Readme.server.md (nicht enthalten)?' fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (nicht enthalten)?' fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?](client/?](?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?](server/?](?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[client/?[?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[server/?[?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	
	# Add mumble plugin bundle
	mkdir fgcom-mumble-$(PLUGINVER)/mumble-plugin
	cp fgcom-mumble-$(PLUGINVER).mumble_plugin fgcom-mumble-$(PLUGINVER)/mumble-plugin/
	cp client/mumble-plugin/fgcom-mumble.ini fgcom-mumble-$(PLUGINVER)/mumble-plugin/
	cp client/plugin.spec.md fgcom-mumble-$(PLUGINVER)/mumble-plugin/
	sed -i 's?](../?](?' fgcom-mumble-$(PLUGINVER)/mumble-plugin/plugin.spec.md
	
	# Add radioGUI
	mkdir fgcom-mumble-$(PLUGINVER)/radioGUI
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-$(PLUGINVER)/radioGUI/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	@echo Version: $(RADIOGUIVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	
	# Add FlightGear-Addon
	cp -r client/fgfs-addon/ fgcom-mumble-$(PLUGINVER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	@echo Version: $(FGFSADDONVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	
	
	# package release
	zip -r fgcom-mumble-$(PLUGINVER).zip fgcom-mumble-$(PLUGINVER)/
	rm -rf fgcom-mumble-$(PLUGINVER)/
	
	# print some summary
	@echo "\nRelease $(PLUGINVER) built successfully:"
	@echo "GITVER:       $(GITVER) $(GITDATE)"
	@echo "PLUGINVER:    $(PLUGINVER)"
	@echo "RADIOGUIVER:  $(RADIOGUIVER)"
	@echo "FGFSADDONVER: $(FGFSADDONVER)"
	@ls -alh fgcom-mumble-$(PLUGINVER)*.zip fgcom-mumble-$(PLUGINVER).mumble_plugin fgcom-mumble-server-*$(PLUGINVER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUIVER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDONVER)*.zip
	@md5sum  fgcom-mumble-$(PLUGINVER)*.zip fgcom-mumble-$(PLUGINVER).mumble_plugin fgcom-mumble-server-*$(PLUGINVER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUIVER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDONVER)*.zip


bundle-plugin:
	# Build mumble_plugin bundle from available binary builds
	# Format is described here: https://github.com/mumble-voip/mumble/blob/master/docs/dev/plugins/Bundling.md
	rm -rf fgcom-mumble-plugin-bundle
	mkdir fgcom-mumble-plugin-bundle
	
	# generate manifest header
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > fgcom-mumble-plugin-bundle/manifest.xml
	@echo '<bundle version="1.0.0">' >> fgcom-mumble-plugin-bundle/manifest.xml
	@echo '  <name>FGCom-Mumble</name>' >> fgcom-mumble-plugin-bundle/manifest.xml
	@echo "  <version>$(PLUGINVER)</version>" >> fgcom-mumble-plugin-bundle/manifest.xml
	
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
	@echo '    <plugin os="macos" arch="x64">fgcom-mumble-macOS.bundle</plugin>' >> fgcom-mumble-plugin-bundle/manifest.xml
endif
	@echo '  </assets>' >> fgcom-mumble-plugin-bundle/manifest.xml
	
	# generate manifest footer
	@echo '</bundle>' >> fgcom-mumble-plugin-bundle/manifest.xml
	
	# bundle up everything
	zip --junk-paths fgcom-mumble-$(PLUGINVER).mumble_plugin fgcom-mumble-plugin-bundle/*
	
	# cleanup
	rm -rf fgcom-mumble-plugin-bundle
	@echo "\nPluginbundle $(PLUGINVER) built successfully:"
	@ls -alh fgcom-mumble-$(PLUGINVER).mumble_plugin
	@md5sum fgcom-mumble-$(PLUGINVER).mumble_plugin


bundle-server:
	# Build server components release
	mkdir fgcom-mumble-server-$(PLUGINVER)
	mkdir fgcom-mumble-server-$(PLUGINVER)/recordings
	cp LICENSE fgcom-mumble-server-$(PLUGINVER)
	cp server/recordings/readme.md server/recordings/fgcom.rec.testsample.fgcs fgcom-mumble-server-$(PLUGINVER)/recordings
	head -n 1 server/Readme.server.md > fgcom-mumble-server-$(PLUGINVER)/README.md
	@echo Version: $(PLUGINVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-server-$(PLUGINVER)/README.md
	tail +2 server/Readme.server.md >> fgcom-mumble-server-$(PLUGINVER)/README.md
	cp -r server/statuspage/ fgcom-mumble-server-$(PLUGINVER)
	mv fgcom-mumble-server-$(PLUGINVER)/statuspage/Readme.statuspage.md fgcom-mumble-server-$(PLUGINVER)
	cp server/Readme.server-de_DE.md fgcom-mumble-server-$(PLUGINVER)/
	cp server/fgcom-botmanager.sh server/*.bot.lua fgcom-mumble-server-$(PLUGINVER)
	sed '/^\s\+gitver/s/""/"$(GITVER) $(GITDATE)"/' server/sharedFunctions.inc.lua > fgcom-mumble-server-$(PLUGINVER)/sharedFunctions.inc.lua
	zip -r fgcom-mumble-server-$(PLUGINVER).zip fgcom-mumble-server-$(PLUGINVER)
	rm -rf fgcom-mumble-server-$(PLUGINVER)

bundle-radioGUI:
	# package radioGUI
	mkdir fgcom-mumble-radioGUI-$(RADIOGUIVER)
	cp LICENSE fgcom-mumble-radioGUI-$(RADIOGUIVER)
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-radioGUI-$(RADIOGUIVER)/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	@echo Version: $(RADIOGUIVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	zip -r fgcom-mumble-radioGUI-$(RADIOGUIVER).zip fgcom-mumble-radioGUI-$(RADIOGUIVER)
	rm -rf fgcom-mumble-radioGUI-$(RADIOGUIVER)

bundle-fgcom-addon:
	# package FlightGear-Addon
	cp -r client/fgfs-addon/ fgcom-mumble-fgfs-addon-$(FGFSADDONVER)
	cp LICENSE fgcom-mumble-fgfs-addon-$(FGFSADDONVER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	@echo Version: $(FGFSADDONVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	zip -r fgcom-mumble-fgfs-addon-$(FGFSADDONVER).zip fgcom-mumble-fgfs-addon-$(FGFSADDONVER)
	rm -rf fgcom-mumble-fgfs-addon-$(FGFSADDONVER)



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
	cd client/radioGUI/lib/jsimconnect && mvn clean package
	mvn install:install-file -Dfile=client/radioGUI/lib/jsimconnect/target/jsimconnect-0.8.0.jar \
		-DgroupId=flightsim \
		-DartifactId=jsimconnect \
		-Dversion=0.8.0 \
		-Dpackaging=jar
	cd client/radioGUI/ && mvn clean animal-sniffer:check package


showVer:
	@echo "GITCOMMIT:$(GITVER)"
	@echo "GITDATE:$(GITDATE)"
	@echo "PLUGIN:$(PLUGINVER)"
	@echo "RADIOGUI:$(RADIOGUIVER)"
	@echo "FGFSADDON:$(FGFSADDONVER)"

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target '$@' undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
