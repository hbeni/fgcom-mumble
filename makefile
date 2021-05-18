GITVER      := $(shell make -C client/mumble-plugin/ showVer |grep GITCOMMIT |cut -d: -f2)
GITDATE     := $(shell make -C client/mumble-plugin/ showVer |grep GITDATE |cut -d: -f2)
PLUGINVER   := $(shell make -C client/mumble-plugin/ showVer |grep VER |cut -d: -f2)
RADIOGUIVER := $(shell grep "VERSION of the Application" client/radioGUI/pom.xml | sed 's/\s*<\/\?version>//g' | sed 's/\s*<!.*$\//')
FGFSADDONVER:= $(shell grep -i '<version.*>.*</version>' client/fgfs-addon/addon-metadata.xml |sed 's/\s*<.*>\(.*\)<.*>\s*/\1/g')

release: build package

build: release-plugin release-server release-radioGUI release-fgcom-addon

package:
	# Generate combined release zip files
	cp client/mumble-plugin/*.zip .
	
	# unzip and build new release tree
	unzip fgcom-mumble-client-$(PLUGINVER).zip
	rm fgcom-mumble-client-$(PLUGINVER).zip
	mv fgcom-mumble-client-$(PLUGINVER) fgcom-mumble-$(PLUGINVER)
	
	# combine radio gui into release
	mkdir fgcom-mumble-$(PLUGINVER)/radioGUI
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-$(PLUGINVER)/radioGUI/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	@echo Version: $(RADIOGUIVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-$(PLUGINVER)/radioGUI/Readme.RadioGUI.md
	
	# combine FlightGear-Addon into release
	cp -r client/fgfs-addon/ fgcom-mumble-$(PLUGINVER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	@echo Version: $(FGFSADDONVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-$(PLUGINVER)/fgfs-addon/Readme.md
	
	# Adjust markdown links in readmes
	sed -i 's?](../?](?'     fgcom-mumble-$(PLUGINVER)/plugin.spec.md
	sed -i 's?](client/?](?' fgcom-mumble-$(PLUGINVER)/Readme.architecture.md
	sed -i 's?\[server/Readme.server.md\](server/Readme.server.md)?Readme.server.md (not included)?' fgcom-mumble-$(PLUGINVER)/README.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (not included)?' fgcom-mumble-$(PLUGINVER)/README.md
	sed -i 's?\[server/Readme.server-de_DE.md\](server/Readme.server-de_DE.md)?Readme.server.md (nicht enthalten)?' fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[server/statuspage/Readme.statuspage.md\](server/statuspage/Readme.statuspage.md)?Readme.statuspage.md (nicht enthalten)?' fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?](client/?](?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?](server/?](?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[client/?[?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	sed -i 's?\[server/?[?' fgcom-mumble-$(PLUGINVER)/README.md fgcom-mumble-$(PLUGINVER)/README-de_DE.md
	
	# repackage release
	zip -r fgcom-mumble-$(PLUGINVER).zip fgcom-mumble-$(PLUGINVER)/
	rm -rf fgcom-mumble-$(PLUGINVER)/
	
	# print some summary
	@echo "\nRelease $(PLUGINVER) built successfully:"
	@echo "GITVER:       $(GITVER) $(GITDATE)"
	@echo "PLUGINVER:    $(PLUGINVER)"
	@echo "RADIOGUIVER:  $(RADIOGUIVER)"
	@echo "FGFSADDONVER: $(FGFSADDONVER)"
	@ls -alh fgcom-mumble-$(PLUGINVER)*.zip fgcom-mumble-server-*$(PLUGINVER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUIVER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDONVER)*.zip
	@md5sum fgcom-mumble-$(PLUGINVER)*.zip fgcom-mumble-server-*$(PLUGINVER)*.zip fgcom-mumble-radioGUI-*$(RADIOGUIVER)*.zip fgcom-mumble-fgfs-addon-*$(FGFSADDONVER)*.zip

release-plugin:
	# Delegate build plugin release
	$(MAKE) -C client/mumble-plugin/ release

release-server:
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

release-radioGUI: radioGUI
	mkdir fgcom-mumble-radioGUI-$(RADIOGUIVER)
	cp LICENSE fgcom-mumble-radioGUI-$(RADIOGUIVER)
	cp client/radioGUI/target/FGCom-mumble-radioGUI-*-jar-with-dependencies.jar fgcom-mumble-radioGUI-$(RADIOGUIVER)/FGCom-mumble-radioGUI.jar
	head -n 1 client/radioGUI/Readme.RadioGUI.md > fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	@echo Version: $(RADIOGUIVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	tail +2 client/radioGUI/Readme.RadioGUI.md >> fgcom-mumble-radioGUI-$(RADIOGUIVER)/Readme.RadioGUI.md
	zip -r fgcom-mumble-radioGUI-$(RADIOGUIVER).zip fgcom-mumble-radioGUI-$(RADIOGUIVER)
	rm -rf fgcom-mumble-radioGUI-$(RADIOGUIVER)

radioGUI:
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

release-fgcom-addon:
	# package FlightGear-Addon
	cp -r client/fgfs-addon/ fgcom-mumble-fgfs-addon-$(FGFSADDONVER)
	head -n 1 client/fgfs-addon/Readme.md > fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	@echo Version: $(FGFSADDONVER) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	tail +2 client/fgfs-addon/Readme.md >> fgcom-mumble-fgfs-addon-$(FGFSADDONVER)/Readme.md
	zip -r fgcom-mumble-fgfs-addon-$(FGFSADDONVER).zip fgcom-mumble-fgfs-addon-$(FGFSADDONVER)
	rm -rf fgcom-mumble-fgfs-addon-$(FGFSADDONVER)

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
