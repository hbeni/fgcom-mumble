GITVER      := $(shell make -C client/mumble-plugin/ showVer |grep GITCOMMIT |cut -d: -f2)
GITDATE     := $(shell make -C client/mumble-plugin/ showVer |grep GITDATE |cut -d: -f2)
PLUGINVER   := $(shell make -C client/mumble-plugin/ showVer |grep VER |cut -d: -f2)
RADIOGUIVER := $(shell grep "VERSION of the Application" client/radioGUI/pom.xml | sed 's/\s*<\/\?version>//g' | sed 's/\s*<!.*$\//')

release: release-server release-radioGUI
	@echo "This is just a convinience make to build packages"
	@echo "GITVER: $(GITVER)  PLUGINVER:$(PLUGINVER)"
	@echo "-------------------------------------------------"
	$(MAKE) -C client/mumble-plugin/ release
	mv client/mumble-plugin/*.zip .
	@echo "\nRelease $(PLUGINVER) built successfully:"
	@ls -alh *client*$(PLUGINVER)* *server*$(PLUGINVER)* *radioGUI*$(PLUGINVER)*
	@md5sum *client*$(PLUGINVER)* *server*$(PLUGINVER)* *radioGUI*$(PLUGINVER)*

release-server:
	# Build server components release
	mkdir fgcom-mumble-server-$(PLUGINVER)
	mkdir fgcom-mumble-server-$(PLUGINVER)/recordings
	cp LICENSE server/recordings/readme.md server/recordings/fgcom.rec.testsample.fgcs fgcom-mumble-server-$(PLUGINVER)/recordings
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
	cd client/radioGUI/ && mvn clean package

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
