GITVER    := $(shell make -C client/mumble-plugin/ showVer |grep GITCOMMIT |cut -d: -f2)
GITDATE   := $(shell make -C client/mumble-plugin/ showVer |grep GITDATE |cut -d: -f2)
PLUGINVER := $(shell make -C client/mumble-plugin/ showVer |grep VER |cut -d: -f2)

release: release-server
	@echo "This is just a convinience make to build packages"
	@echo "GITVER: $(GITVER)  PLUGINVER:$(PLUGINVER)"
	@echo "-------------------------------------------------"
	$(MAKE) -C client/mumble-plugin/ release
	cp client/mumble-plugin/*.tar.gz .
	cp client/mumble-plugin/*.zip .

release-server:
	# Build server components release
	mkdir fgcom-mumble-server-$(PLUGINVER)
	mkdir fgcom-mumble-server-$(PLUGINVER)/recordings
	cp server/recordings/readme.md server/recordings/fgcom.rec.testsample.fgcs fgcom-mumble-server-$(PLUGINVER)/recordings
	head -n 1 server/Readme.server.md > fgcom-mumble-server-$(PLUGINVER)/README.md
	@echo Version: $(VERSION) \($(GITVER) $(GITDATE)\) >> fgcom-mumble-server-$(PLUGINVER)/README.md
	tail +2 server/Readme.server.md >> fgcom-mumble-server-$(PLUGINVER)/README.md
	cp -r server/statuspage/ fgcom-mumble-server-$(PLUGINVER)
	mv fgcom-mumble-server-$(PLUGINVER)/statuspage/Readme.statuspage.md fgcom-mumble-server-$(PLUGINVER)
	cp server/Readme.server-de_DE.md fgcom-mumble-server-$(PLUGINVER)/
	cp server/fgcom-botmanager.sh server/*.bot.lua fgcom-mumble-server-$(PLUGINVER)
	sed '/^\s\+gitver/s/""/"$(GITVER) $(GITDATE)"/' server/sharedFunctions.inc.lua > fgcom-mumble-server-$(PLUGINVER)/sharedFunctions.inc.lua
	zip -r fgcom-mumble-server-$(PLUGINVER).zip fgcom-mumble-server-$(PLUGINVER)
	rm -rf fgcom-mumble-server-$(PLUGINVER)

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
