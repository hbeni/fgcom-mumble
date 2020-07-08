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
	mkdir server-$(PLUGINVER)
	mkdir server-$(PLUGINVER)/recordings
	cp server/recordings/readme.md server/recordings/fgcom.rec.testsample.fgcs server-$(PLUGINVER)/recordings
	head -n 1 server/Readme.server.md > server-$(PLUGINVER)/README.md
	@echo Version: $(VERSION) \($(GITVER) $(GITDATE)\) >> server-$(PLUGINVER)/README.md
	tail +2 server/Readme.server.md >> server-$(PLUGINVER)/README.md
	cp server/fgcom-botmanager.sh server/*.bot.lua server-$(PLUGINVER)
	zip -r server-$(PLUGINVER).zip server-$(PLUGINVER)
	rm -rf server-$(PLUGINVER)

# relay everything else to the mumble-plugin makefile
.DEFAULT:
	@echo "target undefined, using mumble-client makefile instead"
	$(MAKE) -C client/mumble-plugin/ $@
