FGCom mumble Radio GUI
===================================

The FGCom-mumble Radio GUI is a small Java Application that acts as client to the FGCom-mumble plugin and thus simulates radio stacks.


Install / Setup
----------------
In order to run the tool, you need a java runtime version >= 11.


Running and usage
-----------------
The Applicatin comes as executable JAR-Archive. Just start that in the usual java way (e.g. `java -jar FGCom-mumble-radioGUI-*.jar`).

After startup the GUI initializes with a default config (location, radio stack). Adjust that as needed and then hit the "connect" button to actually send data to the mumble plugin.

You can run several instances of the application at once to have different clients connecting to the same mumble plugin.


Compiling
-----------------
The client is written using netbeans, so you may just checkout the netbeans project file and build it with there.

Otherwise use maven:
```sh
apt-get install maven libmaven-jar-plugin-java
cd FGCom-mumble/client/radioGUI
mvn clean package
```

A release package can be built from the top-level makefile using `make release-radioGUI` (which invokes the make target `radioGUI` that invokes maven).
