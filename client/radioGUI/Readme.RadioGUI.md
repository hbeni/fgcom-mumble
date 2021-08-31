FGCom mumble Radio GUI
===================================

The FGCom-mumble Radio GUI is a small Java Application that acts as client to the FGCom-mumble plugin and thus simulates radio stacks.


Install / Setup
----------------
In order to run the tool, you need a java runtime version >= 8. You just need to run the JAR file, no need for installation.

### Updating
When RadioGUI is started, it checks for updates on GitHub. If a newer version is found, it informs about that with an infobox.  
Just download the latest release from GitHub and use that version instead (you can copy over the existing Jar).


Running and usage
-----------------
The Application comes as executable JAR-Archive. Just start that in the usual java way (e.g. `java -jar FGCom-mumble-radioGUI-*.jar`).

After startup the GUI initializes with a default config (location, radio stack). Adjust that as needed and then hit the "connect" button to actually send data to the mumble plugin.

You can run several instances of the application at once to have different clients connecting to the same mumble plugin. You can simulate different locations with their own radio stack this way.


SimConnect support (MSFS2020)
-----------------------------
RadioGUI can connect to a SimConnect compatible simulator like MSFS2020.  
For doing so, you must enable the connection in the simulator.

- Find the SimConnect.xml in the Microsoft files, usually somewhere here:
`C:\Users\[user name]\AppData\Local\Packages\Microsoft.FlightSimulator_8wekyb3d8bbwe\LocalCache`

- Add a new connection to that xml file:
```xml
<SimConnect.Comm>
  <Descr>Global IP Port</Descr>
  <Disabled>False</Disabled>
  <Protocol>IPv4</Protocol>
  <Scope>global</Scope>
  <Address>127.0.0.1</Address> <!-- Set the IP of your machine -->
  <MaxClients>64</MaxClients>
  <Port>7421</Port> <!-- Can be another port if you like -->
  <MaxRecvSize>4096</MaxRecvSize>
  <DisableNagle>False</DisableNagle>
</SimConnect.Comm> 
```

Then you can adjust the SimConnect options in RadioGUI's Options-dialog and finally activate it by choosing the respective option from RadioGUI's main menu.  
Per default, the FGCom-mumble plugin does map mumbles talk activation to COM1-PTT, so you can use mumbles native PTT binding to activate COM1 transmissions transparently.


Compiling
-----------------
A release package can be built from the top-level makefile using `make release-radioGUI` (which invokes the make target `build-radioGUI` that invokes maven).

The client is written using netbeans, so you may just checkout the netbeans project file and build it with there. However, you should build once with `make radioGUI`, because it will set up the build environment.
