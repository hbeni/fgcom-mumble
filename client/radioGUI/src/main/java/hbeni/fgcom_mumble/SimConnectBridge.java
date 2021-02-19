/*
 * JSimConnect Bridge class
 *
 * This class implements the bridge between the RadioGUI and SimConnect.
 * It's purpose is to establish an connection to SimConnect ports and
 * read the positional and avionics data we need from the users plane.
 * The data is then fed into the normal internal state which causes
 * the UDP client to send it out to the FGCom-mumble plugin.
 */
package hbeni.fgcom_mumble;

import java.io.IOException;
import java.security.InvalidParameterException;

import flightsim.simconnect.SimConnect;
import flightsim.simconnect.SimConnectDataType;
import flightsim.simconnect.SimObjectType;
import flightsim.simconnect.config.Configuration;
import flightsim.simconnect.config.ConfigurationNotFoundException;
import flightsim.simconnect.recv.DispatcherTask;
import flightsim.simconnect.recv.EventHandler;
import flightsim.simconnect.recv.OpenHandler;
import flightsim.simconnect.recv.RecvEvent;
import flightsim.simconnect.recv.RecvOpen;
import flightsim.simconnect.recv.RecvSimObjectDataByType;
import flightsim.simconnect.recv.SimObjectDataTypeHandler;
import static hbeni.fgcom_mumble.radioGUI.state;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SimConnectBridge implements EventHandler, OpenHandler, SimObjectDataTypeHandler {

    static enum EVENT_ID {
        EVENT_SIM_START,
    };

    static enum DATA_DEFINE_ID {
        DEFINITION_1,
    };

    static enum DATA_REQUEST_ID {
        REQUEST_1,
    };

    public SimConnectBridge() throws IOException, ConfigurationNotFoundException {
        // Setup config
        Configuration simconnect_cfg = new Configuration();
        simconnect_cfg.setAddress(radioGUI.Options.simConnectHost);
        int foundPort = Configuration.findSimConnectPort();
        if (foundPort < 0) {
            // port could not be found in registry, use manually configured one
            foundPort = radioGUI.Options.simConnectPort;
        }
        simconnect_cfg.setPort(foundPort);

        // build the bridge
        SimConnect sc;
        try {
            sc = new SimConnect("FGCom-mumble RadioGUI", simconnect_cfg);
        } catch (Exception e) {
            state.statusmessage = "ERROR connecting SimConnect: "+e.getLocalizedMessage();
            return;
        }

        // Set up the data definition, but do not yet do anything with it
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "ATC ID", null,
                        SimConnectDataType.STRING256);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "Plane Latitude",
                        "degrees", SimConnectDataType.FLOAT64);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "Plane Longitude",
                        "degrees", SimConnectDataType.FLOAT64);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "Plane ALT ABOVE GROUND",
                        "feet", SimConnectDataType.FLOAT64);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM ACTIVE FREQUENCY:1",
                        "Frequency BCD16", SimConnectDataType.FLOAT64);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM ACTIVE FREQUENCY:2",
                        "Frequency BCD16", SimConnectDataType.FLOAT64);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM TRANSMIT:1",
                        "Bool", SimConnectDataType.INT32);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM TRANSMIT:2",
                        "Bool", SimConnectDataType.INT32);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM STATUS:1",
                        "Enum", SimConnectDataType.INT32);
        sc.addToDataDefinition(DATA_DEFINE_ID.DEFINITION_1, "COM STATUS:2",
                        "Enum", SimConnectDataType.INT32);

        // Request an event when the simulation starts
        sc.subscribeToSystemEvent(EVENT_ID.EVENT_SIM_START, "SimStart");

        // dispatcher
        DispatcherTask dt = new DispatcherTask(sc);
        dt.addOpenHandler(this);
        dt.addEventHandler(this);
        dt.addSimObjectDataTypeHandler(this);
        dt.createThread().start();

    }

    public void handleOpen(SimConnect sender, RecvOpen e) {
        System.out.println("Connected to : " + e.getApplicationName() + " "
                        + e.getApplicationVersionMajor() + "."
                        + e.getApplicationVersionMinor());

        state.statusmessage = "Connected to : " + e.getApplicationName() + " "
                        + e.getApplicationVersionMajor() + "."
                        + e.getApplicationVersionMinor();
    }

    public void handleEvent(SimConnect sender, RecvEvent e) {

        // Now the sim is running, request information on the user aircraft
        try {
            while (true) {
                sender.requestDataOnSimObjectType(DATA_REQUEST_ID.REQUEST_1,
                                DATA_DEFINE_ID.DEFINITION_1, 0, SimObjectType.USER);
                Thread.sleep(100); // request data every 100ms
            }
        } catch (IOException e1) {
        } catch (InterruptedException ex) {
        }
    }

    public void handleSimObjectType(SimConnect sender, RecvSimObjectDataByType e) {
        if (e.getRequestID() == DATA_REQUEST_ID.REQUEST_1.ordinal()) {
            //
            // notice that we cannot cast directly a RecvSimObjectDataByType 
            // to a structure. this is forbidden by java language
            //
            String callsign   = e.getDataString256();
            double lat        = e.getDataFloat64();
            double lon        = e.getDataFloat64();
            double alt        = e.getDataFloat64();
            double com1_frq   = e.getDataFloat64();
            double com2_frq   = e.getDataFloat64();
            int    com1_ptt   = e.getDataInt32();
            int    com2_ptt   = e.getDataInt32();
            int    com1_state = e.getDataInt32();
            int    com2_state = e.getDataInt32();

            String msg = "ObjectID=" + e.getObjectID()
                    + " callsign='" + callsign
                    + " position='" + " lat="+lat + ", lon="+lon + ", alt="+alt
                    + " com1_frq='" + com1_frq
                    + " com2_frq='" + com2_frq
                    + " com1_ptt='" + com1_ptt
                    + " com2_ptt='" + com2_ptt
                    + " com1_state='" + com1_state
                    + " com2_state='" + com2_state;
            state.statusmessage = "received: "+msg;
            System.out.println(msg);

            // Map received data to internal state
            state.callsign  = callsign;
            state.latitude  = lat;
            state.longitude = lon;
            state.height    = (float) alt;
            state.getRadios().get(0).setFrequency(Double.toString(com1_frq));
            state.getRadios().get(0).setPTT(com1_ptt > 0);
            state.getRadios().get(0).setPwrBtn(com1_state > 0);
            state.getRadios().get(1).setFrequency(Double.toString(com2_frq));
            state.getRadios().get(1).setPTT(com2_ptt > 0);
            state.getRadios().get(1).setPwrBtn(com1_state > 0);
            
            radioGUI.mainWindow.updateFromState();
        }

    }

}
