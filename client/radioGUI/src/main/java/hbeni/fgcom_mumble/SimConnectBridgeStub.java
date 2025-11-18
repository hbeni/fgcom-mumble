package hbeni.fgcom_mumble;

/**
 * SimConnect Bridge Stub - Used when JSIMConnect is disabled
 * 
 * This is a placeholder implementation that provides the same interface
 * as SimConnectBridge but without any actual SimConnect functionality.
 */
public class SimConnectBridgeStub {
    
    private boolean connected = false;
    
    /**
     * Default constructor
     */
    public SimConnectBridgeStub() {
        // Stub implementation - no actual SimConnect connection
    }
    
    /**
     * Check if connected (always false for stub)
     * @return false
     */
    public boolean isConnected() {
        return connected;
    }
    
    /**
     * Connect (stub implementation)
     * @return false (always fails for stub)
     */
    public boolean connect() {
        return false;
    }
    
    /**
     * Disconnect (stub implementation)
     */
    public void disconnect() {
        connected = false;
    }
    
    /**
     * Get connection status message
     * @return status message
     */
    public String getStatus() {
        return "SimConnect disabled (JSIMConnect not available)";
    }
}
