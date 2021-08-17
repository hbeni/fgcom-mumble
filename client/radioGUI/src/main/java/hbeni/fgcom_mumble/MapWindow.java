/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package hbeni.fgcom_mumble;

import hbeni.fgcom_mumble.gui.MainWindow;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;
import javax.swing.ImageIcon;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.openstreetmap.gui.jmapviewer.Coordinate;
import org.openstreetmap.gui.jmapviewer.JMapViewer;
import org.openstreetmap.gui.jmapviewer.MapMarkerDot;
import org.openstreetmap.gui.jmapviewer.OsmTileLoader;
import org.openstreetmap.gui.jmapviewer.events.JMVCommandEvent;
import org.openstreetmap.gui.jmapviewer.interfaces.ICoordinate;
import org.openstreetmap.gui.jmapviewer.interfaces.JMapViewerEventListener;
import org.openstreetmap.gui.jmapviewer.interfaces.TileLoader;
import org.openstreetmap.gui.jmapviewer.interfaces.TileSource;
import org.openstreetmap.gui.jmapviewer.tilesources.BingAerialTileSource;
import org.openstreetmap.gui.jmapviewer.tilesources.OsmTileSource;

/**
 * Map window based on JMapViewer
 * @author beni
 */
public class MapWindow extends JFrame implements JMapViewerEventListener {
    
    private final JMapViewer theMap;
    
    private final JLabel zoomLabel;
    private final JLabel zoomValue;
    private static int   lastZoom = -1;

    private final JLabel mperpLabelName;
    private final JLabel mperpLabelValue;
    
    static int lastTileSourceSelectorIDX = 0;
    
    protected State state;
    public MainWindow mainWindow;
    
    
    /**
     * Open MapClick window
     * 
     * @param s internal state so clicked location can be updated
     */
    public MapWindow(State s, MainWindow mw) {
        super("Position selector");
        
        state      = s;  // remember state for updates
        mainWindow = mw; // remember main window for repaint
        
        URL iconURL = getClass().getResource("/fgcom_logo.png");
        ImageIcon icon = new ImageIcon(iconURL);
        this.setIconImage(icon.getImage());
        
        setSize(400, 400);
        theMap = new JMapViewer();
        
        // Listen to the map viewer for user operations so components will
        // receive events and update
        map().addJMVListener(this);
        
        setLayout(new BorderLayout());
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        JPanel panel = new JPanel(new BorderLayout());
        JPanel panelTop = new JPanel();
        JPanel panelBottom = new JPanel();
        JPanel helpPanel = new JPanel();

        JPanel zoomTextPanel = new JPanel();
        mperpLabelName = new JLabel("Meters/Pixels: ");
        mperpLabelValue = new JLabel();
        updateZoomParameters();
        zoomTextPanel.add(mperpLabelName);
        zoomTextPanel.add(mperpLabelValue);

        if (lastZoom == -1) {
            lastZoom = map().getZoom();
        } else {
            map().setZoom(lastZoom);
        }
        zoomLabel = new JLabel("Zoom: ");
        zoomValue = new JLabel(String.format("%s", map().getZoom()));
        
        // init tilesource
        JComboBox<TileSource> tileSourceSelector = new JComboBox<>(new TileSource[] {
            new OsmTileSource.Mapnik(),
            new OsmTileSource.TransportMap(),    
            new BingAerialTileSource(),
        });
        tileSourceSelector.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                map().setTileSource((TileSource) e.getItem());
                lastTileSourceSelectorIDX = tileSourceSelector.getSelectedIndex();
            }
        });
        tileSourceSelector.setSelectedIndex(lastTileSourceSelectorIDX);
        
        // prepare the tile loaders
        OsmTileLoader osm_loader = new OsmTileLoader(map());
        osm_loader.headers.put("User-Agent", "FGCom-mumble RadioGUI / "+ System.getProperty("http.agent"));
        osm_loader.headers.put("Referer", "https://github.com/hbeni/fgcom-mumble/blob/master/client/radioGUI/Readme.RadioGUI.md");
        
        JComboBox<TileLoader> tileLoaderSelector;
        tileLoaderSelector = new JComboBox<>(new TileLoader[] {osm_loader});
        tileLoaderSelector.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                map().setTileLoader((TileLoader) e.getItem());
            }
        });
        map().setTileLoader((TileLoader) tileLoaderSelector.getSelectedItem());
        panelTop.add(tileSourceSelector);
        panelTop.add(zoomTextPanel);
        //panelTop.add(tileLoaderSelector);
        
        map().setTileGridVisible(true);
        map().setZoomControlsVisible(true);
        map().setScrollWrapEnabled(true);
        map().setDisplayPosition(new Coordinate(state.getLatitutde(), state.getLongitude()), map().getZoom());
        
        add(theMap, BorderLayout.CENTER);
        
        add(panel, BorderLayout.NORTH);
        add(helpPanel, BorderLayout.SOUTH);
        panel.add(panelTop, BorderLayout.NORTH);
        panel.add(panelBottom, BorderLayout.SOUTH);
        JLabel helpLabel = new JLabel("Left mouse click selects position. \nUse right mouse button to move,\n "
                + " and mouse wheel to zoom.");
        helpPanel.add(helpLabel);
        JLabel attributionLabel = new JLabel("(C) "+map().getAttribution().toString());
        helpPanel.add(attributionLabel);
        
        
        JFrame myself = this;
        map().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON1) {
                    //map().getAttribution().handleAttribution(e.getPoint(), true);
                    ICoordinate clickedPos = map().getPosition(e.getPoint());
                    DecimalFormat df = new DecimalFormat("#.######");
                    df.setDecimalFormatSymbols(new DecimalFormatSymbols(Locale.ROOT));

                    // store picked location
                    state.setLatitude(Double.parseDouble( df.format(clickedPos.getLat())) );
                    state.setLongitude(Double.parseDouble( df.format(clickedPos.getLon())) );
                    mainWindow.updateFromState();
                    
                    myself.dispose();
                }
            }
        });
        
        // Add a marker at current position
        map().addMapMarker(new MapMarkerDot("Position", new Coordinate(state.getLatitutde(), state.getLongitude())));
        
        setExtendedState(JFrame.NORMAL);
        setPreferredSize(new Dimension(1000, 800));
        pack();
        this.setVisible(true);
    }
    
    
    private JMapViewer map() {
        return theMap;
    }
    
    @Override
    public void dispose() {
        // remember some things on close
        lastZoom = map().getZoom();
        super.dispose();
    }

    private static Coordinate c(double lat, double lon) {
        return new Coordinate(lat, lon);
    }
    
    
    private void updateZoomParameters() {
        if (mperpLabelValue != null)
            mperpLabelValue.setText(String.format("%s", Math.round(map().getMeterPerPixel() *100.0)/100.0));
        if (zoomValue != null)
            zoomValue.setText(String.format("%s", map().getZoom()));
    }
    
    @Override
    public void processCommand(JMVCommandEvent command) {
        if (command.getCommand().equals(JMVCommandEvent.COMMAND.ZOOM) ||
                command.getCommand().equals(JMVCommandEvent.COMMAND.MOVE)) {
            updateZoomParameters();
        }
    }
}
