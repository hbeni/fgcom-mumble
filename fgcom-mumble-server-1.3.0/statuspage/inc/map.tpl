<!-- Leaflet map container (see: https://leafletjs.com/) -->
<div id="mapid"></div> 
<script>

    // init map and center view somewhere on earth
    // (if we have a stored position in cookie, use that)
    var lat  = ( getCookie("lat" ) ? getCookie("lat" ) : %initLAT% );
    var lon  = ( getCookie("lon" ) ? getCookie("lon" ) : %initLON% );
    var zoom = ( getCookie("zoom") ? getCookie("zoom") : %initZOOM% );
    var mymap = L.map('mapid').setView([lat, lon], zoom);
    
    // update location cookie when panning or zooming
    mymap.on("moveend", function(e){
        setCookie("lat", mymap.getCenter().lat, 1800);
        setCookie("lon", mymap.getCenter().lng, 1800);
        setCookie("zoom",mymap.getZoom(),       1800);
    } );
    
    
    // allow mapclick to get coordinates
    var popup = L.popup();
    function onMapClick(e) {
        var e_lat = e.latlng.lat.toFixed(5);
        var e_lon = e.latlng.lng.toFixed(5);
        var pstr = '<table class="map_popup"><tr><th>Lat:</th><td>'+e_lat.toString()+'</td></tr><tr><th>Lon:</th><td>'+e_lon.toString()+'</td></tr></table>';
        popup
            .setLatLng(e.latlng)
            .setContent(pstr)
            .openOn(mymap);
    }
    mymap.on('click', onMapClick);

    // define tile source
    // we use openstreetmaps one. TODO: we might use some sectionals here? is there a free source for that? skyvector!?
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        //maxZoom: 18,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        //id: 'openstreetmap/default',
        //tileSize: 512,
        //zoomOffset: -1
    }).addTo(mymap);
    
    L.control.scale({maxWidth:500}).addTo(mymap);
    
    // define common markers
    var userIcon = L.Icon.extend({
        options: {
            iconUrl:      'inc/user.png',
            iconSize:     [12, 16],
            iconAnchor:   [6, 8],
            popupAnchor:  [0, -10]
        }
    });
    var userIcon_stale = L.Icon.extend({
        options: {
            iconUrl:      'inc/user_stale.png',
            iconSize:     [12, 16],
            iconAnchor:   [6, 8],
            popupAnchor:  [0, -10]
        }
    });
    var radioIcon = L.Icon.extend({
        options: {
            iconUrl:      'inc/radio.png',
            iconSize:     [20, 18],
            iconAnchor:   [10, 9],
            popupAnchor:  [0, -8]
        }
    });
    var radioIcon_stale = L.Icon.extend({
        options: {
            iconUrl:      'inc/radio_stale.png',
            iconSize:     [20, 18],
            iconAnchor:   [10, 9],
            popupAnchor:  [0, -8]
        }
    });
    
    // Add aircraft markers
    var markers = [];
    %client_markers%
    
    // functions to open marker popup
    function showPopup(id){
        markers[id].openPopup();
    }
    
</script>
