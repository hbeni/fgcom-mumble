<!-- Leaflet map container -->
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
    L.tileLayer('https://api.mapbox.com/styles/v1/{id}/tiles/{z}/{x}/{y}?access_token=pk.eyJ1IjoibWFwYm94IiwiYSI6ImNpejY4NXVycTA2emYycXBndHRqcmZ3N3gifQ.rJcFIG214AriISLbB6B5aw', {
        maxZoom: 18,
        attribution: 'Map data &copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors, ' +
            '<a href="https://creativecommons.org/licenses/by-sa/2.0/">CC-BY-SA</a>, ' +
            'Imagery © <a href="https://www.mapbox.com/">Mapbox</a>',
        id: 'mapbox/streets-v11',
        tileSize: 512,
        zoomOffset: -1
    }).addTo(mymap);
    
    L.control.scale({maxWidth:500}).addTo(mymap);
    
    // define common markers
    var userIcon = L.Icon.extend({
        options: {
            iconUrl:      'inc/user.png',
            iconSize:     [20, 24],
            iconAnchor:   [10, 12],
            popupAnchor:  [0, -15]
        }
    });
    // define common markers
    var radioIcon = L.Icon.extend({
        options: {
            iconUrl:      'inc/radio.png',
            iconSize:     [28, 24],
            iconAnchor:   [14, 12],
            popupAnchor:  [0, -12]
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
