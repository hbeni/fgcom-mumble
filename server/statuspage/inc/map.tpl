<!-- Leaflet map container -->
<div id="mapid"></div> 
<script>

    // init map and center view somewhere on earth
    var lat  = 30.0000;
    var lon  = 0.00000;
    var zoom = 2;
    var mymap = L.map('mapid').setView([lat, lon], zoom);
    
    // allow mapclick to get coordinates
    var popup = L.popup();
    function onMapClick(e) {
        popup
            .setLatLng(e.latlng)
            .setContent("<b>Position:</b> " + e.latlng.toString())
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
    
    // Add aircraft markers
    %client_markers%

</script>
