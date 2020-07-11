<!-- Leaflet map container -->
<div id="mapid"></div> 
<script>

    


    // init map and center view somewhere on earth
    // (if we have a stored position in cookie, use that)
    var lat  = ( getCookie("lat" ) ? getCookie("lat" ) : 30.0000 );
    var lon  = ( getCookie("lon" ) ? getCookie("lon" ) : 0.00000 );
    var zoom = ( getCookie("zoom") ? getCookie("zoom") : 2 );
    var mymap = L.map('mapid').setView([lat, lon], zoom);
    
    // update location cookie when panning or zooming
    mymap.on("moveend", function(e){
        setCookie("lat", mymap.getCenter().lat, 1);
        setCookie("lon", mymap.getCenter().lng, 1);
        setCookie("zoom",mymap.getZoom(),       1);
    } );
    
    
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
    
    L.control.scale({maxWidth:500}).addTo(mymap);
    
    // Add aircraft markers
    %client_markers%

    
    
    /***********************************************
     * UTILS
     */
    
    // set a cookie
    function setCookie(cname, cvalue, exdays) {
        var d = new Date();
        d.setTime(d.getTime() + (exdays*24*60*60*1000));
        var expires = "expires="+ d.toUTCString();
        document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
    }

    // get a cookie
    function getCookie(cname) {
        var name = cname + "=";
        var decodedCookie = decodeURIComponent(document.cookie);
        var ca = decodedCookie.split(';');
        for(var i = 0; i <ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ') {
                c = c.substring(1);
            }
            if (c.indexOf(name) == 0) {
                return c.substring(name.length, c.length);
            }
        }
        return "";
    }
    
</script>
