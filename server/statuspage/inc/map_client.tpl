    var client_%id%_popup = '<table class="map_popup"><tr><th>Callsign:</th><td>%callsign%</td></tr><tr><th>Frequencies:</th><td>%fequency%</td></tr><tr><th>Height:</th><td>%alt% ft</td></tr></table>';
    var client_%id% = L.circle([%lat%, %lon%], {icon: new %icon%(), color: '%color%', fillColor: '%color%', fillOpacity: %opacity%, radius: %range% }).addTo(mymap);
    //client_%id%.bindPopup(client_%id%_popup);
    L.marker([%lat%, %lon%], {icon: new %icon%()}).bindPopup(client_%id%_popup).addTo(mymap);
