    var client_%id% = L.circle([%lat%, %lon%], {color: '%color%', fillColor: '%color%', fillOpacity: %opacity%, radius: %range% }).addTo(mymap);
    client_%id%.bindPopup('<table class="map_popup"><tr><th>Callsign:</th><td>%callsign%</td></tr><tr><th>Frequencies:</th><td>%fequency%</td></tr></table>'); 
