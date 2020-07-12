<div class="section">
    <h2>%title%</h2>
    <table id="%table_id%">
        <thead>
            <tr>
                <th>Callsign</th>
                <th>Fequencys</th>
                <th>Latitude</th>
                <th>Longitude</th>
                <th>Altitude</th>
                <th>Approx. range</th>
                <th>Last update</th>
            </tr>
        </thead>
        <tbody>
            %user_table_entries%
        </tbody>
    </table>
</div>
<script>
  new Tablesort(document.getElementById('%table_id%'));
</script>
