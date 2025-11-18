<div class="section %section_id%">
    <h2>%title%</h2>
    <table id="%table_id%">
        <thead>
            <tr>
                <th>Callsign</th>
                <th>Frequency</th>
                <th>Lat/Lon</th>
                <th>Height</th>
                <th>Approx.<br>range</th>
                <th>Last<br>update</th>
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
