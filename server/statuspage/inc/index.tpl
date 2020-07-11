<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>FGCom-mumble Live status page</title>
        <link rel="shortcut icon" type="image/png" href="inc/fgcom_logo.png"/>
        <link rel="stylesheet" href="inc/style.css">
        
        <!-- include leaflet map -->
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.6.0/dist/leaflet.css"
              integrity="sha512-xwE/Az9zrjBIphAcBb3F6JVqxf46+CDLwfLMHloNu6KEQCAWi6HcDUbeOfBIptF7tcCzusKFjFw2yuvEpDL9wQ=="
              crossorigin=""/>
        <script src="https://unpkg.com/leaflet@1.6.0/dist/leaflet.js"
                integrity="sha512-gZwIG9x3wUXg2hdXF6+rVkLF/0Vi9U8D2Ntg4Ga5I5BZpVkVxlJWbSQtXPSiUTtC0TjtGOmxa1AJPuV0CPthew=="
                crossorigin=""></script>
    </head>

    <body>
        <div class="title">
            <h1>FGCom-mumble: live status page</h1>
            <span>Last database update: %dbchanged%</span>
        </div>
        
        %message%
    
        %users%
        
        %bots%
        
        %map%

        
        <div class="footer">
            <a href="https://github.com/hbeni/fgcom-mumble"><img height="15px" width="37px" src="inc/GitHub_Logo.png" />hbeni/fgcom-mumble</a> | <a href="https://www.gnu.org/licenses/gpl-3.0.html"><img height="15px" width="44px" src="inc/gplv3-88x31.png" alt="GPLv3"/></a> | &copy; 2020 Benedikt Hallinger
        </div>
    </body>

</html>
