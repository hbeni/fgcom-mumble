<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>FGCom-mumble Live status page</title>
        <meta name="author" content="Benedikt Hallinger">
        <meta name="description" content="FGCom-mumble online status">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="expires" content="5">
        <link rel="shortcut icon" type="image/png" href="inc/fgcom_logo.png"/>
        
        <link rel="stylesheet" href="inc/style.css">
        <script src="inc/utils.js"></script>
        
        <!-- tablesort from https://github.com/tristen/tablesort -->
        <script src='inc/tablesort.min.js'></script>
        <script src='inc/tablesort.number.js'></script> <!-- modified version to understand units postfix)
        
        <!-- include leaflet map -->
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.6.0/dist/leaflet.css"
              integrity="sha512-xwE/Az9zrjBIphAcBb3F6JVqxf46+CDLwfLMHloNu6KEQCAWi6HcDUbeOfBIptF7tcCzusKFjFw2yuvEpDL9wQ=="
              crossorigin=""/>
        <script src="https://unpkg.com/leaflet@1.6.0/dist/leaflet.js"
                integrity="sha512-gZwIG9x3wUXg2hdXF6+rVkLF/0Vi9U8D2Ntg4Ga5I5BZpVkVxlJWbSQtXPSiUTtC0TjtGOmxa1AJPuV0CPthew=="
                crossorigin=""></script>
    </head>

    <body>
        <div class="header">
            <div class="title">
                <h1>FGCom-mumble: live status page</h1>
                <span class="userinfo">Users: %usercount% | Broadcasts: %playbackcount% | </span>
                <span class="lastdbupdate %updatestale_class%">Last DB update: %dbchanged% (UTC)%updatestale_text%</span>
                %refreshbox%
                %donate%
            </div>
            
            
            %message%
        </div>
            
        <div class="body">
        
            %map%
    
            <div class="flex">
                %users%
                %bots%
            </div>
        
        </div>
        
        <div class="footer">
            <div>%highscore% %usagelink%</div>
            <a href="https://github.com/hbeni/fgcom-mumble"><img height="15px" width="37px" src="inc/GitHub_Logo.png" />hbeni/fgcom-mumble</a> | <a href="https://www.gnu.org/licenses/gpl-3.0.html"><img height="15px" width="44px" src="inc/gplv3-88x31.png" alt="GPLv3"/></a> | &copy; %cur_year% Benedikt Hallinger
        </div>
    </body>

    <!-- restore / save the scroll position -->
    <script>
        document.addEventListener("DOMContentLoaded", function (event) {
            var scrollpos = sessionStorage.getItem('scrollpos');
            if (scrollpos) {
                window.scrollTo(0, scrollpos);
                sessionStorage.removeItem('scrollpos');
            }
        });

        window.addEventListener("beforeunload", function (e) {
            sessionStorage.setItem('scrollpos', window.scrollY);
        });
    </script>

</html>
