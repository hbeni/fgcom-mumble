<?php
/**
* This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
* Copyright (c) 2020 Benedikt Hallinger
* 
* This program is free software: you can redistribute it and/or modify  
* it under the terms of the GNU General Public License as published by  
* the Free Software Foundation, version 3.
*
* This program is distributed in the hope that it will be useful, but 
* WITHOUT ANY WARRANTY; without even the implied warranty of 
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with this program. If not, see <http://www.gnu.org/licenses/>.
***********************************************************************
*
* This is a small status webpage for the FGCom-mumble implementation.
*
* Main code is at the start, some functions at the end.
*
* You can experimentally test this locally with PHPs internal webserver:
*   FGCom-mumble/server/statuspage$ php -S localhost:8080 -t .
* Then the Statuspage is serviced at http://localhost:8080/
*/


// Initialize basic stuff
$tpl_index = new HTMLTemplate(dirname(__FILE__).'/inc/index.tpl');
$tpl_msg   = new HTMLTemplate(dirname(__FILE__).'/inc/msg.tpl');
$tpl_users = new HTMLTemplate(dirname(__FILE__).'/inc/users.tpl');
$tpl_bots  = new HTMLTemplate(dirname(__FILE__).'/inc/users.tpl');
$tpl_map   = new HTMLTemplate(dirname(__FILE__).'/inc/map.tpl');


/*
* Load central config
*/
if (!is_readable(dirname(__FILE__).'/config.ini')) {
    $tpl_msg->assignVar('msg', "Setup error: config file not readable: ".dirname(__FILE__).'/config.ini');
    $tpl_index->assignVar('message', $tpl_msg->generate());
    $tpl_index->render();
    exit(1);
}
$ini_config = parse_ini_file(dirname(__FILE__).'/config.ini', true);
//Array ( [json-database] => Array ( [file] => /tmp/fgcom-web.db ) ) 
$ini_config = sanitize($ini_config);


/**
* Usage statistics output mode
* This mode will show the gnuplot processed result of the status bot stats file.
* The needed file is generated from the status bot when invoking it with the --stats parameter.
* You need to enable this feature in the config file.
*
* The displayed timeframe defaults to the last week, but may be altered using the following GET-parameters.
* Timestamps are in YYYYmmdd[HHMM] format.
*  - last:      ammount of hours to display from now into the past
*  - from:      fixing the selected timeframe start to this timestamp ('last' will be ignored obviously)
*  - to:        fixing the selected timeframe end to this timestamp
*
* Examples:
*   ?usage                             displays the rolling last week
*   ?usage&last=24                     displays the rolling last day
*   ?usage&from=20210101&to=20210131   displays Jan 2021
*/
if (array_key_exists('usage', $_GET)) {
    if (!$ini_config['ui']['gnuplot_source']) die("ERROR: Feature not enabled in config. Enable 'gnuplot_source' option.");
    if (!is_readable($ini_config['ui']['gnuplot_source'])) die("ERROR:".$ini_config['ui']['gnuplot_source']." not readbale or existing!");
    $statfile_p = escapeshellcmd($ini_config['ui']['gnuplot_source']);

    // parse timing parameters
    $time_one_week_in_seconds = 7*24*60*60; // one week in seconds
    $time_delta = (preg_match('/^\d+$/', isset($_GET['last'])))? $_GET['last']*60*60 +900 : $time_one_week_in_seconds;
    $time_to    = (preg_match('/^\d+$/', isset($_GET['to'])))?   $_GET['to']         : gmdate("YmdHis", time());
    $time_from  = (preg_match('/^\d+$/', isset($_GET['from'])))? $_GET['from']       : gmdate("YmdHis", time()-$time_delta);

    $handle = popen("gnuplot -e 'filename=\"".$statfile_p."\"; timeselect_from = \"".$time_from."\"; timeselect_to = \"".$time_to."\"' stats2png.gnuplot", 'r');
    $firstBytes = fread($handle, 1024);
    if (!preg_match('/^.PNG/', $firstBytes)) die("ERROR generating image invoking gnuplot: ".$firstBytes);

    header("Content-type: image/png");
    print $firstBytes;
    while(!feof($handle)) {
        // send the current file part to the browser
        print fread($handle, 1024);
        // flush the content to the browser
        flush();
    }
    fclose($handle); 

    exit;
}


/**
* Add donation link
*/
$donate_link = "";
if (isset($ini_config['donate']['paypalme']) && $ini_config['donate']['paypalme']) {
    $tpl_donation = new HTMLTemplate(dirname(__FILE__).'/inc/donate_paypalme.tpl');
    $tpl_donation->assignVar('name', $ini_config['donate']['paypalme']);
    $donate_link .= $tpl_donation->generate();
}
if (isset($ini_config['donate']['bitcoin']) && $ini_config['donate']['bitcoin']) {
    $tpl_donation = new HTMLTemplate(dirname(__FILE__).'/inc/donate_bitcoin.tpl');
    $tpl_donation->assignVar('address', $ini_config['donate']['bitcoin']);
    $donate_link .= $tpl_donation->generate();
}
$tpl_index->assignVar('donate', $donate_link);


/**
* Add link to usage statistics graph
*/
if ($ini_config['ui']['gnuplot_source'] && is_readable($ini_config['ui']['gnuplot_source'])) {
    $usagelink = '<div id="usagelink"><a href="?usage" target="_blank">Usage stats</a></div>';
    $tpl_index->assignVar('usagelink', $usagelink);
}


/**
* Fetch database contents
*
* Expected format is a JSON structure containing:
*  "meta": metadata table {"highscore_num":12, "highscore_date":1599719381}
*  "clients": table holds elements representing one user record each:
*     [{"type":"client", "callsign":"Calls-1", "radios":[{"frequency":123.45, "operable":1}], "lat":12.3456, "lon":20.11111, "alt":1234.45, "updated":1111111122}, ...]
*/
$allClients = array();
$allBots    = array();
if (!is_readable($ini_config['json-database']['file'])) {
    $tpl_index->assignVar('dbchanged', "???");
    $tpl_msg->assignVar('msg', "Info: Database not initialized yet. Please try again later.");
    $tpl_index->assignVar('message', $tpl_msg->generate());
    $tpl_index->render();
    exit(1);
}

$db_lastUpdate = filemtime($ini_config['json-database']['file']);
date_default_timezone_set('UTC');
$tpl_index->assignVar('dbchanged', date("d.m.Y H:i:s", $db_lastUpdate));
$db_lastUpdate_stale = (time()-$db_lastUpdate > $ini_config['ui']['db_stale']);
if ($db_lastUpdate_stale) {
       $tpl_index->assignVar('updatestale_class', 'stale');
       $tpl_index->assignVar('updatestale_text', ' (stale)');
}

$db_content = file_get_contents($ini_config['json-database']['file']);
$db_data = json_decode($db_content, true);
if ($db_data == "{}") $db_data = array();
if (!is_array($db_data)) {
    $tpl_msg->assignVar('msg', "Error: Database format invalid!");
    var_dump($db_data);
    $tpl_index->assignVar('message', $tpl_msg->generate());
    $tpl_index->render();
    exit(1);
}
$db_data = sanitize($db_data);

// Ensure basic database structure
if (!array_key_exists('meta', $db_data)    || !is_array($db_data['meta'])) $db_data['meta'] = array('highscore_num'=>'', 'highscore_date'=>'', 'highscore_clients'=>0);
if (!array_key_exists('clients', $db_data) || !is_array($db_data['clients'])) {
    $db_data['clients'] = array();
} else {
    foreach ($db_data["clients"] as $uk => $u) {
        if (!array_key_exists('type',     $db_data["clients"][$uk])) $db_data["clients"][$uk]['type']     = '';
        if (!array_key_exists('callsign', $db_data["clients"][$uk])) $db_data["clients"][$uk]['callsign'] = '';
        if (!array_key_exists('lat',      $db_data["clients"][$uk])) $db_data["clients"][$uk]['lat']      = 0;
        if (!array_key_exists('lon',      $db_data["clients"][$uk])) $db_data["clients"][$uk]['lon']      = 0;
        if (!array_key_exists('alt',      $db_data["clients"][$uk])) $db_data["clients"][$uk]['alt']      = 0;
        if (!is_numeric($db_data["clients"][$uk]['lat'])) $db_data["clients"][$uk]['lat'] = 0;
        if (!is_numeric($db_data["clients"][$uk]['lon'])) $db_data["clients"][$uk]['lon'] = 0;
        if (!is_numeric($db_data["clients"][$uk]['alt'])) $db_data["clients"][$uk]['alt'] = 0;
        if (!array_key_exists('updated',  $db_data["clients"][$uk])) $db_data["clients"][$uk]['updated']  = 0;
        if (!array_key_exists('radios',   $db_data["clients"][$uk]) || !is_array($db_data["clients"][$uk]['radios'])) {
            $db_data["clients"][$uk]['radios']  = array();
        } else {
            foreach ($u['radios'] as $ri => $r) {
                if (!array_key_exists('frequency',  $db_data["clients"][$uk]['radios'][$ri])) $db_data["clients"][$uk]['radios'][$ri]['frequency']  = '';
                if (!array_key_exists('dialedFRQ',  $db_data["clients"][$uk]['radios'][$ri])) $db_data["clients"][$uk]['radios'][$ri]['dialedFRQ']  = '';
                if (!array_key_exists('operable',   $db_data["clients"][$uk]['radios'][$ri])) $db_data["clients"][$uk]['radios'][$ri]['operable']   = '';
            }
        }
    }
}



/**
* RAW mode (like for inclusion in other aplications)
* outputs JSON data in the above specified format:
*  "meta": metadata table {"highscore_num":12, "highscore_date":1599719381}
*  "clients": table holds elements representing one user record each:
*     [{"type":"client", "callsign":"Calls-1", "radios":[r1, r2...], "lat":12.3456, "lon":20.11111, "alt":1234.45, "updated":1111111122}, ...]
*/
if (array_key_exists('raw', $_GET) && $ini_config['ui']['allow_raw_mode']) {
    echo json_encode($db_data);
    exit(0);
}


/*
* Get regular users
*/
$tpl_users_body = "";
$numUsers = 0;
$id=0;
foreach ($db_data["clients"] as $u) {
    $id++;
    if ($u['type'] != "client") continue;
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/user_entry.tpl');
    $utpl->assignVar('id',$id);
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('lat', round($u['lat'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('lon', round($u['lon'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('alt', round(m2ft($u['alt']),0) );
    $utpl->assignVar('range', round(getVHFRadioHorizon($u['alt']),0));
    $utpl->assignVar('updated',time()-$u['updated']);
    $utpl->assignVar('stale', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '' : 'class="stale"' );
    
    $frq_str = "";
    foreach ($u['radios'] as $radio) {
        if ($radio['frequency'] != "") {
            $radio_class_name = ($radio['operable'])?"radio_ok":"radio_err";
            $frq_str .= '<span class="'.$radio_class_name.'">'.$radio['dialedFRQ'].'</span><br/>';
        }
    }
    $utpl->assignVar('frequency',$frq_str);
    
    if (time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_users_body .= $utpl->generate();
        $numUsers++;
    }
}
$tpl_users->assignVar('section_id', "s_users"); // for css
$tpl_users->assignVar('title', "Current users: ".$numUsers);
$tpl_users->assignVar('table_id', "table_users"); // for tablesort (and css, if needed)
$tpl_users->assignVar('user_table_entries', $tpl_users_body);
$tpl_index->assignVar('users', $tpl_users->generate());
$tpl_index->assignVar('usercount', $numUsers);


/*
* Get playback bots
*/
$tpl_bots_body = "";
$numBots = 0;
$id=0;
foreach ($db_data["clients"] as $u) {
    $id++;
    if ($u['type'] != "playback-bot") continue;
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/user_entry.tpl');
    $utpl->assignVar('id',$id);
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('lat', round($u['lat'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('lon', round($u['lon'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('alt', round(m2ft($u['alt']),0) );
    $utpl->assignVar('range', round(getVHFRadioHorizon($u['alt']),0));
    $utpl->assignVar('updated',time()-$u['updated']);
    $utpl->assignVar('stale', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '' : 'class="stale"' );
    
    $frq_str = "";
    foreach ($u['radios'] as $radio) {
        if ($radio['frequency'] != "") {
            $radio_class_name = ($radio['operable'])?"radio_ok":"radio_err";
            $frq_str .= '<span class="'.$radio_class_name.'">'.$radio['dialedFRQ'].'</span><br/>';
        }
    }
    $utpl->assignVar('frequency',$frq_str);
    
    if (time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_bots_body .= $utpl->generate();
        $numBots++;
    }
}
$tpl_bots->assignVar('section_id', "s_playbacks"); // for css
$tpl_bots->assignVar('table_id', "table_bots"); // for tablesort (and css, if needed)
$tpl_bots->assignVar('title', "Current radio broadcasts: ".$numBots);
$tpl_bots->assignVar('user_table_entries', $tpl_bots_body);
$tpl_index->assignVar('bots', $tpl_bots->generate());
$tpl_index->assignVar('playbackcount', $numBots);


/**
* Integrate the leaflet map
*/
$tpl_clients_body = "";
$id=1;
foreach ($db_data["clients"] as $u) {
    // draw a nice marker on the map for each client
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/map_client.tpl');
    $utpl->assignVar('id',$id++);
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('range', getVHFRadioHorizon($u['alt'])*1000);
    $utpl->assignVar('lat', $u['lat'] );
    $utpl->assignVar('lon', $u['lon'] );
    $utpl->assignVar('alt', round(m2ft($u['alt']),0) );
    $utpl->assignVar('color',   (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '#ff9900' : '#B0AAA1' );
    $utpl->assignVar('opacity', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? 0.35 : 0.15);
    $utpl->assignVar('icon', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? 'userIcon' : 'userIcon_stale' );
    if ($u['type'] == 'playback-bot') $utpl->assignVar('icon', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? 'radioIcon' : 'radioIcon_stale');
    
    $frq_str = "";
    foreach ($u['radios'] as $radio) {
        if ($radio['frequency'] != "") {
            $radio_class_name = ($radio['operable'])?"radio_ok":"radio_err";
            $frq_str .= '<span class="'.$radio_class_name.'">'.$radio['dialedFRQ'].'</span><br/>';
        }
    }
    $utpl->assignVar('frequency',$frq_str);
    
    if ($u['alt'] >= 0 && time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_clients_body .= $utpl->generate();
    }
}
$tpl_map->assignVar('client_markers', $tpl_clients_body);
$tpl_map->assignVar('initLAT',  $ini_config['map']['lat']);
$tpl_map->assignVar('initLON',  $ini_config['map']['lon']);
$tpl_map->assignVar('initZOOM', $ini_config['map']['zoom']);
$tpl_index->assignVar('map', $tpl_map->generate());


/**
* Calculate auto refresh box
*/
$tpl_refreshbox = new HTMLTemplate(dirname(__FILE__).'/inc/refreshbox.tpl');
$tpl_index->assignVar('refreshbox', $tpl_refreshbox->generate());


/**
* Add highscore info
*/
if ($db_data["meta"]["highscore_clients"] > 0) {
    date_default_timezone_set('UTC');
    $tpl_highscore = new HTMLTemplate(dirname(__FILE__).'/inc/highscore.tpl');
    $tpl_highscore->assignVar('highscore_clients', $db_data["meta"]["highscore_clients"]);
    $tpl_highscore->assignVar('highscore_date', date("Y-m-d H:i:s", $db_data["meta"]["highscore_date"])." UTC");
    $tpl_index->assignVar('highscore', $tpl_highscore->generate());
}


/*
* All done: print the page
*/
$tpl_index->render();




/************************* LIBS ****************************/

/*
* Meters to ft
*/
function m2ft($height) {
    return $height * 3.2808;
}

/*
* Calculate approximate radio range (VHF radio horizon)
* @param $height: in meter
*/
function getVHFRadioHorizon($height) {
    // https://en.wikipedia.org/wiki/Horizon#Distance_to_the_horizon
    // this is a raw value (VHF actually goes slightly furhter) but accurate enough here.
    if ($height <= 0) return(0);
    if (!is_numeric($height)) return(0);
    return 3.57 * sqrt($height);
}

/*
* make the values HTML-secure
*/
function sanitize($v) {
    if (is_array($v)) {
        foreach ($v as $kv => $vv) {
            $v[$kv] = sanitize($vv);
        }
        return $v;
    } else {
        return(htmlentities($v));
    }
    
}



/*
* A really small template engine.
*
* Will load a template file and replace variables in the form "%var%" with content.
*/
class HTMLTemplate {
    private $template_src = '';
    
    private $variables = array();
    
    /**
    * Constructor
    */
    function __construct($tpl) { $this->HTMLTemplate($tpl); }
    function HTMLTemplate($tpl) {
        if (!is_readable($tpl)) {
            print("Setup error: template file not readable: ".$tpl);
            exit(1);
        }
        $this->template_src = file_get_contents($tpl);

        // init some default variables for all templates
        $this->assignVar('cur_year', date('Y'));
        $this->assignVar('cur_month', date('d'));
        $this->assignVar('cur_day', date('m'));
    }

    /**
    * Add some variable content
    *
    * @param string $variable Template variable name
    * @param mixed  $content  Content to assign
    */
    public function assignVar($variable, $content) {
        $this->variables[$variable] = $content;
    }
     
    /**
    * Assembles the page
    */
    public function generate() {
        $tpl_index = $this->template_src;
        
        // generate the body and replace it into the variables
        foreach($this->variables as $var => $content) {
            $tpl_index = str_replace("%$var%", $content, $tpl_index);
        }
        
        $tpl_index = preg_replace("/%.+?%/", '', $tpl_index); // strip remaining variables
        
        return($tpl_index);
    }
    
    /**
    * Prints the page
    */
    public function render() {
        print($this->generate());
    }
    
}
    
?>
