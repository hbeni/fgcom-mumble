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
* Fetch database contents
*
* Expected format is a JSON array representing one user record each:
* {"type":"client",  "callsign":"Calls-1",   "frequencies":["123.456"],
*  "lat":12.3456, "lon":20.11111,  "alt":1234.45,  "updated":1111111122}
*/
$allClients = array();
$allBots    = array();
$tpl_index->assignVar('dbchanged', "TODO: from modifyTime file");
if (!is_readable($ini_config['json-database']['file'])) {
    $tpl_index->assignVar('dbchanged', "???");
    $tpl_msg->assignVar('msg', "Info: Database not initialized yet. Please try again later.");
    $tpl_index->assignVar('message', $tpl_msg->generate());
    $tpl_index->render();
    exit(1);
}
$db_lastUpdate = filemtime($ini_config['json-database']['file']);
$tpl_index->assignVar('dbchanged', date("d.m.Y H:i:s", $db_lastUpdate));
if (time()-$db_lastUpdate > $ini_config['ui']['db_stale']) $tpl_index->assignVar('updatestale', 'class="stale"');
$db_content = file_get_contents($ini_config['json-database']['file']);
$db_data = json_decode($db_content, true);
if ($db_data == "{}") $db_data = array();
if (!$db_data) {
    $tpl_msg->assignVar('msg', "Error: Database format invalid!");
    $tpl_index->assignVar('message', $tpl_msg->generate());
    $tpl_index->render();
    exit(1);
}
$db_data = sanitize($db_data);



/*
* Get regular users
*/
$tpl_users_body = "";
$numUsers = 0;
foreach ($db_data as $u) {
    if ($u['type'] != "client") continue;
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/user_entry.tpl');
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('fequency',implode($u['frequencies'],"<br/>"));
    $utpl->assignVar('lat', round($u['lat'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('lon', round($u['lon'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('alt', round($u['alt'],0) );
    $utpl->assignVar('range', round(getVHFRadioHorizon($u['alt']),0));
    $utpl->assignVar('updated',time()-$u['updated']);
    $utpl->assignVar('stale', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '' : 'class="stale"' );
    
    if (time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_users_body .= $utpl->generate();
        $numUsers++;
    }
}
$tpl_users->assignVar('title', "Current users: ".$numUsers);
$tpl_users->assignVar('user_table_entries', $tpl_users_body);
$tpl_index->assignVar('users', $tpl_users->generate());


/*
* Get playback bots
*/
$tpl_bots_body = "";
$numBots = 0;
foreach ($db_data as $u) {
    if ($u['type'] != "playback-bot") continue;
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/user_entry.tpl');
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('fequency',implode($u['frequencies'],"<br/>"));
    $utpl->assignVar('lat', round($u['lat'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('lon', round($u['lon'],5) ); // 5 decimals is abput 100m accurate
    $utpl->assignVar('alt', round($u['alt'],0) );
    $utpl->assignVar('range', round(getVHFRadioHorizon($u['alt']),0));
    $utpl->assignVar('updated',time()-$u['updated']);
    $utpl->assignVar('stale', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '' : 'class="stale"' );
    
    if (time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_bots_body .= $utpl->generate();
        $numBots++;
    }
}
$tpl_bots->assignVar('title', "Current radio broadcasts: ".$numBots);
$tpl_bots->assignVar('user_table_entries', $tpl_bots_body);
$tpl_index->assignVar('bots', $tpl_bots->generate());


/**
* Integrate the leaflet map
*/
$tpl_clients_body = "";
$id=1;
foreach ($db_data as $u) {
    // draw a nice marker on the map for each client
    $utpl = new HTMLTemplate(dirname(__FILE__).'/inc/map_client.tpl');
    $utpl->assignVar('id',$id++);
    $utpl->assignVar('callsign',$u['callsign']);
    $utpl->assignVar('fequency',implode($u['frequencies'],"<br/>"));
    $utpl->assignVar('range', getVHFRadioHorizon($u['alt'])*1000);
    $utpl->assignVar('lat', $u['lat'] );
    $utpl->assignVar('lon', $u['lon'] );
    $utpl->assignVar('color',   (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? '#ff9900' : '#B0AAA1' );
    $utpl->assignVar('opacity', (time()-$u['updated'] <= $ini_config['ui']['mark_stale_entries'])? 0.35 : 0.15);
    
    if ($u['alt'] >= 0 && time()-$u['updated'] <= $ini_config['ui']['hide_stale_entries']) {
        $tpl_clients_body .= $utpl->generate();
    }
}
$tpl_map->assignVar('client_markers', $tpl_clients_body);
$tpl_map->assignVar('initLAT',  $ini_config['map']['lat']);
$tpl_map->assignVar('initLON',  $ini_config['map']['lon']);
$tpl_map->assignVar('initZOOM', $ini_config['map']['zoom']);
$tpl_index->assignVar('map', $tpl_map->generate());


/*
* All done: print the page
*/
$tpl_index->render();




/************************* LIBS ****************************/

/*
* Calculate approximate radio range (VHF radio horizon)
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
    function HTMLTemplate($tpl) {
        if (!is_readable($tpl)) {
            print("Setup error: template file not readable: ".$tpl);
            exit(1);
        }
        $this->template_src = file_get_contents($tpl);
    }

    /**
    * Add some variable content
    */
    public function assignVar($variable, $tpl_index) {
        $this->variables[$variable] = $tpl_index;
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
