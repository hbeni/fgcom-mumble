/* 
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
 */

//
// Define own plugin api
//
#ifndef FGCOM_MUMBLE_H
#define FGCOM_MUMBLE_H

#include <string>
#include "lib/radio_model.h"

// Plugin Version
#define FGCOM_VERSION_MAJOR 1
#define FGCOM_VERSION_MINOR 1
#define FGCOM_VERSION_PATCH 1


#define SIGNAL_INTERPOLATE_MS  500  // timeframe for signal quality interpolation
#define MAX_AUDIO_BUFFER_SIZE   (1024 * 1024)  // Maximum audio buffer size (1MB)


/*
 * Is the plugin currently active?
 * 
 * @return bool true if yes
 */
bool fgcom_isPluginActive();

/*
 * Handle PTT change of local user
 * 
 * This will check the local radio state and activate the mic if all is operable.
 * When no PTT or no radio is operable, mic is closed.
 */
void fgcom_handlePTT();

/*
 * See if the radio is operable
 * 
 * @param fgcom_radio the radio to check
 * @return bool true, wehn it is
 */
bool fgcom_radio_isOperable(fgcom_radio r);

/*
 * Update client comment
 */
void fgcom_updateClientComment();

/*
 * Initialize Mumble plugin configuration interface
 * 
 * This function integrates with Mumble's plugin configuration system
 * It provides a standardized way to configure plugin settings through Mumble's UI
 */
void initializeMumblePluginConfig();

/*
 * Handle configuration changes from Mumble's UI
 * 
 * This function is called when configuration values change through Mumble's UI
 * @param key Configuration key that changed
 * @param value New configuration value
 */
void handleConfigurationChange(const std::string& key, const std::string& value);

/*
 * Apply configuration changes to running systems
 * 
 * This function updates the running plugin systems with new configuration values
 */
void applyConfigurationChanges();

#endif
