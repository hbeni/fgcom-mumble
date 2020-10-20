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
#include <set>

#ifndef FGCOM_GARBAGECOLLECTOR_H
#define FGCOM_GARBAGECOLLECTOR_H

// Timings for garbage collections
// (remote one must be coherent with the NOTIFYPINGINTERVAL:
//  if its less then ping interval, remote state may be wrongly cleaned)
#define FGCOM_GARBAGECOLLECT_INTERVAL      5000  // ms check interval
#define FGCOM_GARBAGECOLLECT_TIMEOUT_LCL  30000  // ms timeout for local data
#define FGCOM_GARBAGECOLLECT_TIMEOUT_RMT  30000  // ms timeout for remote data



/*
 * Spawn the garbage collector thread.
 */
void fgcom_spawnGarbageCollector();
extern bool fgcom_gcThreadRunning; // will be managed by thread


/*
 * Trigger shutdown of the udp server
 */
void fgcom_shutdownGarbageCollector();


#endif
