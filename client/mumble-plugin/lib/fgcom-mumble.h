// Define opwn plugin api
//

#ifndef FGCOM_MUMBLE_H
#define FGCOM_MUMBLE_H


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


#endif
