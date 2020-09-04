FGCom-mumble - eine (Flugsimulator-) Funksimulation basierend auf Mumble
=======================================================================

Dieses Projekt möchte eine erweiterbare, Mumblebasierende Funksimulation für Flugsimulatoren bereitstellen.
Das Projekt begann hauptsächlich als Nachfolger der Asterisk-basierten FGCom Implementierung für Flightgear.

([-> english original version](README.md)) | [![donate](https://img.shields.io/badge/Halt's_mit_am_laufen-PaypalMe/BeniH-blue)](https://www.paypal.com/paypalme/BeniH/5)

### Die Hauptziele sind:
- Bereitstellung von Funkkommunikation mit geographischer und Kanalseparierung
- Eine realistische Funksimulation
- Einfach für den Endnutzer/Piloten zu benutzen
- Unterstützung für beliebige Frequenzen
- ATIS Aufzeihnung und Wiedergabe
- Unterstützung für Radiosender 
- Unterstützung für Festnetz/Intercom
- RDF Erkennung (Richtungspeilung des Signals)
- Einfachheit der serverseitigen Installatio und des Betriebes
- Unabhängigkeit von einer spezifischen Flugsimulation (z.B. Flightgear); d.h. Offenheit der Schnittstellen
- Integrierbarkeit in Flightgear, mit der Option für Drittsoftware (z.B. ATC, aber auch andere Flugsimulatoren)
- Modularität, damit einzelne Teile der Implementierung einfach ausgetauscht werden können
- Gute und vollständige Dokumentation

Dokumentationsübersicht
=======================
Die deutsche Dokumentation ist eine Übersetzung der englischen und möglicherweise nicht auf dem aktuellsten Stand.  
Die englische Version ist stets führend.

Die Doku ist in folgende Dateien aufgeteilt:

- Readme-de_DE.md (*diese Datei*): allgemeine Übersicht ([englisch](README.md))
- [Readme.architecture.md](Readme.architecture.md) (engl.) Details über die Komponenten des Systems
- [client/plugin.spec.md](client/plugin.spec.md) (engl.) Technische Spezifikation des mumble Plugins und seiner Schnittstellen
- [server/Readme.server-de_DE.md](server/Readme.server-de_DE.md) (deutsch) Details über die serverseitigen Koponenten und ihre Installation/Betrieb
- [server/statuspage/Readme.statuspage.md](server/statuspage/Readme.statuspage.md) (engl.) Technische Details über die Statuswebseite und deren Komponenten

### Fehler melden / Features anfragen / Hilfe anbieten
Dieses Projekt wird auf github gehostet: https://github.com/hbeni/fgcom-mumble

Wenn du ein neues Feature anfragen möchtest, oder einen Fehler gefunden hast, kannst du ihn sehr gerne auf github als "Issue" erfassen.
Ich freue mich auch über Hilfe beim Programmieren! Bitte klone das Projekt und reiche Pullrequests ein.


Installation / Einrichtung des Mumble-plugins
=============================================

Vorraussetzungen
----------------------
- Du brauchst lediglich ein aktuelles Mumble mit Pluginunterstützung (>= v1.4.0)
- Eine aktuelle OpenSSL Installation

Installation
-----------------------
Das compilierte FGCom-mumble Plugin muss in den `plugins`-Ordner von mumble kopiert werden. Von dort aus erkennt Mumble es automatisch und du kannst es über den "Plugins"-Dialog aktivieren.


Das Plugin einsetzen
====================
- Verbinde dich auf den mumble server
- Aktiviere das FGCom-mumble plugin
- betrete den `fgcom-mumble` Chatraum

Jetzt bist du bereit, am Funkverkehr teilzunehmen!  
Dein Flugsimulator oder ATC-Programm muss dem Plugin nun die notwendigen Informationen senden, damit es weiß, wo du bist und welche Funkgeräte zur Verfügung stehen.

### Allgemeine Kompatibilität
Das Plugin versucht, weitestgehend zum alten FGCom UDP Protokoll kompatibel zu bleiben, d.h. alle halbwegs aktuellen Flightgear und ATC-Instanzen
sollten kompatibel sein (zumindest mit dem ersten Funkgerät COM1).

Bitte beachte, dass "Frequenzen" alles mögliche sein können. Dies bedeutet, dass alle teilnehmenden Pogramme im System sich auf eine gemeinsame Definition von "Frequenz" einigen müssen.
Dies sollte daher der kleinste gemeinsame Nenner sein, d.h. die physikalische Frequenz der Trägerwelle (vor allem mit 8.33kHz Kanälen, bei denen die im Gerät angewählte Frequenz nicht immer der physikalischen entspricht).
Im Protokoll haben Fließkommazahlen außerdem immer den Punkt (`.`) als Dezimaltrenner; das Komma ist als Feldtrenner nicht erlaubt.


### Flightgear spezifisch
- Kopiere die Flightgear Protokolldefinitionsdatei in deinen Flightgear Installationsordner unter `Protocol`.
- Starte Flightgear mit aktiviertem fgcom-mumble Protokoll (füge "`--generic=socket,out,10,127.0.0.1,16661,udp,fgcom-mumble`" im Startprogramm als zusätzlichen Parameter hinzu)
- Nachdem Flightgear gestartet wurde, kannst du die Funkgeräte wie gewohnt benutzen (Standard ist *Leertaste* für Sprechen auf COM1 und *Umschalt-Leetaste* für COM2).


### ATC-Pie specific
ATC-Pie hat seit v1.7.1 eingebaute Unterstützung für FGCom-mumble.


### OpenRadar spezifisch
Aktuell unterstützt OpenRadar nur ein Funkgerät pro UDP Port. Falls du also mehrere Funkgeräte benutzen möchtest (was sehr wahrscheinlich ist), musst du mehrere parrallele mumble-Instanzen mit jeweils aktivietem FGCom-Plugin  starten (`mumble -m`).
Dies erzeugt pro Plugin einen eigenen UDP-Port, die in OpenRadar bei "fgcom standalone" Kommasepariert angegeben werden können.


Spezielle FGCom Frequenzen
-------------------------------------
Eine allgemeine Anforderung von Piloten ist, Anfangs testen zu können, ob ihr Setup funktioniert.
Dafür wurde ein spezieller mumble-Bot bereitgestellt.

Bitte beachte, dass es keine global empfangbare Sprechfrequenz gibt. Dies kann allerdings über einen Festnetzkanal simuliert werden (stelle die Frequenz `PHONE:<irgendwas>` ein siehe unten).

### ATIS Aufzeichnung
ATIS Aufzeichnung wird über einen speziellen serverseitigen Mumble-Bot implementiert. Schau vor einem Versuch nach, ob der `recorder`-Bot eingewählt ist.

Um eine ATIS-Aufzeichnung aufzunehmen, musst du:

- Dein Rufzeichen auf das ATIS-Zielrufzeichen stellen (der Wiedergabe-Bot wird dieses Rufzeichen verwenden)
- Deine Position festgelegt haben; stelle vor allem auch eine angemessene Höhenangabe sicher, denn das beeinflusst die Funkreichweite bei VHF maßgeblich!
- Wäle die "Frequenz" `RECORD_<tgtFrq>`
- Starte die Aufnahme des Funkgeräts mittels Aktivieren der psh-to-talk taste
- Wenn die Aufnahme fertig ist, lasse den PTT-Knopf wieder los

Normale Aufnahmen haben standardmäßig ein Serverseitigs Limit von 120 Sekunden.

Bitte beachte: Es ist wahrscheinlich, dass dein ATC-Programm dies alles für dich bereits erleidgt und du nur einen "ATIS-Aufnahme"-Knopf zu drücken brauchst.


### Festnetz / Intercom
Festnetz und Intercoms ist ein Feature, das vor allem für ATC-Clients gedacht ist. Solche Verbindungen unterliegen keiner Reichweitenbeschränkung, operieren in Vollduplex und haben immer perfekte Signalqualität.

Um auf einer Festnetzleitung zu sprechen musst du:

- Ein Funkgerät auf die Frequenz `PHONE:[ICAO]:[POS](:[Leitung])` stellen, z.B. `PHONE:EDDM:TWR:1` pder `PHONE:EDMO:GND`.

- Den push-to-talk Knopf wie üblich benutzen.

Bitte beachte: Es ist wahrscheinlich, dass dein ATC-Programm dies alles für dich bereits erleidgt und du nur einen "Intercom/Festnetz"-Knopf zu drücken brauchst.


### Testfrequenzen
Testfrequenzen werden über einen speziellen serverseitigen mumblebot bereitgestellt. Bitte schau nach, ob der Bot angemeldet ist.

  - 910.000 MHz: Echo-Test Frequenz. Deine Stimme wird nac abgeschlossener Aufnahme abgespielt, was dir ermöglicht, deine Einrichtung zun prüfen und zu hören, wie du von anderen gehört werden würdest.
  Testaufnahmen sind standardmäßig serverseitig auf 10 Sekunden eingeschränkt.
  - NOCH-NICHT-IMPLEMENTIERT: 911.000 MHz: Diese Frequent spielt laufend eine Testaufnahme ab, die dir die Prüfung deiner Enpmfangseinstelllngen ermöglicht. 


### Veraltete FGCom Frequenzen von früher
Die folenden traditionellen FGCom Frequenzen sind nicht mher "speziell", sondern werden über die normale Implementierung abgedeckt (sie waren lediglich wegen Asterisk-Internas speziell).

- 121.000 MHz, 121.500 MHz: Schutzfrequenzen für Notfälle;
- 123.450 MHz, 123.500 MHz, 122.750 MHz: allgemeine Sprechfrequenzen;
- 700.000 MHz: Radiosenderfrequenz (abhängig von der alten FGCom-Implementierung)
- 723.340 MHz: Mil. Frequenz (Fanz. Flugpatroullie)


### Spezielle FGCom-mumble Frequenzen
- `<del>`: Einstellen dieser Frequenz meldet ein vorhandenes Funkgerät ab. Ein Funkgert auf dieser "Frequenz" ist nie aktiv und kann daher weder empfangen noch senden.


Fehlerbehebung
------------------------
Falls du andere Piloten nicht hören kannst, oder nicht senden kannst, prüfe die folgenden Punkte:

- Stelle sicher, dass mumle an sich gut funktioniert (d.h. du kannst ohne Plugin gut senden und hören)
- Versuche, deine Einstelllungen mit dem FGCOM-Echo bot zu prüfen Frequenz `910.00` anwählen und übertragen; dies benötigt allerdings den Recorder-Bot am Server)
- Stelle sicher, dass du nicht versehentlich überträgst, wenn du andere hören möchtest (Funkgeräte sind Halbduplex, d.h. nur einer kann gleichzeitig senden -> Prüfe dein mumble-Symbol, um zu sehen, dass du aktuell nicht übeträgst)
- Prüfe nochmal die angewählte Frequenz und Lautstärkeeinstellung des Funkgerätes
- Stelle sicher, dass das Funkgerät Betriebsbereit ist (ist es angeschaltet? hat es Strom? Ist es defekt?)
- Stelle sicher, dass du wirklich in Reichweite bist (niedrige Flughöhe begrenzt die Reichweite drastisch!)
- Versuche, den `fgcom-mumble`-Channel zu verlassen und neu zu betreten.
- Stelle sicher, dass die Clientsoftware (ATC, Flugsimulator) wirklich daten an den UDP-Port des Plugins übermittelt. Prüfe auch den Port des Plugins nochmal nach (die Portnummer wird vom Plugin in den Mumble-Chat berichtet).
- Prüfe den Kommentar deines Mumbleclients, ob das Callsign und die Funkgeräte registriert wurden.
- Prüfe die Plugin-Debugnachrichten (Starte dafür mumble über eine Kommandozeile; du brauchst außerdem eine spezielle Pluginversion mit aktiver Debug-Konfiguration)


Das Plugin selbst Kompilieren
=============================
Das FGCom-mumble plugin muss in Maschinensprache vorliegen, um von Mumble geladen werden zu können.
Um den aktuellsten Quellcode zu benutzen, kannst du das Plugin selbst übersetzen.  

- Vorraussetzungen:
  - `git`, `make`, `g++`, `mingw32` (für Windows-Erzeugung unter Linux)
  - OpenSSL: Linux baut dynamisch gegen das installierte `libssl-dev`. MingW/Windows linkt statisch gegen einen Bau des git submodules `lib/openssl` durch den Auruf von `make openssl-win`.

- Bauen:
  - Geh in das Verzeichnis `client/mumble-plugin/`
  - Unter Linux, tippe `make`
  - oder `make all-win64`, um eine Kreuzkompilierung für Windows auszuführen

Weitere interessante make buildtargets:

  - `make` ist ein Alias für `make all`
  - `make all` baut alles verfügbare für Linux: die Bibliotheken, das Plugin, sowie einige Testwerkzeuge im Testverzeichnis
  - `make all-debug` macht das gleiche, fügt aber Debuginformationen hinzu. Solche Versionen schreiben ganz viele Informationen auf die Kommandozeile.
  - `make plugin` baut lediglich das Plugin für Linux
  - `make plugin-win64` baut das Plugin für Windows
  - `make release` baut ein Releasepaket (je ein `tar.gz` und `zip`, dass die Linux/Windows Binärdateien enthält)
