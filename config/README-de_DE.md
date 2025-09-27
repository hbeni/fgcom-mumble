FGCom-mumble - eine (Flugsimulator-) Funksimulation basierend auf Mumble
=======================================================================

<img src="server/statuspage/inc/fgcom_logo.png" width="100px" align="left" />
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
- [client/radioGUI/Readme.RadioGUI.md](client/radioGUI/Readme.RadioGUI.md) Doku der Radio GUI Anwendung
- [client/fgfs-addon/Readme.md](client/fgfs-addon/Readme.md) Details über das Flightgear-Addon
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
Das ZIP Releasepaket enthält die plugins für alle unterstützten Betriebssysteme im `mumble_plugin`-bundle.

Es gibt verschiedene Installationsmethoden:

### GUI Methode (empfohlen)
Nach der Installation von Mumble kann das Plugin üblicherweise mit einfachem Doppelklick auf die `.mumble_plugin`-Datei installiert werden.

Ansonsten kannst du den integrierten Plugin-installer von Mumble benutzen:
- Starte Mumble.
- In Mumbles *Konfiguration/Einstellungen/Plugins* Fenster: aktiviere *Plugin installieren*.
- wähle das `.mumble_plugin` Plugin-bundle aus. Mumble installiert daraufhin das Plugin und meldet dessen Erfolg.
- Suche in der Pluginliste nach dem neuen *FGCom-mumble*-Plugin und aktiviere es.
- Fertig!

### Manuelle Installation auf der Kommandozeile
Die Installation kann auch über eine Kommandozeile gestartet werden, indem man das Binärrelease als Parameter angibt; z.B.: `mumble fgcom-mumble-0.14.1.mumble_plugin`

### Manuelle Installation durch Dateikopieren
- Benenne die `.mumble_plugin`-Datei in `.zip` um und entpacke sie.
- Wähle die für dein Betriebssystem passende Plugin-Binärdatei aus. Das FGCom-mumble Plugin muss in den `plugins`-Ordner von mumble kopiert werden:
  - `fgcom-mumble.so` for Linux (64 bit)
  - `fgcom-mumble.dll` for Windows (64 bit)
  - `fgcom-mumble-x86_32.dll` for Windows (32 bit)
  - `fgcom-mumble-macOS.bundle` für MacOS
- Von dort aus erkennt Mumble es automatisch und du kannst es über den "Plugins"-Dialog aktivieren.


Aktualisieren (update Prozedur)
-------------------------------
Wenn Mumble startet, sucht es auf GitHub nach der aktuellsten Pluginversion.
Das plugin auto-update kann in den mumble Einstellungen deaktiviert sein.

Falls eine aktuellere Version gefunden wird, fragt Mumble, ob du diese installieren möchtest. Bejast du, lädt Mumble die neue Version herunter und installiert sie automatisch über die Vorhandene.  
Alternativ kannst du die neue Version auch manuell herunterladen und wie oben beschrieben installieren.


Plugin konfigurieren
-----------------------
Normalerweise sind die Standardeinstellungen des Plugins ausreichend. Falls doch nicht, können einige Features (wie das Abschalten der Audioeffekte wie Rauschen, oder der Port des UPD-Servers, oder die Erkennung des speziellen Chatraums) abweichend konfiguriert werden.

Dies kannst du tun, indem du die [`fgcom-mumble.ini`](../configs/fgcom-mumble.ini) Beispieldatei in dein Benutzer-Heimatverzeichniss kopierst und dann entsprechend anpasst. Die Datei wird dann beim Initialisieren des Plugins einmalig von folgenden Orten geladen (in dieser Reihenfolge):

- Linux:
  - `/etc/mumble/fgcom-mumble.ini`
  - `<home>/.fgcom-mumble.ini`
  - `<home>/fgcom-mumble.ini`
- Windows:
  - `<home>\fgcom-mumble.ini`
  - `<home>\Documents\fgcom-mumble.ini`



Das Plugin einsetzen
====================
- Verbinde dich auf den mumble server
- Aktiviere das FGCom-mumble plugin
- betrete einen Chatraum der mit `fgcom-mumble` beginnt

Jetzt bist du bereit, am Funkverkehr teilzunehmen!  
Dein Flugsimulator oder ATC-Programm muss dem Plugin nun die notwendigen Informationen senden, damit es weiß, wo du bist und welche Funkgeräte zur Verfügung stehen.


### Allgemeine Kompatibilität
Das Plugin versucht, weitestgehend zum alten FGCom UDP Protokoll kompatibel zu bleiben, d.h. alle halbwegs aktuellen Flightgear und ATC-Instanzen
sollten kompatibel sein (zumindest mit dem ersten Funkgerät COM1).

Bitte beachte, dass "Frequenzen" alles mögliche sein können. Dies bedeutet, dass alle teilnehmenden Pogramme im System sich auf eine gemeinsame Definition von "Frequenz" einigen müssen.
Dies sollte daher der kleinste gemeinsame Nenner sein, d.h. die physikalische Frequenz der Trägerwelle (vor allem mit 8.33kHz Kanälen, bei denen die im Gerät angewählte Frequenz nicht immer der physikalischen entspricht).
Im Protokoll haben Fließkommazahlen außerdem immer den Punkt (`.`) als Dezimaltrenner; das Komma ist als Feldtrenner nicht erlaubt.

Obwohl wir davon ausgehen, dass die verbundenen Simulatoren Informationen für das PTT der Funkgeräte übermitteln, kannst du über die Konfigurationsdatei Zuordnungen für mumble's interne Sendeaktivierung definieren. Auf diese Weise kannst du beispielsweise mit mumbles eigenem PTT-Tastenkürzel das Senden deiner Funkgeräte aktivieren. Standardmäßig ist bereits das erste Funkgerät entsprechend konfiguriert, d.h. mumbles internes PTT aktiviert gleichzeitig das PTT des ersten Funkgerätes.


### RadioGUI
FGCom-mumble liefert eine plattformunabhängige Java-Applikation mit, die die meisten UDP-Protokollfelder implementiert. Dadurch eignet sich RadioGUI nicht nur zum testen, sondern auch für echte Aufgaben wie ATC ohne die Notwendigkeit eines weiteren Clients.

#### SimConnect (MSFS-2020) support
RadioGUI kann als Brücke zu SimConnect-Kompatiblen Simulatoren fungieren (z.B. MSF-S2020, P3d, FSX, etc).
Weitere Details stehen im Readme des RadioGUI.


### Flightgear spezifisch
- Füge den ordner `fgfs-addon` aus dem entpackten client-release als Addon im Launcher hinzu.
- Aktiviere das [FGFS-addon](client/fgfs-addon/Readme.md) in deinem Launcher (FGCom-Mumble und das alte FGCom können parallel aktiviert werden).
- FlightGear sendet dann automatisch die notwendigen Daten an mumble (mit Standardparametern; diese können über das *Mehrspieler*-Menü geändert werden).

Die FGFS-Protokolldefinition unterstützt alte 25kHz- genauso wie neuere 8.3kHz Funkgeräte.
Nachdem Flightgear gestartet wurde, kannst du die Funkgeräte wie gewohnt benutzen (Standard ist *Leertaste* für Sprechen auf COM1 und *Umschalt-Leetaste* für COM2). Weitere Geräte können über eigene Tastenkürzel oder die _Combar_ angesprochen werden.

Der ADF-Empfänger misst Übertragungen im kHz-Band und zeigt im _ADF_-Modus die Empfangsrichtung auf der Instrumentennadel des ADF-Instrumentes an. Empfangene anaolge Signale können zudem wiedergegeben werden. Dies wird üblicherwiese im Audiopanel des Flugzeugs aktiviert.

### ATC-Pie specific
ATC-Pie hat seit v1.7.1 eingebaute Unterstützung für FGCom-mumble. Stelle sicher, dass du die fgcom-mumble Option aktivierst, denn fgcom alleine unterstützt nur COM1.


### OpenRadar spezifisch
Aktuell unterstützt OpenRadar nur ein Funkgerät pro UDP Port. Falls du also mehrere Funkgeräte benutzen möchtest (was sehr wahrscheinlich ist), musst du mehrere parrallele mumble-Instanzen mit jeweils aktivietem FGCom-Plugin  starten (`mumble -m`).
Dies erzeugt pro Plugin einen eigenen UDP-Port, die in OpenRadar bei "fgcom standalone" Kommasepariert angegeben werden können.

Für die bessereUnterstützung von FGCom-mumble sind bereits [patches eingereicht](https://sourceforge.net/p/openradar/tickets/) und es gibt eine [kompilierte Version](https://github.com/hbeni/openradar/releases).  
Mit dieser Unterstützung kann man FGCom-mumble auswählen und dann einfach mehrmals den gleichen Port für jedes gewünschte Funkgerät angeben (bspw. "`16661,16661`" für zwei Geräte, die mit der einzigen Plugininstanz verbunden werden).


Spezielle FGCom Frequenzen
-------------------------------------
Eine allgemeine Anforderung von Piloten ist, Anfangs testen zu können, ob ihr Setup funktioniert.
Dafür wurde ein spezieller mumble-Bot bereitgestellt.

Bitte beachte, dass es keine global empfangbare Sprechfrequenz gibt. Dies kann allerdings über einen Festnetzkanal simuliert werden (stelle die Frequenz `PHONE:<irgendwas>` ein siehe unten).

### ATIS

ATIS-Aufzeichnung und -Wiedergabe wird über je einen speziellen serverseitigen Mumble-Bot implementiert. Schau vor einem Versuch nach, ob der `recorder`-Bot eingewählt ist.

Aufzeichnung
------------
Um eine ATIS-Aufzeichnung aufzunehmen, musst du:

- Dein Rufzeichen auf das ATIS-Zielrufzeichen stellen (der Wiedergabe-Bot wird dieses Rufzeichen verwenden)
- Deine Position festgelegt haben; stelle vor allem auch eine angemessene Höhenangabe sicher, denn das beeinflusst die Funkreichweite bei VHF maßgeblich!
- Wäle die "Frequenz" `RECORD_<tgtFrq>`
- Starte die Aufnahme des Funkgeräts mittels Aktivieren der psh-to-talk taste
- Wenn die Aufnahme fertig ist, lasse den PTT-Knopf wieder los

Normale Aufnahmen haben standardmäßig ein Serverseitigs Limit von 120 Sekunden.

Bitte beachte: Es ist wahrscheinlich, dass dein ATC-Programm dies alles für dich bereits erleidgt und du nur einen "ATIS-Aufnahme"-Knopf zu drücken brauchst.  
Die FGCom-mumble RadioGUI hat eine Frequenzvorlage hierfür. Es könnte eine gute Idee sein, für die Aufnahme eine separate Instanz der RadioGUI zu starten, damit die Orgiginaldaten der ersten Verbindung unberührt bleiben.

Wiedergabe
------------
Läuft auf dem Server ein `botmanager`, wird der Recorderbot dafür sorgen, dass der manager einen passenden `playback`-bot startet. Der Aufzeichnende User ist standardmäßig mit ihm authentifiziert und kann ihn über Chatkommandos steuern (sag zum Start `/help` zu ihm).


### Festnetz / Intercom
Festnetz und Intercoms ist ein Feature, das vor allem für ATC-Clients gedacht ist. Solche Verbindungen unterliegen keiner Reichweitenbeschränkung, operieren in Vollduplex und haben immer perfekte Signalqualität.  
Festnetznamen beginnen mit `PHONE` und Intercom mit `IC:`. Sie unterscheiden sich nur im Toneffekt.

Um auf einer Festnetzleitung zu sprechen musst du:

- Ein Funkgerät auf die Frequenz `PHONE:[ICAO]:[POS](:[Leitung])` stellen, z.B. `PHONE:EDDM:TWR:1` oder `PHONE:EDMO:GND`.

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
- 123.450 MHz, 123.500 MHz, 122.750 MHz: allgemeine Sprechfrequenzen (diese sind seit Einführung der 8.33-Kanälen am 20.12.2019 sowiso veraltet -> neu: 122.540, 122.555, 130.430 MHz);
- 700.000 MHz: Radiosenderfrequenz (abhängig von der alten FGCom-Implementierung)
- 723.340 MHz: Mil. Frequenz (Fanz. Flugpatroullie)


### Spezielle FGCom-mumble Frequenzen
- `<del>`: Einstellen dieser Frequenz meldet ein vorhandenes Funkgerät ab. Ein Funkgert auf dieser "Frequenz" ist nie aktiv und kann daher weder empfangen noch senden.


Fehlerbehebung
------------------------
Falls du andere Piloten nicht hören kannst, oder nicht senden kannst, prüfe die folgenden Punkte:

- Stelle sicher, dass mumle an sich gut funktioniert (d.h. du kannst ohne Plugin gut senden und hören)
- Prüfe den Kommentar deines Mumbleclients, ob das Callsign und die Funkgeräte registriert wurden.
- Prüfe, ob du auf der Statuswebseite angezeigt wirst (das zeigt die Daten, die andere sehen)
- Um zu senden, musst du PTT des Funkgerätes aktivieren, es reicht nicht, mumbles eingebautes PTT-kürzel zu benutzen!
- Versuche, deine Einstelllungen mit dem FGCOM-Echo bot zu prüfen Frequenz `910.00` anwählen und übertragen; dies benötigt allerdings den Recorder-Bot am Server)
- Stelle sicher, dass du nicht versehentlich überträgst, wenn du andere hören möchtest (Funkgeräte sind Halbduplex, d.h. nur einer kann gleichzeitig senden -> Prüfe dein mumble-Symbol, um zu sehen, dass du aktuell nicht übeträgst)
- Prüfe nochmal die angewählte Frequenz und Lautstärkeeinstellung des Funkgerätes
- Stelle sicher, dass das Funkgerät Betriebsbereit ist (ist es angeschaltet? hat es Strom? Ist es defekt?)
- Stelle sicher, dass du wirklich in Reichweite bist (niedrige Flughöhe begrenzt die Reichweite drastisch!)
- Versuche, den `fgcom-mumble`-Channel zu verlassen und neu zu betreten; alternativ kannst du mumble nochmal neu starten.
- Stelle sicher, dass die Clientsoftware (ATC, Flugsimulator) wirklich daten an den UDP-Port des Plugins übermittelt. Prüfe auch den Port des Plugins nochmal nach (die Portnummer wird vom Plugin in den Mumble-Chat berichtet).
- Prüfe die Plugin-Debugnachrichten (Starte dafür mumble über eine Kommandozeile; du brauchst außerdem eine spezielle Pluginversion mit aktiver Debug-Konfiguration)
- Prüfe das murmur server Fehlerlog nach Nachrichten zu abgewiesenen Pluginnachrichten (`Dropping plugin message`), diese können zum Verlust der Synchronizität führen. Ursachen können sein:
  -  Die Einstellung *`pluginmessagelimit`* in der `murmur.ini` ist möglicherweise zu restriktiv.
  - Ein Fehler im Plugin-IO Code: dieser sollte gut mit den Standardeinstellungen funktionieren. Verworfene Nachrichten können auf einen Codefehler hinweisen, insbesondere wenn sie in rascher Abfolge über eine längere Zeit auftauchen.


Das Plugin selbst Kompilieren
=============================
Das FGCom-mumble plugin muss in Maschinensprache vorliegen, um von Mumble geladen werden zu können.
Um den aktuellsten Quellcode zu benutzen, kannst du das Plugin selbst übersetzen. Das makefile ist primär für Linux, funktioniert aber auch für Windows und macOS.  

- Vorraussetzungen:
  - `git`, `make`, `g++`, `mingw32` (für Windows-Erzeugung unter Linux)
  - OpenSSL: Linux baut dynamisch gegen das installierte `libssl-dev`. MingW/Windows linkt statisch gegen einen Bau des git submodules `lib/openssl` durch den Auruf von `make openssl-win`.

- Bauen:
  - Lade den aktuellen source herunter: `git clone https://github.com/hbeni/fgcom-mumble.git`
  - Geh in das Projektverzeichnis: `cd fgcom-mumble`
  - Unter Linux, tippe `make plugin`
  - oder `make plugin-win64`, um eine Kreuzkompilierung für Windows auszuführen

Weitere interessante make buildtargets:

  - `make` ist ein Alias für `make release`
  - `make release` baut einen Satz Release-ZIP Dateien
  - `make debug` macht baut das Plugin, fügt aber Debuginformationen hinzu. Solche Versionen schreiben ganz viele Informationen auf die Kommandozeile.
  - `make test` baut und startet die catch2-unittests
  - `make tools` baut ein paar Testtools und Werkzeuge


Windows nativer build
---------------------
Das makefile funktioniert auch unter Windows mit cygwin64 und mingw32.  
Du musst lediglich einen anderen Compiler setzen:

- 64bit: `make CC=x86_64-w64-mingw32-g++ plugin-win64`
- 32bit: `make CC=i686-w64-mingw32-g++ plugin-win32`


MacOS nativer build
-------------------
Es gibt einen alias für macOS: `make plugin-macOS`, der das folgende tut:

- Du musst den Compiler _g++-11_ explizit setzen, da das Standard _g++_-Kommando ein alias auf _clang_ ist. Darüberhinaus musst du den OpenSSL-Pfad anpassen:  
`make outname=fgcom-mumble-macOS.bundle CC=g++-11 CFLAGS="-I/usr/local/opt/openssl/include/ -L/usr/local/opt/openssl/lib/" plugin`

- Nach dem bauen benennst du die Plugindate am besten in `fgcom-mumble-macOS.bundle` um, um kompatibel mit den offiziellen Releases zu bleiben.
