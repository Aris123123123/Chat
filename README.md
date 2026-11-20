# Chatly – privater Mini-Messenger

## Voraussetzungen
- Python 3.10 oder neuer
- Ein SMTP-Mailkonto, über das dein Server E-Mails versenden darf
- Internet/Hosting, wenn andere Personen von außerhalb deines PCs zugreifen sollen

## Installation unter Windows (PowerShell)

```powershell
cd Chatly
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Setze vor dem Start die Umgebungsvariablen. Erzeuge einen langen geheimen Schlüssel und sichere Admin-Zugangsdaten:

```powershell
$env:CHATLY_SECRET_KEY = "HIER_EINEN_LANGEN_ZUFAELLIGEN_WERT_EINTRAGEN"
$env:CHATLY_ADMIN_USER = "admin"
$env:CHATLY_ADMIN_PASSWORD = "HIER_EIN_LANGES_EINZIGARTIGES_PASSWORT"
$env:CHATLY_ADMIN_EMAIL = "deine-adresse@example.com"

$env:SMTP_HOST = "smtp.dein-anbieter.de"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "deine-adresse@example.com"
$env:SMTP_PASSWORD = "DEIN_SMTP_APP_PASSWORT"
$env:SMTP_FROM = "deine-adresse@example.com"

python app.py
```

Danach lokal öffnen: http://127.0.0.1:5000

## Erste Einrichtung
Beim ersten Start wird der Admin-Account automatisch angelegt. Melde dich mit den oben festgelegten Admin-Daten an. Im Adminbereich kannst du Benutzernamen zur Whitelist hinzufügen. Erst dann können diese Namen registriert werden. Nach erfolgreicher E-Mail-Bestätigung muss der Admin den Account zusätzlich freischalten.

## Andere Nutzer erreichen die Website
`127.0.0.1` funktioniert nur auf deinem eigenen PC. Für andere Nutzer brauchst du ein Hosting/einen Server mit öffentlicher HTTPS-Adresse. Setze dort `COOKIE_SECURE=1`, verwende einen starken `CHATLY_SECRET_KEY` und speichere SMTP-Zugangsdaten als geheime Umgebungsvariablen. Starte Flask im öffentlichen Betrieb hinter einem richtigen WSGI-Server (z. B. Waitress oder Gunicorn) und HTTPS-Reverse-Proxy. Nicht den Entwicklungsserver direkt ins Internet stellen.

## Wichtige Grenzen des Prototyps
- JSON-Dateien sind für einen kleinen Test geeignet, aber nicht ideal für viele gleichzeitige Nutzer oder mehrere Serverinstanzen.
- Es gibt noch keine Passwort-zurücksetzen-Funktion, keine Admin-Rollenverwaltung, keine Sperr-/Melde-Funktion und keine Ende-zu-Ende-Verschlüsselung.
- Ergänze vor öffentlichem Einsatz Rate-Limits, sichere Backups, Lösch-/Datenschutzprozesse und gründliche Sicherheitstests.
- Der SMTP-Anbieter muss SMTP-Versand erlauben; oft wird ein App-Passwort benötigt.
- Lege `.env`/Zugangsdaten niemals in ein öffentliches Repository.
