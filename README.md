# Postfix Map Agent REST

<p align="center">
  <img src="docs/banner.png" alt="Postfix Map Agent REST" width="900">
</p>

Ein kleiner REST Dienst (Mojolicious Lite), der Postfix Map Dateien pro Instanz verwaltet. Fokus ist Betriebssicherheit: atomare Writes, Backups mit Rotation, per Map Locking und optionaler Reload Status via systemd oder postmulti. Die API loescht **keine** Dateien auf dem Postfix Dateisystem. `delmap` entfernt nur Registrierungen in `configs.json` und liefert Hinweise zur manuellen Bereinigung.

Quelle: Script Stand in fileciteturn0file0

## Features

- REST API fuer Map Dateien pro Instanz (lesen, schreiben, Restore aus Backup)
- Atomare Writes (Temp Datei, Rename)
- Timestamp Backups mit Rotation (Sortierung nach mtime, stabil)
- Per Map Locking (SH und EX) pro Instanz
- Optional `postmap` nur fuer `lmdb` oder andere definierte Typen (via `postmap_by_type`)
- Optionaler Reload und Status Check nach Aenderung (systemd oder postmulti)
- Access Control per CIDR Allowlist und Token Auth (Header `X-API-Token` oder `Authorization: Bearer`)
- Optional `require_https` als Hardblock
- Logging via Mojo::Log in Datei, Format bleibt kompatibel: `YYYY/MM/DD HH:MM:SS LEVEL Nachricht`
- JSON Pretty Canonical Writer fuer `configs.json` Updates

## Schnellstart

### Voraussetzungen

- Perl
- Mojolicious (Lite)
- Module im Script: `Mojo::*`, `Try::Tiny`, `Net::CIDR`, `Time::HiRes`
- Schreibrechte auf `map_dir` pro Instanz, Backup Verzeichnisse, Logfile Pfad
- Root oder ein dedizierter Service User, je nach Postfix Setup

### Repo Struktur Vorschlag

~~~text
.
├─ postfix-map-agent.pl
├─ global.json
├─ configs.json
├─ docs/
│  └─ banner.png
└─ systemd/
   └─ postfix-map-agent.service
~~~

### Starten

Token setzen und starten:

~~~bash
export API_TOKEN='change-me'
perl ./postfix-agent.pl daemon
~~~

Standard Listen Adresse ist `0.0.0.0:5000`, konfigurierbar in `global.json`.

Health Check:

~~~bash
curl -s http://127.0.0.1:5000/health
~~~

## Konfiguration

Beim Start erwartet das Script **zwingend** diese Dateien im `app->home` Verzeichnis:

- `global.json`
- `configs.json`

Wenn eine fehlt, bricht der Start ab.

### global.json Beispiel

~~~json
{
  "secret": "change-this-long-random-secret-please",
  "api_token": "set-a-token-here-or-use-env",
  "listen": "0.0.0.0:5000",

  "allowed_ips": ["127.0.0.1/32", "10.0.0.0/8"],

  "logfile": "/var/log/mmbb/postfix-agent.log",

  "serviceUser": "root",
  "serviceGroup": "root",
  "fileMode_service": "0644",
  "fileMode_backup": "0660",

  "tmpDir": "/tmp",
  "lockDir": "/var/lock/postfix-agent",
  "backupDir": "/var/backups/postfix-agent",

  "ssl_enable": 0,
  "ssl_cert_file": "/etc/ssl/certs/agent.crt",
  "ssl_key_file": "/etc/ssl/private/agent.key",
  "require_https": 0,

  "dirs": {
    "service_folder": ["backupDir", "lockDir"],
    "service_mode": "0770"
  }
}
~~~

Wichtige Punkte:

- `API_TOKEN` ist Pflicht. Entweder als ENV `API_TOKEN` oder `global.json` Feld `api_token`.
- `allowed_ips` ist eine CIDR Liste. Default faellt auf `127.0.0.1`, wenn nicht gesetzt.
- Umask ist im Script restriktiv: `0007`. Das passt gut fuer Group RW, Other none.
- `require_https` blockiert Requests, die nicht ueber HTTPS kommen. Das ist zusaetzlich zu TLS Listen.

### configs.json Beispiel

Es gibt zwei moegliche Formen. Das Script akzeptiert beides.

Variante mit Wrapper `instances`:

~~~json
{
  "instances": {
    "main": {
      "map_dir": "/etc/postfix",
      "config_dir": "/etc/postfix",
      "backup_dir": "/var/backups/postfix-agent/main",
      "lock_dir": "/var/lock/postfix-agent/main",

      "max_backups": 5,
      "reload_on_change": true,

      "reload_cmd": "systemctl reload postfix",
      "status_cmd": "systemctl status postfix --no-pager",

      "globs": {
        "virtual": "hash",
        "*.lmdb": "lmdb",
        "sender_access": "hash"
      },

      "postmap_by_type": {
        "lmdb": "postmap -c {config_dir} lmdb:{path}",
        "hash": "postmap -c {config_dir} hash:{path}"
      }
    }
  }
}
~~~

Variante flach ohne Wrapper:

~~~json
{
  "main": {
    "map_dir": "/etc/postfix",
    "config_dir": "/etc/postfix"
  }
}
~~~

`globs` steuert zwei Dinge:

1) Welche Maps in `/instances/:inst/maps` angezeigt werden, wenn `all` nicht gesetzt ist  
2) Welcher `postmap` Typ fuer eine Datei gilt. Es wird zuerst exaktes Match versucht, dann Pattern mit `*`.

Sicherheitsregel im Code:

- `main.cf` und `master.cf` sind **verboten** und koennen nicht ueber die API gelesen oder geschrieben werden.

## Auth und Zugriff

Jeder Request muss zwei Bedingungen erfuellen:

1) IP muss in `allowed_ips` liegen (CIDR lookup)  
2) Token muss stimmen, per Header:

- `X-API-Token: <token>`  
oder  
- `Authorization: Bearer <token>`

Sonst gibt es `403 Forbidden` oder `401 Unauthorized`.

CORS:

- Setzt `Access-Control-Allow-Origin` dynamisch auf `Origin` Header
- Erlaubt `GET, POST, DELETE, OPTIONS`
- Erlaubt Header `Content-Type, X-API-Token, Authorization`

## API Endpoints

### GET /

Info Endpoint.

Antwort:

~~~json
{ "info": "Postfix Agent", "version": "1.5.1" }
~~~

### GET /health

Prueft ob benoetigte Verzeichnisse existieren. Liefert `ok`.

### GET /instances

Listet Instanzen aus `configs.json`.

### GET /instances/:inst/maps?all=1

Listet Maps.

- Ohne `all=1` werden nur Dateien ermittelt, die durch `globs` abgedeckt sind, ausser `globs` ist leer  
- Mit `all=1` werden Dateien im `map_dir` gelesen (nur Files, keine Dotfiles)

### GET /instances/:inst/map/*map

Liest eine Map Datei als `text/plain; charset=UTF-8`.

### POST /instances/:inst/map/*map

Speichert Map Inhalt.

Input Wege:

- `Content-Type: application/json` mit `{ "content": "..." }`
- Form Param `content=...`
- Raw Body wird als UTF 8 dekodiert

Antwort enthält u a:

- `changed` ob Inhalt anders war
- `backup` ob Backup gemacht wurde
- `postmap` Ergebnis, falls ausgefuehrt
- `reload` und `status`, falls `reload_on_change` aktiv und Kommandos gesetzt

Beispiel:

~~~bash
curl -s \
  -H "X-API-Token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"user@example.org OK\n"}' \
  http://127.0.0.1:5000/instances/main/map/sender_access
~~~

### GET /instances/:inst/backup/*map

Listet Backups fuer eine Map. Sortiert nach mtime absteigend.

### GET /instances/:inst/backupfile/*backup?mode=text|download|json

Liest ein bestimmtes Backup.

- `mode=text` default, liefert Text
- `mode=download` liefert Octet Stream Attachment
- `mode=json` liefert JSON mit `content` als String

### POST /instances/:inst/restore/*backupfile

Stellt ein Backup wieder her. Danach optional `postmap`, `reload`, `status` je nach Instanz Config.

### POST /instances/:inst/delmap/*map

Deregistriert eine Map nur in `configs.json` und liefert Hinweise.

Wichtig:

- Es wird **keine** Datei geloescht.
- Kein Reload wird ausgefuehrt.

### GET /instances/:inst/globs

Liest `globs` der Instanz aus `configs.json`.

### POST /instances/:inst/globs

Upsert fuer `globs`.

Payload Beispiele:

~~~json
{ "map": "*.lmdb", "type": "lmdb" }
~~~

oder mehrere:

~~~json
{ "items": [ { "map": "virtual", "type": "hash" }, { "map": "*.lmdb", "type": "lmdb" } ] }
~~~

Erlaubte Typen:

`regexp, pcre, cidr, lmdb, hash, btree, db`

### DELETE /instances/:inst/globs/:map

Entfernt einen einzelnen Key aus `globs`.

## Betrieb, Systemd und Service User

### systemd Service Beispiel

~~~ini
[Unit]
Description=Postfix Map Agent REST
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/postfix-map-agent
Environment=API_TOKEN=change-me
ExecStart=/usr/bin/perl /opt/postfix-map-agent/postfix-agent.pl daemon
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
~~~

Hinweise:

- Wenn du nicht als root laufen willst, muessen `map_dir` und Backup Pfade passend berechtigt sein.
- Umask ist im Script 0007. Das ist ok, wenn die Gruppe korrekt gesetzt ist.

## Sicherheitshinweise

- Setze `allowed_ips` restriktiv und nutze am besten nur interne Netze oder localhost plus Reverse Proxy.
- Token nicht in Logs oder Tickets kopieren.
- Wenn ueber Internet erreichbar, zwinge TLS. Entweder `ssl_enable` plus cert key oder via Reverse Proxy und `require_https=1`.
- Map Name Sanitizing blockiert Pfad Traversal und erlaubt nur `[0-9A-Za-z._-]`.
- `main.cf` und `master.cf` sind gesperrt.

## Troubleshooting

### 401 Unauthorized

Token fehlt oder stimmt nicht. Header pruefen:

~~~bash
-H "X-API-Token: $API_TOKEN"
~~~

oder:

~~~bash
-H "Authorization: Bearer $API_TOKEN"
~~~

### 403 Forbidden

IP ist nicht in `allowed_ips`. Remote IP ist die TCP Quelle. Falls Reverse Proxy genutzt wird, brauchst du dort eine passende Network Policy, oder du erlaubst nur den Proxy und laesst den Proxy authentisieren.

### 423 Map locked

Ein anderer Request haelt gerade den Lock. Lock Timeout ist 3 Sekunden.

### postmap oder reload Fehler

In der JSON Antwort stehen `rc` und `output`. Damit siehst du direkt, was schief ging. Achte drauf, dass die Kommandos in `postmap_by_type`, `reload_cmd`, `status_cmd` korrekt sind.

## Lizenz

MIT License. Siehe `LICENSE`.

