#!/usr/bin/env perl
# Postfix Map Agent - REST
# Version: 1.4.16-hardened-compatible (2026-07-14)
#
# Änderungen ggü. 1.4.15:
# - run_command_capture überwacht die Kind-PID auch dann weiter, wenn stdout
#   und stderr bereits geschlossen sind. Der konfigurierte Timeout kann dadurch
#   nicht mehr in einem blockierenden waitpid verloren gehen.
# - JSON-Map-Inhalte werden strikt geparst: ungültiges JSON sowie Arrays/Objekte
#   ohne skalaren content-Wert liefern HTTP 400. Raw-Body-UTF-8 wird verlustfrei
#   validiert und nie still durch U+FFFD ersetzt.
# - Überlappende Globs werden deterministisch nach Spezifität ausgewertet
#   (exakter Key, längster Literalanteil, wenigste Wildcards, lexikalischer Tie-Break).
# - Ein Statuskommando mit Exit-Code 0 gilt auch ohne Textausgabe als erfolgreich.
# - Map- und Backup-Lesezugriffe öffnen reguläre Dateien mit O_NOFOLLOW und
#   fstat-Prüfung. Backups werden symlinksicher und atomar geschrieben.
# - Glob-Upserts validieren jedes Array-Element und lehnen widersprüchliche
#   Mehrfachdefinitionen desselben Map-Keys ab.
#
# Änderungen ggü. 1.4.14:
# - Die reine Endungssperre für .lmdb/.db/.dir/.pag wurde durch eine Prüfung des
#   tatsächlichen Dateiinhalts ersetzt. Registrierte Text-Quelldateien mit einer
#   solchen Endung bleiben zulässig; binäre DB-Artefakte werden abgelehnt.
#
# Änderungen ggü. 1.4.13:
# - DELETE /instances/:inst/globs/#map verwendet jetzt einen relaxed
#   Placeholder. Dadurch funktionieren auch registrierte Map-Keys mit Punkten
#   wie check_sender.regexp oder transport.lmdb.source.
# - Gelöscht wird ausschließlich ein exakt in configs.json -> globs
#   registrierter Key. Wildcard-Muster werden nicht aufgelöst und es werden
#   weiterhin keinerlei Dateien im Postfix-Dateisystem gelöscht.
# - Nicht registrierte Keys führen zu HTTP 404 und configs.json wird dabei
#   weder geschrieben noch neu aufgebaut.
#
# Änderungen ggü. 1.4.12:
# - validate_config verwendet beim globalen backupDir-Fallback jetzt immer das
#   tatsächlich übergebene Global-Objekt; Reload-Prüfungen greifen nicht mehr
#   versehentlich auf die vorherige globale Konfiguration zu.
# - allowed_ips wird vollständig beim Start/Reload normalisiert und mit
#   Net::CIDR::cidrvalidate geprüft; fehlende Angabe bleibt kompatibel und wird
#   auf 127.0.0.1/32 gesetzt. Der Request-Hook verwendet nur vorvalidierte Werte.
# - Konfiguration wird vor dem Anlegen bzw. chmod/chown von Dienst-, Backup- und
#   Temp-Verzeichnissen vollständig validiert.
# - JSON content muss ein Skalar sein; Arrays/Objekte liefern HTTP 400 und werden
#   nicht als Perl-Referenztext in eine Map geschrieben.
# - waitpid wird bei EINTR wiederholt; sonstige sysread-Fehler beenden und reapen
#   den Kindprozess kontrolliert statt als EOF zu gelten. syswrite behandelt
#   EINTR korrekt und einen Null-Write als Fehler.
#
# Änderungen ggü. 1.4.11 (aus gezieltem Security-/Robustheitstest):
# - KRITISCH: Ohne explizit gesetztes allowed_ips fiel der Code auf
#   ['127.0.0.1'] zurück, aber Net::CIDR::cidrlookup verlangt zwingend eine
#   CIDR-Notation mit Prefix. Der Aufruf warf eine Exception, die von eval()
#   still verschluckt wurde: JEDE Anfrage wurde als "Forbidden" abgelehnt,
#   auch von localhost. Verifiziert reproduzierbar. Default korrigiert auf
#   '127.0.0.1/32', zusätzlich werden alle konfigurierten allowed_ips-Einträge
#   ohne Prefix automatisch normalisiert (/32 bzw. /128), damit derselbe
#   Fehler nicht bei eigener Fehlkonfiguration erneut auftritt. Fehler beim
#   CIDR-Lookup werden jetzt zusätzlich geloggt statt still zu verschwinden.
# - KRITISCH: Request-Body über app->max_request_size (2 MiB) wurde von
#   Mojolicious still gekürzt, die Antwort meldete trotzdem Erfolg.
#   Verifiziert: 5-MB-Upload wurde auf exakt 2 MiB gekürzt, ok=1. Body wird
#   jetzt vor und nach dem Lesen auf is_limit_exceeded geprüft, HTTP 413 bei
#   Überschreitung statt stillem Datenverlust.
# - Waisenprozess-Schutz: setpgid($pid,$pid) aus dem Elternprozess nach
#   open3 schlägt zuverlässig fehl, sobald das Kind bereits exec't hat
#   (praktisch immer der Fall). Verifiziert: ein von reload_cmd gestarteter
#   Hintergrundprozess überlebte den Timeout-Kill. Ersetzt durch setsid(1)-
#   Wrapper (wie bei config_manager erprobt), exec't ohne zusätzlichen Fork
#   in-place, setzt aber eine neue Prozessgruppe.
# - sysread-Fehler durch EINTR wurden wie ein echtes EOF behandelt
#   (Stream wurde vorzeitig als beendet markiert). Jetzt wird bei EINTR der
#   Lesevorgang für den betroffenen Descriptor im nächsten Durchlauf einfach
#   wiederholt.
#
# Änderungen ggü. 1.4.10:
# - JSON::MaybeXS entfernt: Mojo::JSON für Lesen/API-Inhalte, JSON::PP (Perl-Core)
#   nur für die lesbare kanonische Ausgabe von configs.json.
# - Try::Tiny entfernt; Fehlerbehandlung verwendet ausschließlich Perl-Core eval.
# - Eigener Tokenvergleich entfernt; Mojo::Util::secure_compare wird verwendet.
# - Numerische Dateimodi, signalbeendete Kommandos, Status-Gesamttimeout und
#   Lockdatei-Öffnung wurden zusätzlich korrigiert/gehärtet.
# - REST-Endpunkte, Konfigurationsformat, Backup/Restore, postmap, Reload/Status
#   und die bewusst gewählte No-Auto-Rollback-Policy bleiben unverändert.
#
# Änderungen ggü. 1.4.9:
# - Dateilog wird pro Logeintrag mit O_APPEND|O_CREAT geöffnet und wieder geschlossen.
#   Wird die Logdatei während des Betriebs gelöscht oder rotiert, wird sie beim
#   nächsten Logeintrag automatisch neu erstellt bzw. der neue Pfad verwendet.
# - Dateilogzeilen werden vor dem Schreiben explizit genau einmal als UTF-8 kodiert.
# - Symlinks werden beim Öffnen mit O_NOFOLLOW (falls verfügbar) abgelehnt.
# - Der globale __DIE__-Handler ist nur während der Startphase aktiv; nach dem
#   erfolgreichen Logger-Wechsel gilt wieder Perls Standardverhalten. Fehler in
#   Mojolicious-Request-Handlern beenden damit nicht versehentlich den Daemon.
# - DELETE /instances/:inst/globs/:map und der globale backupDir-Fallback bleiben
#   wie in 1.4.9 konsistent validiert.
#
# Security-/Robustheits-Hardening gegenüber 1.3.3:
# - Voll rückwärtskompatibel zu bestehender global.json/configs.json (keine Pflichtänderung)
# - Bekanntes Legacy-Template 'postmap -c lmdb:{path}' wird nur zur Laufzeit korrigiert
# - Konfigurationsvalidierung beim Start mit klaren Warnungen statt unnötigen Pflichtfeldern
# - Nur registrierte Maps sind les-/schreib-/restorebar; main.cf/master.cf und DB-Artefakte gesperrt
# - Strikte Backup-Fehlerbehandlung und atomarer Restore; Fehlerbehandlung wieder ohne automatischen Rollback
# - Befehls-Timeouts, Status-Retry und begrenzte Command-Ausgabe
# - Konstante Token-Prüfung, CORS-Allowlist und sicherer HTTP-Guard
# - UTF-8 JSON-Verarbeitung korrigiert; Config-Schreibzugriffe serialisiert
# - Symlink-Schutz und konsequente Prüfung von chmod/chown
#
# Änderungen ggü. 1.4.3:
# - Log::Log4perl vollständig entfernt; Logging erfolgt nativ über Mojo::Log.
# - Startup- und Hauptlog verwenden dasselbe UTF-8-Format.
# - Mojolicious-interne Meldungen werden in das konfigurierte Hauptlog geschrieben.
# - Optional: log_level und fileMode_log in global.json; Defaults info und 0660.
# - Keine Änderungen an REST-Endpunkten, Maps, postmap, Reload, Restore oder PID-Verhalten.
#
# Änderungen ggü. 1.3.2:
# - Per-Map flock: Instanz in Lock-Pfad einbezogen (Bugfix: $inst an with_map_lock übergeben)
# - Lock-Timeout jetzt hochauflösend (Time::HiRes::time), Poll-Intervall bleibt 50ms
# - Aufräumen: Fcntl-Import konsolidiert
#
# Änderungen ggü. 1.3.1:
# - No-FS-delete Policy: delmap deregistriert NUR configs.json und liefert Hinweise
#
# Änderungen ggü. 1.3.0:
# - API_TOKEN Pflicht: Start bricht ab, wenn weder ENV(API_TOKEN) noch global.json(api_token) gesetzt
# - Backup-Rotation nach mtime statt Stringsortierung (stabil bei untypischen Dateinamen)
# - atomic_write_umask robuster: mehr Versuche, sauberes Logging, Fallback auf File::Temp falls O_EXCL scheitert
# - Konsistentes Logging über Mojolicious/Mojo::Log statt zusätzlicher Log4perl-Abhängigkeit
# - Statuserkennung erweitert (/(?:is\s+running|^active|^running)/)
# - Löschen aus globs nur bei EXAKTEM Key-Match (Patterns bleiben unangetastet)
# - Kleines Cleanup: chmod/chown nur, wenn Parameter wirklich gesetzt (kein sprintf auf undef)
# - Optional: require_https (global.json) erzwingt HTTPS-Start
#
# Kurzbeschreibung:
# - Liest/schreibt Postfix-Map-Dateien (UTF-8) atomar
# - Timestamp-Backups mit Rotation (mtime-basiert)
# - postmap nur für lmdb; regexp/pcre ohne Build-Schritt
# - Optionaler Reload/Status via systemd oder postmulti (pro Instanz konfigurierbar)
# - ACL (CIDR) + X-API-Token; Owner/Mode aus global.json (fileMode_*)
# - Umask-only für config/tmp/log (chmod über umask/UMask)
# - **WICHTIG: Diese API löscht KEINE Dateien auf dem Postfix-Dateisystem.**
#   `delmap` deregistriert ausschliesslich in configs.json und liefert Hinweise,
#   was manuell in main.cf/master.cf zu bereinigen und ggf. zu löschen ist.

use strict;
use warnings;
use utf8;

# Die Standard-Handles bleiben binär. Journalmeldungen werden ASCII-sicher
# formatiert; Dateilogzeilen werden im eigenen Writer explizit als UTF-8 kodiert.
binmode STDOUT, ':raw';
binmode STDERR, ':raw';

use Mojolicious::Lite;
use File::Basename qw(basename dirname);
use POSIX qw(strftime WNOHANG);
use FindBin qw($Bin);
use Mojo::Log;
use File::Temp qw(tempfile);
use File::Path qw(make_path);
use File::Spec;
use Encode qw(decode encode FB_CROAK);
use Net::CIDR;
use Mojo::Util qw(url_escape secure_compare);
use Mojo::JSON qw(from_json true false);
use JSON::PP ();
use Fcntl qw(:mode O_RDONLY O_CREAT O_EXCL O_WRONLY O_RDWR O_APPEND :flock);
use Errno qw(EEXIST ENOENT EINTR);
use Time::HiRes qw(time sleep);
use IPC::Open3 qw(open3);
use IO::Select;
use Symbol qw(gensym);


use constant LOCK_TIMEOUT_S       => 3.0;
use constant COMMAND_TIMEOUT_S    => 30;
use constant STATUS_TIMEOUT_S     => 5.0;
use constant STATUS_POLL_S        => 0.25;
use constant MAX_COMMAND_OUTPUT_B => 1_048_576;

our $VERSION = '1.4.16-hardened-compatible';
# Umask bewusst restriktiv: Group-RW, Other none
umask 0007;

# Der Startlogger schreibt ausschließlich nach STDERR/journald. Erst nach dem
# erfolgreichen Lesen und Validieren der gesamten Konfiguration wird auf den
# in global.json angegebenen Dateilogpfad umgeschaltet.
my $logger;
my $journal_logger;
my $in_die_handler = 0;
my $startup_die_handler_active = 1;
my $runtime_log_error_guard = 0;
my $o_nofollow = eval { Fcntl::O_NOFOLLOW() } || 0;

sub _as_text {
  my ($value) = @_;
  return '' unless defined $value;
  return $value if utf8::is_utf8($value);

  # Externe Kommandos liefern Bytes. Gültiges UTF-8 wird dekodiert; nur bei
  # wirklich ungültigen Bytefolgen erfolgt ein verlustfreier Latin-1-Fallback.
  my $copy = "$value";
  my $decoded = eval { decode('UTF-8', $copy, FB_CROAK) };
  return $decoded if defined $decoded;
  return decode('ISO-8859-1', "$value");
}

sub _single_line {
  my ($msg) = @_;
  $msg = _as_text($msg);
  $msg =~ s/[\r\n]+/ | /g;
  $msg =~ s/^\s+|\s+$//g;
  return $msg;
}

sub _mojo_log_format {
  my ($time, $level, @lines) = @_;
  my $timestamp = strftime('%Y/%m/%d %H:%M:%S', localtime($time));
  my $message = _single_line(join(' ', map { _as_text($_) } @lines));
  return sprintf("%s %s %s\n", $timestamp, uc($level // 'INFO'), $message);
}

sub _journal_ascii {
  my ($msg) = @_;
  $msg = _as_text($msg);
  $msg =~ s/Ä/Ae/g;
  $msg =~ s/Ö/Oe/g;
  $msg =~ s/Ü/Ue/g;
  $msg =~ s/ä/ae/g;
  $msg =~ s/ö/oe/g;
  $msg =~ s/ü/ue/g;
  $msg =~ s/ß/ss/g;
  $msg =~ s/é/e/g;
  $msg =~ s/è/e/g;
  $msg =~ s/à/a/g;
  $msg =~ s/[^\x09\x20-\x7e]/?/g;
  return $msg;
}

sub _mojo_journal_format {
  my ($time, $level, @lines) = @_;
  my $timestamp = strftime('%Y/%m/%d %H:%M:%S', localtime($time));
  my $message = _single_line(join(' ', map { _as_text($_) } @lines));
  $message = _journal_ascii($message);
  return sprintf("%s %s %s\n", $timestamp, uc($level // 'INFO'), $message);
}

sub _normalized_log_level {
  my ($level) = @_;
  $level = lc($level // 'info');
  return $level =~ /\A(?:trace|debug|info|warn|error|fatal)\z/ ? $level : 'info';
}

sub _new_stderr_logger {
  my ($level) = @_;
  my $log = Mojo::Log->new(
    handle => \*STDERR,
    level  => _normalized_log_level($level),
    color  => 0,
    short  => 0,
  );
  $log->format(\&_mojo_journal_format);
  return $log;
}

sub _validate_log_path {
  my ($path) = @_;
  die "global.json: logfile fehlt"
    unless defined($path) && length($path);
  die "global.json: ungültiger logfile-Pfad"
    if $path =~ /[\x00\r\n]/ || !File::Spec->file_name_is_absolute($path);
  return 1;
}

sub _ensure_log_directory {
  my ($path) = @_;
  my $dir = dirname($path);
  make_path($dir) unless -d $dir;
  die "Kann Log-Verzeichnis $dir nicht anlegen" unless -d $dir;
  return $dir;
}

sub _open_log_append {
  my ($path, $mode, $user, $group) = @_;
  my $flags = O_WRONLY | O_APPEND | $o_nofollow;

  for (1 .. 4) {
    die "Logdatei ist ein Symlink und wird abgelehnt: $path"
      if !$o_nofollow && -l $path;

    my ($fh, $created) = (undef, 0);
    if (sysopen($fh, $path, $flags | O_CREAT | O_EXCL, $mode)) {
      $created = 1;
    } elsif ($! == EEXIST) {
      if (!sysopen($fh, $path, $flags, $mode)) {
        next if $! == ENOENT;
        die "Kann Logdatei $path nicht öffnen: $!";
      }
    } else {
      die "Kann Logdatei $path nicht öffnen: $!";
    }

    binmode($fh, ':raw') or do {
      my $err = $!;
      close $fh;
      die "binmode($path) fehlgeschlagen: $err";
    };

    if ($created) {
      my $perm_err = set_file_ownership_and_mode(
        $path, $user, $group, sprintf('%04o', $mode)
      );
      if ($perm_err) {
        close $fh;
        die "Logfile-Rechte konnten nicht gesetzt werden: $perm_err";
      }
    }

    return ($fh, $created);
  }

  die "Kann Logdatei $path wegen gleichzeitiger Rotation/Löschung nicht stabil öffnen";
}

sub _write_utf8_log_line {
  my ($path, $mode, $user, $group, $line) = @_;
  my $bytes = encode('UTF-8', _as_text($line), FB_CROAK);

  for (1 .. 4) {
    my ($fh) = _open_log_append($path, $mode, $user, $group);
    flock($fh, LOCK_EX) or do {
      my $err = $!;
      close $fh;
      die "Kann Logdatei $path nicht sperren: $err";
    };

    my @fh_stat   = stat($fh);
    my @path_stat = stat($path);
    if (!@path_stat || !@fh_stat
        || $fh_stat[0] != $path_stat[0]
        || $fh_stat[1] != $path_stat[1]) {
      flock($fh, LOCK_UN);
      close $fh;
      next;
    }

    my $offset = 0;
    my $length = length($bytes);
    while ($offset < $length) {
      my $written = syswrite($fh, $bytes, $length - $offset, $offset);
      if (!defined $written) {
        next if $!{EINTR};
        my $err = $!;
        flock($fh, LOCK_UN);
        close $fh;
        die "Kann Logdatei $path nicht schreiben: $err";
      }
      if ($written == 0) {
        flock($fh, LOCK_UN);
        close $fh;
        die "Kann Logdatei $path nicht schreiben: syswrite lieferte 0 Bytes";
      }
      $offset += $written;
    }

    flock($fh, LOCK_UN);
    close $fh or die "Kann Logdatei $path nicht schließen: $!";
    return 1;
  }

  die "Kann Logdatei $path nach Rotation/Löschung nicht schreiben";
}

sub _direct_journal_error {
  my ($message) = @_;
  return if $runtime_log_error_guard;
  $runtime_log_error_guard = 1;
  my $line = _mojo_journal_format(time, 'error', $message);
  syswrite(STDERR, $line);
  $runtime_log_error_guard = 0;
}

sub _prepare_configured_log {
  my ($path, $mode, $user, $group) = @_;
  _validate_log_path($path);
  _ensure_log_directory($path);

  my ($fh) = _open_log_append($path, $mode, $user, $group);
  my $perm_err = set_file_ownership_and_mode(
    $path, $user, $group, sprintf('%04o', $mode)
  );
  close $fh;
  die "Logfile-Rechte konnten nicht gesetzt werden: $perm_err" if $perm_err;
  return 1;
}

sub _new_file_logger {
  my ($path, $mode, $user, $group, $level) = @_;
  my $log = Mojo::Log->new(
    level => _normalized_log_level($level),
    color => 0,
    short => 0,
  );

  $log->unsubscribe('message');
  $log->on(message => sub {
    my ($log_obj, $msg_level, @lines) = @_;
    my $line = _mojo_log_format(time, $msg_level, @lines);
    my $ok = eval {
      _write_utf8_log_line($path, $mode, $user, $group, $line);
      1;
    };
    unless ($ok) {
      my $error = _single_line($@ || 'unbekannter Dateilog-Fehler');
      _direct_journal_error("MAIN LOG WRITE FAILED: path=$path error=$error");
    }
  });

  return $log;
}

$journal_logger = _new_stderr_logger('info');
$logger = $journal_logger;
app->log($logger);
$logger->info("STARTUP BEGIN: version=$VERSION");

sub _log_fatal {
  my ($msg) = @_;
  $msg = _single_line($msg);
  eval { $logger->fatal($msg) } if $logger;
}

$SIG{__DIE__} = sub {
  my ($msg) = @_;
  return if !$startup_die_handler_active;
  return if $^S;
  return if $in_die_handler;
  $in_die_handler = 1;
  _log_fatal($msg);
  $in_die_handler = 0;
  exit 255;
};

# -------------------- I/O Basis-Helfer --------------------

sub read_raw {
  my ($file) = @_;
  open my $fh, '<:raw', $file or die "Kann $file nicht lesen: $!";
  local $/; my $data = <$fh>;
  close $fh;
  return $data;
}

sub read_text {
  my ($file) = @_;
  open my $fh, '<:encoding(UTF-8)', $file or die "Kann $file nicht lesen: $!";
  local $/; my $data = <$fh>;
  close $fh;
  return $data;
}

# Für durch die API adressierbare Map-/Backup-Dateien reicht eine vorgelagerte
# -l-Prüfung nicht: Der Pfad könnte zwischen Prüfung und open() ausgetauscht
# werden. Deshalb wird der Pfad mit O_NOFOLLOW geöffnet und anschließend der
# bereits geöffnete Deskriptor als reguläre Datei verifiziert. Auf Plattformen
# ohne O_NOFOLLOW verhindert der Vergleich mit lstat/stat das Folgen eines
# Symlinks beziehungsweise einen Pfadaustausch vor der Verifikation.
sub _open_regular_read {
  my ($file, $label) = @_;
  $label //= 'Datei';

  my $flags = O_RDONLY | $o_nofollow;
  sysopen(my $fh, $file, $flags)
    or die "$label kann nicht sicher geöffnet werden: $file: $!";
  binmode($fh, ':raw') or do {
    my $err = $!;
    close $fh;
    die "binmode($file) fehlgeschlagen: $err";
  };

  my @fh_stat = stat($fh);
  unless (@fh_stat && S_ISREG($fh_stat[2])) {
    close $fh;
    die "$label ist keine reguläre Datei: $file";
  }

  unless ($o_nofollow) {
    my @link_stat = lstat($file);
    my @path_stat = stat($file);
    unless (@link_stat && @path_stat
        && !S_ISLNK($link_stat[2])
        && $fh_stat[0] == $path_stat[0]
        && $fh_stat[1] == $path_stat[1]) {
      close $fh;
      die "$label wurde während des Öffnens ausgetauscht oder ist ein Symlink: $file";
    }
  }

  return $fh;
}

sub read_raw_regular {
  my ($file, $label) = @_;
  my $fh = _open_regular_read($file, $label);
  my $data = '';

  while (1) {
    my $chunk = '';
    my $n = sysread($fh, $chunk, 64 * 1024);
    if (!defined $n) {
      next if $!{EINTR};
      my $err = $!;
      close $fh;
      die "Kann $file nicht lesen: $err";
    }
    last if $n == 0;
    $data .= $chunk;
  }

  close $fh or die "Kann $file nicht schließen: $!";
  return $data;
}

sub read_text_regular {
  my ($file, $label) = @_;
  my $bytes = read_raw_regular($file, $label);
  my $text = eval { decode('UTF-8', $bytes, FB_CROAK) };
  die (($label // 'Datei') . " enthält kein gültiges UTF-8: $file: " . _single_line($@))
    if $@;
  return $text;
}

sub read_regular_prefix {
  my ($file, $limit, $label) = @_;
  $limit = 8192 unless defined($limit) && $limit > 0;
  my $fh = _open_regular_read($file, $label);
  my $data = '';

  while (length($data) < $limit) {
    my $chunk = '';
    my $want = $limit - length($data);
    my $n = sysread($fh, $chunk, $want);
    if (!defined $n) {
      next if $!{EINTR};
      my $err = $!;
      close $fh;
      die "Kann $file nicht lesen: $err";
    }
    last if $n == 0;
    $data .= $chunk;
  }

  close $fh or die "Kann $file nicht schließen: $!";
  return $data;
}

sub _random_secret {
  my $bytes = '';
  if (open my $fh, '<:raw', '/dev/urandom') {
    my $read = read($fh, $bytes, 48);
    close $fh;
    return unpack('H*', $bytes) if defined $read && $read == 48;
  }
  die "Sicherer Zufallsgenerator /dev/urandom ist nicht verfügbar";
}

sub _shell_quote {
  my ($value) = @_;
  $value //= '';
  $value =~ s/'/'"'"'/g;
  return "'$value'";
}

sub _is_loopback_listen {
  my ($listen) = @_;
  return 1 if !defined($listen) || $listen =~ /\A(?:127\.0\.0\.1|localhost|\[::1\]|::1):/i;
  return 0;
}

sub _normalize_mode {
  my ($m) = @_;
  return unless defined $m;

  my $text = "$m";

  # Konfigurationsstrings wie "0644"/"0660" sind oktal.
  return oct($text) if $text =~ /\A0[0-7]{3}\z/;

  # Numerische JSON-Werte sind bereits dezimal (z. B. 420 == 0644).
  return 0 + $text if $text =~ /\A\d+\z/ && $text >= 0 && $text <= 4095;

  return;
}

sub read_json_config {
  my ($file) = @_;

  my $text;
  eval { $text = read_text($file); 1 }
    or die "CONFIG READ FAILED: file=$file error=" . _single_line($@);

  my $data;
  eval { $data = from_json($text); 1 }
    or die "CONFIG JSON INVALID: file=$file error=" . _single_line($@);

  return $data;
}

# -------------------- Config laden --------------------

my $global_cfg_file    = "$Bin/global.json";
my $instances_cfg_file = "$Bin/configs.json";
die "Missing config $global_cfg_file\n"    unless -f $global_cfg_file;
die "Missing config $instances_cfg_file\n" unless -f $instances_cfg_file;

$logger->info("CONFIG READ START: global=$global_cfg_file instances=$instances_cfg_file");
my $global         = read_json_config($global_cfg_file);
$logger->info("CONFIG READ OK: file=$global_cfg_file");
my $instances_raw  = read_json_config($instances_cfg_file);
$logger->info("CONFIG READ OK: file=$instances_cfg_file");
my $instances      = (ref($instances_raw->{instances}) eq 'HASH')
                     ? $instances_raw->{instances}
                     : $instances_raw;

# Harte Defaults für globale Berechtigungen (nur falls nicht gesetzt)
$global->{serviceUser}      //= 'root';
$global->{serviceGroup}     //= 'root';
$global->{fileMode_service} //= '0644';  # Maps
$global->{fileMode_backup}  //= '0660';  # Backups

# Secret für Mojo (Session/Signer)
my $mojo_secret = $global->{secret};
if (!defined($mojo_secret) || length($mojo_secret) < 32) {
  $mojo_secret = _random_secret();
}
app->secrets([$mojo_secret]);
app->max_request_size(2 * 1024 * 1024);

# -------------------- Logging-Konfiguration vorbereiten --------------------

# Kein hart codierter Hauptlogpfad: logfile muss aus global.json kommen.
my $logfile = $global->{logfile};
my $log_mode = _normalize_mode($global->{fileMode_log} // '0660');
$log_mode = 0660 unless defined $log_mode;

my $requested_log_level = lc($global->{log_level} // 'info');
my $effective_log_level = _normalized_log_level($requested_log_level);

# Bis zum erfolgreichen Abschluss der Startprüfung bleibt $logger auf journald.

# -------------------- FS-Rechte & Ownership --------------------

sub _resolve_owner_group {
  my ($user, $group) = @_;
  my ($uid, $gid);
  if (defined $user && $user ne '') {
    $uid = getpwnam($user);
    return (undef, undef, "unbekannter user '$user'") unless defined $uid;
  }
  if (defined $group && $group ne '') {
    $gid = getgrnam($group);
    return (undef, undef, "unbekannte group '$group'") unless defined $gid;
  }
  return ($uid, $gid, '');
}

sub set_file_ownership_and_mode {
  my ($path, $user, $group, $mode) = @_;
  my $err = '';
  my ($uid, $gid, $resolve_err) = _resolve_owner_group($user, $group);
  return "$resolve_err; " if $resolve_err;

  if (defined($uid) || defined($gid)) {
    chown(defined $uid ? $uid : -1, defined $gid ? $gid : -1, $path)
      or $err .= "chown $user:$group fehlgeschlagen: $!; ";
  }
  if (defined(my $oct_mode = _normalize_mode($mode))) {
    chmod $oct_mode, $path
      or $err .= "chmod " . sprintf('%04o',$oct_mode) . " fehlgeschlagen: $!; ";
  }
  return $err;
}

sub set_dir_ownership_and_mode {
  my ($dir, $user, $group, $mode) = @_;
  my $err = '';
  my ($uid, $gid, $resolve_err) = _resolve_owner_group($user, $group);
  return "$resolve_err; " if $resolve_err;

  if (defined($uid) || defined($gid)) {
    chown(defined $uid ? $uid : -1, defined $gid ? $gid : -1, $dir)
      or $err .= "chown $user:$group auf $dir fehlgeschlagen: $!; ";
  }
  if (defined(my $oct_mode = _normalize_mode($mode))) {
    my $cur = (stat($dir))[2] & 07777;
    unless ($cur == $oct_mode) {
      chmod($oct_mode, $dir)
        or $err .= "chmod " . sprintf('%04o',$oct_mode) . " auf $dir fehlgeschlagen: $!; ";
    }
  }
  return $err;
}

# Nur globale Berechtigungen verwenden
sub effective_service_user   { return $global->{serviceUser}; }
sub effective_service_group  { return $global->{serviceGroup}; }
sub effective_file_mode      { return $global->{fileMode_service}; }
sub effective_backup_mode    { return $global->{fileMode_backup} // $global->{fileMode_service}; }
sub effective_service_dir_mode {
  return (ref($global->{dirs}) eq 'HASH' && defined $global->{dirs}{service_mode})
    ? $global->{dirs}{service_mode}
    : '0770';
}

# Backup-Fallback: backupDir/<inst>. Für Validierungs- und Reload-Pfade kann
# ausdrücklich das zu prüfende Global-Objekt übergeben werden.
sub effective_backup_dir {
  my ($ci, $inst, $g) = @_;
  $g //= $global;

  return $ci->{backup_dir}
    if $ci && defined($ci->{backup_dir}) && length($ci->{backup_dir});
  return File::Spec->catdir($g->{backupDir}, $inst)
    if $g && defined($g->{backupDir}) && length($g->{backupDir});
  return; # kein Fallback
}

# Der Wert wird bereits benötigt, bevor die Verzeichnisse nach erfolgreicher
# Konfigurationsvalidierung tatsächlich vorbereitet werden.
my $tmp_dir = $global->{tmpDir} // '/tmp';

sub _prepare_runtime_directories {
  # Globale Dienstverzeichnisse anlegen/absichern
  if (my $dconf = $global->{dirs}) {
    my $folders = $dconf->{service_folder};
    $folders = [] unless defined $folders;
    $folders = [$folders] unless ref $folders eq 'ARRAY';
    my $owner = $global->{serviceUser};
    my $group = $global->{serviceGroup};
    my $mode  = effective_service_dir_mode();

    foreach my $fldkey (@$folders) {
      my $dir = $global->{$fldkey} // next;
      unless (-d $dir) {
        eval { make_path($dir) };
        die "Kann Verzeichnis $dir nicht anlegen: $@" if $@;
      }
      my $err = set_dir_ownership_and_mode($dir, $owner, $group, $mode);
      $logger->warn($err) if $err;
    }
  }

  # Instanz-Backupverzeichnisse sicherstellen
  {
    my $owner = $global->{serviceUser};
    my $group = $global->{serviceGroup};
    my $mode  = effective_service_dir_mode();
    for my $name (keys %$instances) {
      my $dir = effective_backup_dir($instances->{$name}, $name, $global) // next;
      unless (-d $dir) {
        eval { make_path($dir) };
        if ($@) {
          $logger->error("Backup-Verzeichnis $dir konnte nicht erstellt werden: $@");
          next;
        }
      }
      my $err = set_dir_ownership_and_mode($dir, $owner, $group, $mode);
      $logger->warn($err) if $err;
    }
  }

  # tmp-dir
  unless (-d $tmp_dir) {
    eval { make_path($tmp_dir) };
    die "Konnte tmp_dir $tmp_dir nicht anlegen: $@" if $@;
  }

  return 1;
}

# Zusammengeführte Config (mutable via reload_config / _rebuild_cfgmap_from)
my $config = { global => $global, instances => $instances };

# -------------------- Atomare Writes --------------------

sub _assert_not_symlink {
  my ($path, $label) = @_;
  return unless -e $path || -l $path;
  die (($label // 'Pfad') . " ist ein Symlink und wird aus Sicherheitsgründen abgelehnt: $path") if -l $path;
}

sub atomic_write {
  my ($path, $content, $user, $group, $mode) = @_;
  my $dir = dirname($path);
  die "Verzeichnis nicht beschreibbar: $dir" unless -d $dir && -w $dir;
  _assert_not_symlink($path, 'Zieldatei');

  my ($fh, $tmpfile) = tempfile('.tmp_XXXXXXXX', DIR => $dir, UNLINK => 0);
  my $ok = eval {
    binmode($fh, ':encoding(UTF-8)') or die "binmode($tmpfile) failed: $!";
    print {$fh} (defined($content) ? $content : '') or die "write($tmpfile) failed: $!";
    close $fh or die "close($tmpfile) failed: $!";

    my $perm_err = set_file_ownership_and_mode($tmpfile, $user, $group, $mode);
    die "Berechtigungen für $tmpfile fehlgeschlagen: $perm_err" if $perm_err;

    rename $tmpfile, $path or die "rename($tmpfile -> $path) failed: $!";
    $tmpfile = undef;
    1;
  };
  my $err = $@;
  close $fh if defined(fileno($fh));
  unlink $tmpfile if defined($tmpfile) && -e $tmpfile;
  die $err unless $ok;
  return 1;
}

sub atomic_write_raw {
  my ($path, $bytes, $user, $group, $mode) = @_;
  my $dir = dirname($path);
  die "Verzeichnis nicht beschreibbar: $dir" unless -d $dir && -w $dir;
  _assert_not_symlink($path, 'Zieldatei');

  my ($fh, $tmpfile) = tempfile('.tmp_XXXXXXXX', DIR => $dir, UNLINK => 0);
  my $ok = eval {
    binmode($fh, ':raw') or die "binmode($tmpfile) failed: $!";
    my $offset = 0;
    my $length = length($bytes // '');
    while ($offset < $length) {
      my $written = syswrite($fh, $bytes, $length - $offset, $offset);
      if (!defined $written) {
        next if $!{EINTR};
        die "write($tmpfile) failed: $!";
      }
      die "write($tmpfile) lieferte 0 Bytes" if $written == 0;
      $offset += $written;
    }
    close $fh or die "close($tmpfile) failed: $!";

    my $perm_err = set_file_ownership_and_mode($tmpfile, $user, $group, $mode);
    die "Berechtigungen für $tmpfile fehlgeschlagen: $perm_err" if $perm_err;

    rename $tmpfile, $path or die "rename($tmpfile -> $path) failed: $!";
    $tmpfile = undef;
    1;
  };
  my $err = $@;
  close $fh if defined(fileno($fh));
  unlink $tmpfile if defined($tmpfile) && -e $tmpfile;
  die $err unless $ok;
  return 1;
}

sub atomic_write_umask {
  my ($path, $content, $user, $group) = @_;
  my $dir = dirname($path);
  die "Verzeichnis nicht beschreibbar: $dir" unless -d $dir && -w $dir;
  _assert_not_symlink($path, 'Zieldatei');

  my $tmpfile;
  my $max_tries = 32;
  for (1..$max_tries) {
    my $rand = int(rand(1_000_000_000));
    my $candidate = File::Spec->catfile($dir, ".tmp_${$}_$rand");
    if (sysopen(my $fh, $candidate, O_CREAT|O_EXCL|O_WRONLY, 0666)) {
      binmode($fh, ':encoding(UTF-8)') or die "binmode($candidate) failed: $!";
      print {$fh} (defined($content) ? $content : '') or die "write($candidate) failed: $!";
      close $fh or die "close($candidate) failed: $!";
      $tmpfile = $candidate;
      last;
    }
  }
  unless ($tmpfile) {
    $logger->warn("atomic_write_umask: O_EXCL ausgeschöpft, Fallback auf File::Temp");
    my ($fh, $cand) = tempfile('.tmp_XXXXXXXX', DIR => $dir, UNLINK => 0);
    binmode($fh, ':encoding(UTF-8)') or die "binmode($cand) failed: $!";
    print {$fh} (defined($content) ? $content : '') or die "write($cand) failed: $!";
    close $fh or die "close($cand) failed: $!";
    $tmpfile = $cand;
  }

  my $ok = eval {
    my $perm_err = set_file_ownership_and_mode($tmpfile, $user, $group);
    die "Berechtigungen für $tmpfile fehlgeschlagen: $perm_err" if $perm_err;
    rename $tmpfile, $path or die "rename($tmpfile -> $path) failed: $!";
    $tmpfile = undef;
    1;
  };
  my $err = $@;
  unlink $tmpfile if defined($tmpfile) && -e $tmpfile;
  die $err unless $ok;
  return 1;
}

# -------------------- Netz & Auth --------------------

my $listen_addr   = $config->{global}{listen}        // '0.0.0.0:5000';
my $ssl_enable    = $config->{global}{ssl_enable}    // 0;
my $ssl_cert      = $config->{global}{ssl_cert_file} // '';
my $ssl_key       = $config->{global}{ssl_key_file}  // '';
my $require_https = $config->{global}{require_https} // 0;
my $allow_insecure_http = $config->{global}{allow_insecure_http} // 0;

if ($ssl_enable) {
  die "FATAL: ssl_enable=true, aber ssl_cert_file fehlt oder ist nicht lesbar
"
    unless defined($ssl_cert) && length($ssl_cert) && -r $ssl_cert;
  die "FATAL: ssl_enable=true, aber ssl_key_file fehlt oder ist nicht lesbar
"
    unless defined($ssl_key) && length($ssl_key) && -r $ssl_key;
}

if (!$ssl_enable && !$require_https && !_is_loopback_listen($listen_addr) && !$allow_insecure_http) {
  $logger->warn(
    "KOMPATIBILITÄTSMODUS: Unverschlüsseltes HTTP auf Nicht-Loopback ($listen_addr). "
    . "Die bestehende global.json bleibt gültig. Für zusätzliche Härtung später TLS aktivieren."
  );
}

# API-Token bleibt wie in 1.3.3 zwingend. Eine Mindestlänge wird nur erzwungen,
# wenn min_api_token_length bereits ausdrücklich in global.json gesetzt ist.
my $api_token = $ENV{API_TOKEN} // ($global->{api_token} // '');
my $min_token_length = $global->{min_api_token_length};
die "FATAL: API_TOKEN nicht gesetzt (ENV API_TOKEN oder global.json api_token)\n"
  unless defined $api_token && length $api_token;
if (defined($min_token_length) && $min_token_length =~ /\A\d+\z/ && $min_token_length > 0) {
  die "FATAL: API_TOKEN ist zu kurz; mindestens $min_token_length Zeichen erforderlich\n"
    if length($api_token) < $min_token_length;
} elsif (length($api_token) < 24) {
  $logger->warn("API_TOKEN ist kürzer als 24 Zeichen; aus Kompatibilitätsgründen wird der Start nicht blockiert.");
}

sub _normalize_allowed_ips {
  my ($entries) = @_;
  $entries = ['127.0.0.1/32'] unless defined $entries;

  die "allowed_ips muss ein nicht-leeres Array sein"
    unless ref($entries) eq 'ARRAY' && @$entries;

  my @normalized;
  for my $raw (@$entries) {
    die "allowed_ips enthält keinen gültigen String"
      if !defined($raw) || ref($raw);

    my $entry = "$raw";
    $entry =~ s/^\s+|\s+$//g;
    die "allowed_ips enthält einen leeren Eintrag" unless length($entry);
    die "allowed_ips enthält Steuerzeichen" if $entry =~ /[\x00\r\n]/;

    $entry .= ($entry =~ /:/ ? '/128' : '/32') unless $entry =~ m{/};

    my $validated = eval { Net::CIDR::cidrvalidate($entry) };
    my $validation_error = $@;
    die "Ungültiger allowed_ips-Eintrag '$raw': " . _single_line($validation_error)
      if $validation_error;
    die "Ungültiger allowed_ips-Eintrag '$raw'" unless defined($validated);

    push @normalized, $validated;
  }

  return \@normalized;
}

sub _cors_origin_allowed {
  my ($origin) = @_;
  return 0 unless defined $origin && length $origin;
  return 1 if $config->{global}{cors_allow_any_origin};
  my $allowed = $config->{global}{allowed_origins};

  # Rückwärtskompatibilität: Fehlt allowed_origins vollständig, gilt das bisherige
  # Verhalten (Origin spiegeln). Sobald allowed_origins gesetzt ist, wird strikt geprüft.
  return 1 unless exists $config->{global}{allowed_origins};
  return 0 unless ref($allowed) eq 'ARRAY';
  return scalar grep { defined($_) && $_ eq $origin } @$allowed;
}

if (!exists $config->{global}{allowed_origins}) {
  $logger->warn(
    "CORS COMPATIBILITY MODE: allowed_origins fehlt; jede Origin wird gespiegelt. "
    . "Produktiv allowed_origins explizit setzen."
  );
}

hook before_dispatch => sub {
  my $c = shift;

  # validate_config normalisiert und validiert allowed_ips bereits beim Start
  # bzw. vor einem Config-Reload. Der Request-Pfad arbeitet nur noch mit der
  # akzeptierten CIDR-Liste.
  my @acl_rt = @{ $config->{global}{allowed_ips} };

  my $origin = $c->req->headers->origin // '';
  if ($origin) {
    unless (_cors_origin_allowed($origin)) {
      return $c->render(status => 403, json => { ok => 0, error => 'CORS origin forbidden' });
    }
    $c->res->headers->header('Access-Control-Allow-Origin'  => $origin);
    $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS');
    $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, X-API-Token, Authorization');
    $c->res->headers->header('Access-Control-Max-Age'       => '86400');
    $c->res->headers->header('Vary'                         => 'Origin');
  }

  if ($require_https) {
    my $is_https = ($c->req->url->to_abs->scheme // '') eq 'https' || ($c->req->is_secure // 0);
    unless ($is_https) {
      return $c->render(status => 403, json => { ok => 0, error => 'HTTPS required' });
    }
  }

  my $remote = $c->tx->remote_address // '';
  my $acl_ok = eval { Net::CIDR::cidrlookup($remote, @acl_rt) } ? 1 : 0;
  if (!$acl_ok && $@) {
    $logger->error("IP-ACL-Pruefung fehlgeschlagen (allowed_ips ungueltig?): $@");
  }
  unless ($acl_ok) {
    return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
  }

  if ($c->req->method eq 'OPTIONS') {
    return $c->render(text => '', status => 204);
  }

  my $hdr_token = $c->req->headers->header('X-API-Token') // '';
  my $bearer    = ($c->req->headers->authorization // '') =~ /^Bearer\s+(.+)/i ? $1 : '';
  my $token     = $hdr_token || $bearer;
  unless (secure_compare($token, $api_token)) {
    return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' });
  }
};

# -------------------- Config-Helfer (reload & raw read/write) ----------------

sub reload_config {
  $logger->info("CONFIG RELOAD START: global=$global_cfg_file instances=$instances_cfg_file");

  my $ok = eval {
    my $raw_global    = read_json_config($global_cfg_file);
    my $raw_instances = read_json_config($instances_cfg_file);

    $raw_global->{serviceUser}      //= 'root';
    $raw_global->{serviceGroup}     //= 'root';
    $raw_global->{fileMode_service} //= '0644';
    $raw_global->{fileMode_backup}  //= '0660';

    my $inst_hash =
      (ref($raw_instances->{instances}) eq 'HASH') ? $raw_instances->{instances}
                                                   : $raw_instances;

    validate_config($raw_global, $inst_hash);
    $global    = $raw_global;
    $instances = $inst_hash;
    $config    = { global => $global, instances => $instances };
    1;
  };

  unless ($ok) {
    my $err = _single_line($@);
    $logger->error("CONFIG RELOAD FAILED: $err");
    die "$err\n";
  }

  $logger->info("CONFIG RELOAD OK: instances=" . scalar(keys %$instances));
  return 1;
}

sub _read_cfg_hash {
  my $cfg = from_json(read_text($instances_cfg_file));
  return $cfg;
}

sub _inst_node_rw {
  my ($cfg, $inst) = @_;
  my $insts = (ref($cfg->{instances}) eq 'HASH') ? $cfg->{instances} : $cfg;
  die "Unknown instance '$inst'" unless ref($insts) eq 'HASH' && exists $insts->{$inst};
  return $insts->{$inst};
}

sub _write_cfg_hash_atomic {
  my ($cfg) = @_;

  # JSON::PP ist Perl-Core und bewahrt die bisherige lesbare, kanonische
  # configs.json-Ausgabe. Mojo::JSON bleibt für Parsing und API-Inhalte zuständig.
  my $json = JSON::PP->new
    ->canonical(1)
    ->pretty(1)
    ->allow_nonref(1)
    ->encode($cfg);

  atomic_write_umask($instances_cfg_file, $json, $global->{serviceUser}, $global->{serviceGroup});
}

sub _rebuild_cfgmap_from {
  my ($cfg) = @_;
  my $insts = (ref($cfg->{instances}) eq 'HASH') ? $cfg->{instances} : $cfg;
  $instances = $insts;
  $config->{instances} = $insts;
}

# -------------------- Map-Typen & Sanitizer --------------------

my %GLOB_TYPES = map { $_ => 1 } qw(regexp pcre cidr lmdb hash btree db);

sub sanitize_map_name {
  my ($raw) = @_;
  $raw //= '';
  return (undef, 'Empty name') unless length $raw;
  return (undef, 'Path traversal detected') if $raw =~ m{/|\\} || $raw =~ /\.\./;
  return (undef, 'Invalid characters') unless $raw =~ /\A[0-9A-Za-z._-]{1,255}\z/;
  return ($raw, undef);
}

# Verbotene Dateinamen (NICHT als Maps editier-/abrufbar)
my %FORBIDDEN = map { $_ => 1 } qw(
  main.cf master.cf
  change_main.cf change_master.cf
  chnage_master.cf
);
sub _deny_forbidden_map {
  my ($name) = @_;
  return 1 if $FORBIDDEN{ lc($name // '') };
  return 0;
}

sub _is_compiled_map_artifact {
  my ($name, $path) = @_;
  return 0 unless ($name // '') =~ /\.(?:lmdb|db|dir|pag)$/i;
  return 0 unless defined($path) && (-e $path || -l $path);
  return 1 if -l $path || !-f $path;

  my $prefix = read_regular_prefix($path, 8192, 'Map-Datei');
  return 1 if $prefix =~ /\x00/;
  return 1 if $prefix =~ /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/;

  my $copy = $prefix;
  my $utf8_ok = eval { decode('UTF-8', $copy, FB_CROAK); 1 };
  return $utf8_ok ? 0 : 1;
}

sub _deny_compiled_map_artifact {
  my ($name, $path) = @_;
  return _is_compiled_map_artifact($name, $path) ? 1 : 0;
}

sub _require_registered_map {
  my ($ci, $map) = @_;
  die "Map '$map' ist nicht in globs registriert" unless defined map_type_for_file($ci, $map);
  die "Map '$map' ist gesperrt" if _deny_forbidden_map($map);
  return 1;
}

sub parse_backup_filename {
  my ($filename) = @_;
  return unless defined $filename;
  return $1 if $filename =~ /\A([0-9A-Za-z._-]+)\.bak\.\d{8}_\d{6}(?:_\d{6})?\z/;
  return;
}

sub sanitize_glob_key {
  my ($raw) = @_;
  my $k = $raw // '';
  $k =~ s/^\s+|\s+$//g;
  return (undef, 'Empty key') unless length $k;
  return (undef, 'Invalid characters') unless $k =~ /\A[0-9A-Za-z._*\-]{1,255}\z/;
  return (undef, 'Path traversal detected') if $k =~ m{/|\\|\.\.};
  return ($k, undef);
}

sub sanitize_glob_val {
  my ($v) = @_;
  $v //= '';
  $v =~ s/^\s+|\s+$//g;
  return (undef, 'Empty value') unless length $v;
  return (undef, 'Invalid value') unless $v =~ /\A[a-z0-9_\-]{1,32}\z/i;
  return (lc($v), undef);
}

sub map_type_for_file {
  my ($ci, $file) = @_;
  my $globs = $ci->{globs} // {};
  return $globs->{$file} if exists $globs->{$file};

  my @matches;
  for my $glob (keys %$globs) {
    next if $glob eq $file;
    my $type = $globs->{$glob};
    my $re = quotemeta($glob);
    $re =~ s/\\\*/.*/g;
    next unless $file =~ /\A$re\z/;

    my $literal = $glob;
    my $stars = ($literal =~ tr/*/*/);
    $literal =~ s/\*//g;
    push @matches, {
      glob        => $glob,
      type        => $type,
      literal_len => length($literal),
      stars       => $stars,
    };
  }

  return unless @matches;
  @matches = sort {
       $b->{literal_len} <=> $a->{literal_len}
    || $a->{stars}       <=> $b->{stars}
    || $a->{glob}        cmp $b->{glob}
  } @matches;
  return $matches[0]{type};
}

# -------------------- Kommandoplätze / sichere Ausführung --------------------

sub expand_cmd {
  my ($ci, $inst, $cmd) = @_;
  return '' unless defined $cmd && length $cmd;
  my $bdir = effective_backup_dir($ci, $inst) // ($ci->{backup_dir} // '');
  my %values = (
    inst       => $inst,
    config_dir => $ci->{config_dir},
    map_dir    => $ci->{map_dir},
    backup_dir => $bdir,
  );
  $cmd =~ s/\{(inst|config_dir|map_dir|backup_dir)\}/_shell_quote($values{$1})/ge;
  return $cmd;
}

my %legacy_postmap_template_warned;

sub _runtime_postmap_template {
  my ($template, $type, $inst) = @_;
  return $template unless defined($template) && length($template);

  # Kompatibilität für die bekannte Alt-/Fehlkonfiguration:
  #   postmap -c lmdb:{path}
  # -c benötigt config_dir. Die Korrektur erfolgt ausschließlich im Arbeitsspeicher;
  # configs.json wird dadurch nicht verändert.
  my $qt = quotemeta($type // '');
  if ($template =~ /\A(\s*(?:\/[0-9A-Za-z._\/-]+\/)?postmap)\s+-c\s+($qt:\{path\})\s*\z/) {
    my $fixed = "$1 -c {config_dir} $2";
    my $warn_key = join("\x1f", ($inst // ''), ($type // ''), $template);
    unless ($legacy_postmap_template_warned{$warn_key}++) {
      $logger->warn(
        "Instanz '$inst': Legacy-postmap-Template '$template' wird zur Laufzeit als '$fixed' ausgeführt; configs.json bleibt unverändert."
      );
    }
    return $fixed;
  }

  return $template;
}

sub postmap_cmd {
  my ($ci, $file, $inst) = @_;
  my $type = map_type_for_file($ci, $file) or return;
  my $template = $ci->{postmap_by_type}{$type} or return;
  $template = _runtime_postmap_template($template, $type, $inst);
  my $path = File::Spec->catfile($ci->{map_dir}, $file);
  my %values = (
    config_dir => $ci->{config_dir},
    path       => $path,
    inst       => $inst,
  );
  my $cmd = $template;
  $cmd =~ s/\{(config_dir|path|inst)\}/_shell_quote($values{$1})/ge;
  return $cmd;
}

sub _waitpid_status {
  my ($pid, $label) = @_;
  $label //= 'command';

  while (1) {
    my $waited = waitpid($pid, 0);
    return $? if $waited == $pid;
    next if $waited == -1 && $!{EINTR};
    die "$label: waitpid($pid) fehlgeschlagen: $!" if $waited == -1;
  }
}

sub _terminate_and_reap {
  my ($pid, $label) = @_;
  kill 'TERM', -$pid;
  kill 'TERM',  $pid;
  sleep 0.20;
  kill 'KILL', -$pid;
  kill 'KILL',  $pid;
  return _waitpid_status($pid, $label);
}

sub _terminate_process_group {
  my ($pid) = @_;
  kill 'TERM', -$pid;
  kill 'TERM',  $pid;
  sleep 0.20;
  kill 'KILL', -$pid;
  kill 'KILL',  $pid;
  return 1;
}

sub run_command_capture {
  my (%opt) = @_;
  my $label   = $opt{label}   // 'command';
  my $cmd     = $opt{command} // die "$label: command fehlt";
  my $timeout = $opt{timeout} // COMMAND_TIMEOUT_S;
  die "$label: ungültiger Befehl" if $cmd =~ /[\x00\r\n]/;

  my $stderr = gensym;
  my ($stdout, $pid);
  # In eigene Session/Prozessgruppe starten. Ein blosses setpgid($pid,$pid)
  # aus dem Elternprozess (frueheres Verhalten) schlaegt zuverlaessig fehl,
  # sobald das Kind bereits exec't hat, was bei einem schnellen /bin/sh -c
  # praktisch immer der Fall ist (POSIX: setpgid auf ein bereits exec'tes
  # Kind liefert EACCES). setsid(1) exec't dagegen im Normalfall ohne
  # zusaetzlichen Fork in-place (gleiche PID, Pipes bleiben gueltig) und
  # setzt dabei PGID=eigene PID, wodurch kill(-$pid) im Timeout-Fall auch
  # von der Shell gestartete Hintergrundprozesse mitbeendet. Kein setsid
  # vorhanden -> ohne Wrapper weiterlaufen (bisheriges Verhalten als Fallback).
  my @cmd_argv = ('/bin/sh', '-c', $cmd);
  my ($setsid_bin) = grep { -x $_ } qw(/usr/bin/setsid /bin/setsid);
  unshift @cmd_argv, $setsid_bin, '--' if $setsid_bin;
  $pid = open3(undef, $stdout, $stderr, @cmd_argv);
  my $selector = IO::Select->new($stdout, $stderr);
  my $deadline = time + $timeout;
  my $output = '';
  my $truncated = 0;
  my $child_reaped = 0;
  my $wait_status;

  while (!$child_reaped || $selector->count) {
    unless ($child_reaped) {
      my $waited = waitpid($pid, WNOHANG);
      if ($waited == $pid) {
        $wait_status = $?;
        $child_reaped = 1;
      } elsif ($waited == -1 && !$!{EINTR}) {
        die "$label: waitpid($pid) fehlgeschlagen: $!";
      }
    }

    last if $child_reaped && !$selector->count;

    my $remaining = $deadline - time;
    if ($remaining <= 0) {
      if ($child_reaped) {
        # Der direkte Kindprozess kann beendet sein, während ein von ihm
        # gestarteter Prozess die Pipes noch offen hält.
        _terminate_process_group($pid);
      } else {
        $wait_status = _terminate_and_reap($pid, $label);
        $child_reaped = 1;
      }
      for my $fh ($selector->handles) {
        $selector->remove($fh);
        close $fh;
      }
      die "$label timeout nach ${timeout}s: $cmd";
    }

    unless ($selector->count) {
      sleep($remaining > 0.05 ? 0.05 : $remaining);
      next;
    }

    my @ready = $selector->can_read($remaining > 0.25 ? 0.25 : $remaining);
    next unless @ready;
    for my $fh (@ready) {
      my $buf = '';
      my $n = sysread($fh, $buf, 8192);
      if (defined($n) && $n > 0) {
        if (length($output) < MAX_COMMAND_OUTPUT_B) {
          my $room = MAX_COMMAND_OUTPUT_B - length($output);
          $output .= substr($buf, 0, $room);
          $truncated = 1 if length($buf) > $room;
        } else {
          $truncated = 1;
        }
      } elsif (!defined($n) && $!{EINTR}) {
        # Unterbrochener Syscall: kein EOF, im naechsten Durchlauf erneut versuchen.
        next;
      } elsif (!defined($n)) {
        my $read_error = "$!";
        $selector->remove($fh);
        close $fh;
        if ($child_reaped) {
          _terminate_process_group($pid);
        } else {
          $wait_status = _terminate_and_reap($pid, $label);
          $child_reaped = 1;
        }
        die "$label: Fehler beim Lesen der Kommandoausgabe: $read_error";
      } else {
        # Reguläres EOF (n == 0).
        $selector->remove($fh);
        close $fh;
      }
    }
  }

  $wait_status = _waitpid_status($pid, $label) unless $child_reaped;
  my $signal      = $wait_status & 127;
  my $rc          = $signal ? 128 + $signal : ($wait_status >> 8);

  $output .= "\n[output truncated]" if $truncated;
  $output .= "\n[terminated by signal $signal]" if $signal;
  return ($rc, $output);
}

sub _status_is_running {
  my ($rc, $out) = @_;
  return $rc == 0 ? 1 : 0;
}

sub execute_postmap {
  my ($ci, $map, $inst, $result) = @_;
  my $pm_cmd = postmap_cmd($ci, $map, $inst);

  unless ($pm_cmd) {
    $result->{postmap} = { executed => 0 };
    $logger->info("POSTMAP SKIPPED: instance=$inst map=$map reason=no_command");
    return 1;
  }

  $logger->info("POSTMAP START: instance=$inst map=$map command=$pm_cmd");
  my ($rc, $out) = run_command_capture(
    label   => 'postmap',
    command => $pm_cmd,
    timeout => $ci->{postmap_timeout} // $global->{postmap_timeout} // COMMAND_TIMEOUT_S,
  );
  $result->{postmap} = {
    executed => 1, command => $pm_cmd, rc => $rc, output => $out,
    result => ($rc == 0) ? 'ok' : 'fail',
  };

  if ($rc != 0) {
    $logger->error("POSTMAP FAILED: instance=$inst map=$map rc=$rc output=" . _single_line($out));
    die "postmap rc=$rc: $out";
  }

  $logger->info("POSTMAP OK: instance=$inst map=$map rc=0");
  return 1;
}

sub execute_reload_and_status {
  my ($ci, $inst, $result) = @_;

  unless ($ci->{reload_on_change}) {
    $result->{reload} = { executed => 0 };
    $result->{status} = { executed => 0 };
    $logger->info("RELOAD SKIPPED: instance=$inst reload_on_change=0");
    return 1;
  }

  my $reload_cmd = expand_cmd($ci, $inst, $ci->{reload_cmd} // '');
  if ($reload_cmd) {
    $logger->info("RELOAD START: instance=$inst command=$reload_cmd");
    my ($rc, $out) = run_command_capture(
      label   => 'reload',
      command => $reload_cmd,
      timeout => $ci->{reload_timeout} // $global->{reload_timeout} // COMMAND_TIMEOUT_S,
    );
    $result->{reload} = {
      executed => 1, command => $reload_cmd, rc => $rc, output => $out,
      result => ($rc == 0) ? 'ok' : 'fail',
    };
    if ($rc != 0) {
      $logger->error("RELOAD FAILED: instance=$inst rc=$rc output=" . _single_line($out));
      die "reload rc=$rc: $out";
    }
    $logger->info("RELOAD OK: instance=$inst rc=0");
  } else {
    $result->{reload} = { executed => 0 };
    $logger->info("RELOAD SKIPPED: instance=$inst reason=no_command");
  }

  my $status_cmd = expand_cmd($ci, $inst, $ci->{status_cmd} // '');
  unless ($status_cmd) {
    $result->{status} = { executed => 0 };
    $logger->info("STATUS SKIPPED: instance=$inst reason=no_command");
    return 1;
  }

  $logger->info("STATUS CHECK START: instance=$inst command=$status_cmd");
  my $status_timeout = $ci->{status_timeout} // $global->{status_timeout} // STATUS_TIMEOUT_S;
  my $deadline = time + $status_timeout;
  my ($last_rc, $last_out) = (255, '');

  while (1) {
    my $remaining = $deadline - time;
    last if $remaining <= 0;

    my $command_timeout =
      $ci->{status_command_timeout}
      // $global->{status_command_timeout}
      // COMMAND_TIMEOUT_S;
    $command_timeout = $remaining if $command_timeout > $remaining;

    ($last_rc, $last_out) = run_command_capture(
      label   => 'status',
      command => $status_cmd,
      timeout => $command_timeout,
    );
    if (_status_is_running($last_rc, $last_out)) {
      $result->{status} = {
        executed => 1, command => $status_cmd, rc => $last_rc,
        output => $last_out, result => 'running',
      };
      $logger->info("STATUS OK: instance=$inst state=running rc=$last_rc");
      return 1;
    }
    sleep STATUS_POLL_S;
  }

  $result->{status} = {
    executed => 1, command => $status_cmd, rc => $last_rc,
    output => $last_out, result => 'not_running',
  };
  $logger->error("STATUS FAILED: instance=$inst state=not_running rc=$last_rc output=" . _single_line($last_out));
  die "Status not running (rc=$last_rc): $last_out";
}

sub validate_config {
  my ($g, $insts) = @_;
  die "instances-Konfiguration muss ein Objekt sein" unless ref($insts) eq 'HASH' && %$insts;

  if (exists $g->{allowed_origins}) {
    die "allowed_origins muss ein Array sein" unless ref($g->{allowed_origins}) eq 'ARRAY';
  }
  $g->{allowed_ips} = _normalize_allowed_ips(
    exists($g->{allowed_ips}) ? $g->{allowed_ips} : undef
  );

  for my $inst (sort keys %$insts) {
    my $ci = $insts->{$inst};
    die "Instanz '$inst' muss ein Objekt sein" unless ref($ci) eq 'HASH';
    die "Instanz '$inst': ungültiger Instanzname" unless $inst =~ /\A[0-9A-Za-z._-]+\z/;
    for my $key (qw(config_dir map_dir)) {
      die "Instanz '$inst': $key fehlt" unless defined($ci->{$key}) && length($ci->{$key});
      die "Instanz '$inst': $key enthält Steuerzeichen" if $ci->{$key} =~ /[\x00\r\n]/;
      die "Instanz '$inst': $key muss absolut sein ($ci->{$key})" unless File::Spec->file_name_is_absolute($ci->{$key});
    }

    my $effective_bdir = effective_backup_dir($ci, $inst, $g);
    die "Instanz '$inst': weder backup_dir noch globales backupDir konfiguriert"
      unless defined($effective_bdir) && length($effective_bdir);
    die "Instanz '$inst': Backup-Pfad enthält Steuerzeichen"
      if $effective_bdir =~ /[\x00\r\n]/;
    die "Instanz '$inst': Backup-Pfad muss absolut sein ($effective_bdir)"
      unless File::Spec->file_name_is_absolute($effective_bdir);

    die "Instanz '$inst': config_dir nicht vorhanden: $ci->{config_dir}" unless -d $ci->{config_dir};
    die "Instanz '$inst': main.cf nicht lesbar: $ci->{config_dir}/main.cf" unless -r File::Spec->catfile($ci->{config_dir}, 'main.cf');
    die "Instanz '$inst': map_dir nicht vorhanden: $ci->{map_dir}" unless -d $ci->{map_dir};
    die "Instanz '$inst': map_dir nicht beschreibbar: $ci->{map_dir}" unless -w $ci->{map_dir};
    die "Instanz '$inst': globs muss ein Objekt sein" unless ref($ci->{globs}) eq 'HASH';
    die "Instanz '$inst': postmap_by_type muss ein Objekt sein" unless ref($ci->{postmap_by_type}) eq 'HASH';

    for my $map (keys %{$ci->{globs}}) {
      my $type = $ci->{globs}{$map};
      die "Instanz '$inst': ungültiger Glob '$map'" unless $map =~ /\A[0-9A-Za-z._*-]{1,255}\z/ && $map !~ /\.\./;
      die "Instanz '$inst': gesperrter Map-Name '$map'" if $map !~ /\*/ && _deny_forbidden_map($map);
      die "Instanz '$inst': unbekannter Map-Typ '$type' für '$map'" unless defined($type) && $GLOB_TYPES{$type};
    }

    for my $type (keys %{$ci->{postmap_by_type}}) {
      my $template = $ci->{postmap_by_type}{$type};
      next unless defined($template) && length($template);
      die "Instanz '$inst': unbekannter postmap-Typ '$type'" unless $GLOB_TYPES{$type};
      die "Instanz '$inst': postmap-Template enthält Zeilenumbruch/NUL" if $template =~ /[\x00\r\n]/;
      die "Instanz '$inst': postmap-Template muss mit postmap beginnen"
        unless $template =~ /\A\s*(?:\/[0-9A-Za-z._\/-]+\/)?postmap(?:\s|\z)/;
      die "Instanz '$inst': postmap-Template für '$type' benötigt {path}"
        unless $template =~ /\{path\}/;

      my $qt = quotemeta($type);
      my $strict_ok = $template =~ /\A\s*(?:\/[0-9A-Za-z._\/-]+\/)?postmap(?:\s+-c\s+\{config_dir\})?\s+$qt:\{path\}\s*\z/;
      my $legacy_c_ok = $template =~ /\A\s*(?:\/[0-9A-Za-z._\/-]+\/)?postmap\s+-c\s+$qt:\{path\}\s*\z/;

      die "Instanz '$inst': postmap-Template für '$type' hat keine erlaubte Form"
        unless $strict_ok || $legacy_c_ok;

      if ($legacy_c_ok) {
        $logger->warn(
          "Instanz '$inst': Legacy-postmap-Template '$template' erkannt. "
          . "Es wird zur Laufzeit mit -c {config_dir} korrigiert; configs.json wird nicht verändert."
        );
      }

      while ($template =~ /\{([^}]+)\}/g) {
        die "Instanz '$inst': unbekannter Platzhalter {$1} im postmap-Template"
          unless $1 =~ /\A(?:config_dir|path|inst)\z/;
      }
    }

    for my $key (qw(reload_cmd status_cmd)) {
      next unless defined($ci->{$key}) && length($ci->{$key});
      die "Instanz '$inst': $key enthält Zeilenumbruch/NUL" if $ci->{$key} =~ /[\x00\r\n]/;
    }
  }
  return 1;
}

$logger->info("CONFIG VALIDATION START: global=$global_cfg_file instances=$instances_cfg_file");
validate_config($global, $instances);
$logger->info("CONFIG VALIDATION OK: instances=" . scalar(keys %$instances));
_prepare_runtime_directories();
$logger->info("RUNTIME DIRECTORIES OK");
$logger->info("STARTUP CHECKS OK: switching_to_configured_log=1");

# Erst jetzt den in global.json angegebenen Logpfad vorbereiten. Bei einem Fehler
# bleibt die vollständige Ursache im Journal und der Dienst startet nicht halb.
my $file_logger;
eval {
  _prepare_configured_log(
    $logfile,
    $log_mode,
    $global->{serviceUser},
    $global->{serviceGroup},
  );
  $file_logger = _new_file_logger(
    $logfile,
    $log_mode,
    $global->{serviceUser},
    $global->{serviceGroup},
    $effective_log_level,
  );
  1;
} or do {
  my $log_error = _single_line($@ || 'unbekannter Logger-Fehler');
  my $fatal =
    "LOGGER SWITCH FAILED: path=" . (defined($logfile) ? $logfile : '<missing>')
    . " error=$log_error";
  die $fatal . "\n";
};

# Erfolg noch im Journal bestätigen, dann Hauptlogger atomar umschalten.
$logger->info("LOGGER SWITCH OK: path=$logfile");
$logger = $file_logger;
app->log($logger);

# Der prozessweite __DIE__-Handler ist nur für die Startphase gedacht.
$startup_die_handler_active = 0;
$SIG{__DIE__} = 'DEFAULT';

if ($effective_log_level ne $requested_log_level) {
  $logger->warn("Ungültiges log_level '$requested_log_level'; verwende 'info'");
}
$logger->info(
  "LOGGER READY: backend=Mojo::Log reopen_per_entry=1 path=$logfile "
  . "encoding=UTF-8 level=$effective_log_level mode=" . sprintf('%04o', $log_mode)
);

# -------------------- Backups --------------------

sub backup_file {
  my ($file, $dir, $max, $ci) = @_;
  die "Backup-Quelldatei fehlt: $file" unless -f $file;
  die "Backup-Verzeichnis ist nicht konfiguriert" unless defined($dir) && length($dir);
  die "max_backups muss eine nicht-negative Ganzzahl sein"
    unless defined($max) && $max =~ /\A\d+\z/;

  unless (-d $dir) {
    make_path($dir) or die "Backup-Verzeichnis $dir konnte nicht erstellt werden: $!";
    my $mode = effective_service_dir_mode();
    my $err = set_dir_ownership_and_mode($dir, $global->{serviceUser}, $global->{serviceGroup}, $mode);
    die "Berechtigungen für Backup-Verzeichnis $dir fehlgeschlagen: $err" if $err;
  }
  die "Backup-Verzeichnis nicht beschreibbar: $dir" unless -w $dir;

  my $fraction = int((time - int(time)) * 1_000_000);
  my $ts  = strftime('%Y%m%d_%H%M%S', localtime) . sprintf('_%06d', $fraction);
  my $dst = File::Spec->catfile($dir, basename($file) . ".bak.$ts");
  $logger->info("Erstelle Backup von $file nach $dst");

  my $source_bytes = read_raw_regular($file, 'Backup-Quelldatei');
  my $bk_mode = effective_backup_mode();
  atomic_write_raw(
    $dst,
    $source_bytes,
    $global->{serviceUser},
    $global->{serviceGroup},
    $bk_mode,
  );
  $logger->info("BACKUP OK: source=$file target=$dst");

  my @bak = grep { -f $_ && !-l $_ } glob(File::Spec->catfile($dir, basename($file) . '.bak.*'));
  @bak = sort { (stat($a))[9] <=> (stat($b))[9] } @bak;
  if ($max && @bak > $max) {
    my $to_delete = @bak - $max;
    for my $del (@bak[0 .. $to_delete-1]) {
      unlink $del or $logger->warn("Konnte altes Backup nicht löschen: $del ($!)");
    }
  }
  return $dst;
}

# -------------------- Locks (per Map & Instanz) --------------------

sub _lock_dir_for {
  my ($ci, $inst) = @_;
  my $base = ($ci && $ci->{lock_dir})
    // $config->{global}{lockDir}
    // File::Spec->catdir($config->{global}{tmpDir} // '/tmp', 'postfix-agent-locks');
  return File::Spec->catdir($base, ($inst // 'default'));
}

sub _map_lock_path {
  my ($ci, $inst, $map) = @_;
  my $ldir = _lock_dir_for($ci, $inst);
  return File::Spec->catfile($ldir, "$map.lock");
}

sub _open_lock_file {
  my ($path, $label) = @_;
  $label //= 'Lockfile';

  die "$label ist ein Symlink und wird abgelehnt: $path"
    if !$o_nofollow && -l $path;

  my $flags = O_RDWR | O_CREAT | $o_nofollow;
  sysopen(my $fh, $path, $flags, 0660)
    or die "$label open failed $path: $!";

  my @st = stat($fh);
  unless (@st && S_ISREG($st[2])) {
    close $fh;
    die "$label ist keine reguläre Datei: $path";
  }

  return $fh;
}

sub with_map_lock {
  my ($ci, $map, $exclusive, $code, $inst) = @_;
  $inst //= '';
  my $ldir = _lock_dir_for($ci, $inst);
  unless (-d $ldir) {
    eval { make_path($ldir) };
    die "Lock-Verzeichnis $ldir konnte nicht erstellt werden: $@" if $@;
  }
  my $mode = effective_service_dir_mode();
  my $dir_err = set_dir_ownership_and_mode($ldir, $config->{global}{serviceUser}, $config->{global}{serviceGroup}, $mode);
  die "Lock-Verzeichnis-Rechte fehlgeschlagen: $dir_err" if $dir_err;

  my $lpath = _map_lock_path($ci, $inst, $map);
  my $lfh = _open_lock_file($lpath, 'Lockfile');

  my $e = set_file_ownership_and_mode($lpath, $config->{global}{serviceUser}, $config->{global}{serviceGroup}, '0660');
  die "Lockfile-Rechte fehlgeschlagen: $e" if $e;

  my $want = $exclusive ? LOCK_EX : LOCK_SH;
  my $t0 = time;
  while (1) {
    if (flock($lfh, $want | LOCK_NB)) {
      my $ret; my $err;
      eval { $ret = $code->(); 1 } or $err = $@;
      flock($lfh, LOCK_UN); close $lfh;
      die $err if $err;
      return $ret;
    }
    if ((time - $t0) > LOCK_TIMEOUT_S) {
      close $lfh;
      die "Lock-Timeout ($map)";
    }
    sleep 0.05;
  }
}

sub with_config_lock {
  my ($code) = @_;
  my $base = $config->{global}{lockDir}
    // File::Spec->catdir($config->{global}{tmpDir} // '/tmp', 'postfix-agent-locks');
  my $ldir = File::Spec->catdir($base, '_config');
  unless (-d $ldir) {
    eval { make_path($ldir) };
    die "Config-Lock-Verzeichnis $ldir konnte nicht erstellt werden: $@" if $@;
  }
  my $mode = effective_service_dir_mode();
  my $derr = set_dir_ownership_and_mode($ldir, $config->{global}{serviceUser}, $config->{global}{serviceGroup}, $mode);
  die "Config-Lock-Verzeichnis: $derr" if $derr;

  my $lpath = File::Spec->catfile($ldir, 'configs.json.lock');
  my $lfh = _open_lock_file($lpath, 'Config-Lockfile');
  my $perr = set_file_ownership_and_mode($lpath, $config->{global}{serviceUser}, $config->{global}{serviceGroup}, '0660');
  die "Config-Lockfile Rechte: $perr" if $perr;

  my $t0 = time;
  while (!flock($lfh, LOCK_EX | LOCK_NB)) {
    if ((time - $t0) > LOCK_TIMEOUT_S) {
      close $lfh;
      die "Config-Lock-Timeout";
    }
    sleep 0.05;
  }
  my ($ret, $err);
  eval { $ret = $code->(); 1 } or $err = $@;
  flock($lfh, LOCK_UN);
  close $lfh;
  die $err if $err;
  return $ret;
}


# -------------------- Routen --------------------

get '/' => sub {
  shift->render(json => { info => 'Postfix Agent', version => $VERSION });
};

get '/instances' => sub {
  shift->render(json => { instances => [sort keys %{ $config->{instances} }]} );
};

get '/instances/:inst/maps' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst}
    or return $c->render(status => 404, json => { ok => 0, error => 'Unknown' });

  my %seen;
  my $globs = $ci->{globs} // {};
  my $want_all = ($c->param('all') // '') eq '1';

  if ($want_all || !%$globs) {
    if (opendir(my $dh, $ci->{map_dir})) {
      while (my $e = readdir($dh)) {
        next if $e =~ /^\./;
        next if _deny_forbidden_map($e);
        next unless defined map_type_for_file($ci, $e);
        my $p = "$ci->{map_dir}/$e";
        next if _deny_compiled_map_artifact($e, $p);
        $seen{$e} = 1 if -f $p && !-l $p;
      }
      closedir $dh;
    }
  } else {
    for my $glob (keys %$globs) {
      for my $f (glob "$ci->{map_dir}/$glob") {
        my $bn = basename($f);
        next if _deny_forbidden_map($bn);
        next if _deny_compiled_map_artifact($bn, $f);
        $seen{$bn} = 1 if -f $f && !-l $f;
      }
    }
  }

  $c->render(json => { ok => 1, maps => [sort keys %seen] });
};

# Map anzeigen (Text, UTF-8)
get '/instances/:inst/map/*map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst} or return $c->render(status => 404, json => { ok => 0, error => 'Unknown' });

  my ($map, $err) = sanitize_map_name($c->stash('map'));
  return $c->render(status=>400, json=>{ ok=>0, error=>$err }) if $err;
  return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
    if _deny_forbidden_map($map);
  return $c->render(status=>403, json=>{ ok=>0, error=>'map not registered' })
    unless defined map_type_for_file($ci, $map);

  my $path = "$ci->{map_dir}/$map";
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled map artifact not allowed' })
    if _deny_compiled_map_artifact($map, $path);
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $path;
  unless (-r $path) { return $c->render(status => 404, json => { ok => 0, error => 'Not found' }); }
  my $text = read_text_regular($path, 'Map-Datei');
  $c->res->headers->content_type('text/plain; charset=UTF-8');
  $c->render(data => $text);
};

# Backups auflisten
get '/instances/:inst/backup/*map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst} or return $c->render(status => 404, json => { ok => 0, error => 'Unknown' });

  my ($base, $err) = sanitize_map_name($c->stash('map'));
  return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
  return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
    if _deny_forbidden_map($base);
  return $c->render(status=>403, json=>{ ok=>0, error=>'map not registered' })
    unless defined map_type_for_file($ci, $base);

  my $map_path = "$ci->{map_dir}/$base";
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled map artifact not allowed' })
    if _deny_compiled_map_artifact($base, $map_path);

  my $backup_dir = effective_backup_dir($ci, $inst)
    or return $c->render(status => 404, json => { ok => 0, error => 'No backup_dir' });

  my @files = grep { -f $_ && !-l $_ } glob("$backup_dir/$base.bak.*");
  @files = sort { (stat($b))[9] <=> (stat($a))[9] } @files; # mtime DESC
  @files = map { basename($_) } @files;

  $c->render(json => { ok => 1, backups => \@files });
};

# Backup-Vorschau/-Download
get '/instances/:inst/backupfile/*backup' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst} or return $c->render(status => 404, json => { ok => 0, error => 'Unknown instance' });

  my ($backup_file, $err) = sanitize_map_name($c->stash('backup') // '');
  return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;

  my $backup_dir  = effective_backup_dir($ci, $inst);
  unless ($backup_dir && -d $backup_dir) { return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }); }

  my $backup_map = parse_backup_filename($backup_file);
  return $c->render(status=>400, json=>{ ok=>0, error=>'invalid backup filename' })
    unless defined $backup_map;
  return $c->render(status=>403, json=>{ ok=>0, error=>'map not registered' })
    unless defined map_type_for_file($ci, $backup_map);
  my $fullpath = "$backup_dir/$backup_file";
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled map artifact not allowed' })
    if _deny_compiled_map_artifact($backup_map, $fullpath);
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $fullpath;
  unless ($backup_file && -f $fullpath && -r $fullpath) { return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }); }

  my $mode = $c->param('mode') // 'text';
  if ($mode eq 'download') {
    my $bytes = read_raw_regular($fullpath, 'Backup-Datei');
    $c->res->headers->content_disposition(qq{attachment; filename="$backup_file"});
    $c->res->headers->content_type('application/octet-stream');
    return $c->render(data => $bytes);
  } elsif ($mode eq 'json') {
    my $content = read_text_regular($fullpath, 'Backup-Datei');
    $content =~ s/\r\n/\n/g;
    return $c->render(json => { ok => 1, name => $backup_file, size => length($content), content => $content });
  } else {
    my $content = read_text_regular($fullpath, 'Backup-Datei');
    $c->res->headers->content_type('text/plain; charset=UTF-8');
    return $c->render(data => $content);
  }
};

# Map speichern / anlegen (UTF-8)
post '/instances/:inst/map/*map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst};

  my %result = (
    ok => 1, error => '', changed => 0,
    backup => 'skipped', write => 'skipped',
    postmap => { executed => 0 },
    reload  => { executed => 0 },
    status  => { executed => 0 },
  );

  unless ($ci) {
    $result{ok} = 0; $result{error} = 'Unknown instance';
    return $c->render(json => \%result, status => 404);
  }

  my ($map, $san_err) = sanitize_map_name($c->stash('map'));
  if ($san_err) {
    $result{ok} = 0; $result{error} = $san_err;
    return $c->render(json => \%result, status => 400);
  }
  return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
    if _deny_forbidden_map($map);
  return $c->render(status=>403, json=>{ ok=>0, error=>'map not registered' })
    unless defined map_type_for_file($ci, $map);

  my $path = "$ci->{map_dir}/$map";
  $logger->info("MAP SAVE REQUEST: instance=$inst map=$map target=$path");
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled map artifact not allowed' })
    if _deny_compiled_map_artifact($map, $path);
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $path;

  # Request-Body-Groessenlimit (app->max_request_size) pruefen, BEVOR der Body
  # gelesen wird. Mojolicious kuerzt einen zu grossen Body sonst still und
  # setzt req->error/is_limit_exceeded, was ohne diese Pruefung unbemerkt
  # bliebe: der gekuerzte Inhalt wuerde als vollstaendig gespeichert gelten.
  if ($c->req->can('is_limit_exceeded') && $c->req->is_limit_exceeded) {
    $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=request_too_large");
    return $c->render(status=>413, json=>{ ok=>0, error=>'Anfrage zu gross (max_request_size ueberschritten), Body wurde nicht vollstaendig empfangen' });
  }

  # ---- Inhalt einlesen (JSON / x-www-form-urlencoded / raw) ----
  my $new_content;
  my $ct = $c->req->headers->content_type // '';
  if ($ct =~ m{\bapplication/json\b}i) {
    my $raw_json = $c->req->body // '';
    my $json;
    my $parse_ok = eval {
      $json = from_json($raw_json);
      1;
    };
    unless ($parse_ok) {
      my $json_error = _single_line($@ || 'ungültiges JSON');
      $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=invalid_json error=$json_error");
      return $c->render(status=>400, json=>{ ok=>0, error=>'Ungültiger JSON-Body' });
    }

    if (ref($json) eq 'HASH' && exists $json->{content}) {
      if (ref($json->{content})) {
        $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=content_not_scalar");
        return $c->render(
          status => 400,
          json   => { ok => 0, error => 'content muss ein String oder null sein' },
        );
      }
      $new_content = defined($json->{content}) ? "$json->{content}" : '';
    } elsif (!ref($json)) {
      # JSON null wird wie ein explizit leerer Inhalt behandelt.
      $new_content = defined($json) ? "$json" : '';
    } else {
      $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=json_container_without_scalar_content");
      return $c->render(
        status => 400,
        json   => { ok => 0, error => 'JSON-Arrays/-Objekte benötigen einen skalaren content-Wert' },
      );
    }
  } else {
    my $form_content = $c->param('content');
    if (defined $form_content) {
      $new_content = $form_content;
    } else {
      my $raw_body = $c->req->body // '';
      my $decode_ok = eval {
        $new_content = decode('UTF-8', $raw_body, FB_CROAK);
        1;
      };
      unless ($decode_ok) {
        my $utf8_error = _single_line($@ || 'ungültiges UTF-8');
        $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=invalid_utf8 error=$utf8_error");
        return $c->render(status=>400, json=>{ ok=>0, error=>'Raw-Body enthält kein gültiges UTF-8' });
      }
    }
  }
  # Erneute Pruefung: manche Mojolicious-Versionen setzen das Limit-Flag erst
  # nachdem der Body tatsaechlich (und damit gekuerzt) gelesen wurde.
  if ($c->req->can('is_limit_exceeded') && $c->req->is_limit_exceeded) {
    $logger->warn("MAP SAVE REJECTED: instance=$inst map=$map reason=request_too_large_post_read");
    return $c->render(status=>413, json=>{ ok=>0, error=>'Anfrage zu gross (max_request_size ueberschritten), Body wurde nicht vollstaendig empfangen' });
  }
  $new_content =~ s/\r\n/\n/g if defined $new_content;

  # ---- map_dir sicherstellen ----
  my $dir = dirname($path);
  unless (-d $dir) {
    eval { make_path($dir) };
    if ($@) {
      return $c->render(status => 500, json => { ok => 0, error => 'map_dir create failed', details => { dir => $dir, msg => "$@", inst => $inst } });
    }
    my $err = set_dir_ownership_and_mode($dir, $global->{serviceUser}, $global->{serviceGroup}, effective_service_dir_mode());
    $logger->warn("set_dir_ownership_and_mode($dir): $err") if $err;
  }
  unless (-w $dir) {
    my @st = stat($dir);
    return $c->render(status => 403, json => {
      ok => 0, error => 'Directory not writable',
      details => {
        dir  => $dir,
        mode => sprintf('%04o', ($st[2] // 0) & 07777),
        uid  => $st[4], gid => $st[5],
        euid => $<, egid => $(,
        inst => $inst
      }
    });
  }

  if (-e $path && !-w $path) {
    $result{ok} = 0; $result{error} = 'Not found or not writable';
    return $c->render(json => \%result, status => 403);
  }

  # Vergleich, Backup und Schreiben erfolgen unter demselben Map-Lock. Damit
  # kann kein zweiter API-Writer zwischen Vergleich und atomarem Rename einen
  # inzwischen veralteten Stand unterschieben.
  my $lock_err;
  eval {
    with_map_lock($ci, $map, 1, sub {
      die "Binäres Map-Artefakt darf nicht überschrieben werden: $path"
        if _deny_compiled_map_artifact($map, $path);

      my $exists = -e $path ? 1 : 0;
      my $old_content = $exists ? read_text_regular($path, 'Map-Datei') : '';

      # Minimalinhalt, wenn eine neue Map mit leerem Body angelegt wird.
      if (!$exists && (!defined($new_content) || $new_content eq '')) {
        $new_content = "#\n";
      }

      return 1 if $new_content eq $old_content;

      $result{changed} = 1;
      my $bdir = effective_backup_dir($ci, $inst);
      if ($exists) {
        backup_file($path, $bdir, $ci->{max_backups} // 5, $ci);
        $result{backup} = 'ok';
      } else {
        $result{backup} = 'not_existing';
      }

      atomic_write(
        $path, $new_content,
        effective_service_user(),
        effective_service_group(),
        effective_file_mode()
      );
      $logger->info("Atomic write: $path (user=".effective_service_user().", group=".effective_service_group().", mode=".effective_file_mode().")");
      $result{write} = 'ok';

      execute_postmap($ci, $map, $inst, \%result);
      execute_reload_and_status($ci, $inst, \%result);
      return 1;
    }, $inst);
    1;
  } or do { $lock_err = $@; };

  if ($lock_err) {
    $logger->error("MAP SAVE FAILED: instance=$inst map=$map error=" . _single_line($lock_err));
    if ($lock_err =~ /Lock-Timeout/) {
      return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
    }
    $result{ok} = 0; $result{error} = "$lock_err";
    return $c->render(json => \%result, status => 500);
  }

  if ($result{changed}) {
    $logger->info("MAP SAVE OK: instance=$inst map=$map changed=1");
  } else {
    $logger->info("MAP SAVE SKIPPED: instance=$inst map=$map reason=no_change");
  }
  return $c->render(json => \%result);
};

# --------- RESTORE ---------
post '/instances/:inst/restore/*backupfile' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $ci   = $config->{instances}{$inst};
  return $c->render(status => 404, json => { ok => 0, error => 'Unknown instance' }) unless $ci;

  my ($backupfile, $err) = sanitize_map_name($c->stash('backupfile') // '');
  return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;

  my $backup_dir = effective_backup_dir($ci, $inst);
  my $map_dir    = $ci->{map_dir};
  return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }) unless $backup_dir && -d $backup_dir;
  return $c->render(status => 500, json => { ok => 0, error => 'No map dir' })    unless $map_dir    && -d $map_dir;

  my $src = "$backup_dir/$backupfile";
  return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }) unless -f $src;

  my $map = parse_backup_filename($backupfile);
  return $c->render(status=>400, json=>{ ok=>0, error=>'invalid backup filename' }) unless defined $map;
  return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
    if _deny_forbidden_map($map);
  return $c->render(status=>403, json=>{ ok=>0, error=>'map not registered' })
    unless defined map_type_for_file($ci, $map);
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled map artifact not allowed' })
    if _deny_compiled_map_artifact($map, $src);
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $src;

  my $dst = "$map_dir/$map";
  $logger->info("RESTORE START: instance=$inst map=$map backup=$backupfile target=$dst");

  my %result = ( ok => 1, restored => $backupfile, target => $dst );
  return $c->render(status=>403, json=>{ ok=>0, error=>'compiled restore target not allowed' })
    if _deny_compiled_map_artifact($map, $dst);
  return $c->render(status=>403, json=>{ ok=>0, error=>'restore target symlink not allowed' }) if -l $dst;

  my $lock_err;
  eval {
    with_map_lock($ci, $map, 1, sub {
      die "Binäres Backup-Artefakt darf nicht wiederhergestellt werden: $src"
        if _deny_compiled_map_artifact($map, $src);
      die "Binäres Map-Artefakt darf nicht überschrieben werden: $dst"
        if _deny_compiled_map_artifact($map, $dst);

      my $restore_content = read_text_regular($src, 'Backup-Datei');
      if (-f $dst) {
        my $before = backup_file($dst, $backup_dir, $ci->{max_backups} // 5, $ci);
        $result{pre_restore_backup} = $before;
      }
      atomic_write(
        $dst, $restore_content,
        effective_service_user(), effective_service_group(), effective_file_mode()
      );
      $result{write} = 'ok';
      $logger->info("RESTORE WRITE OK: instance=$inst map=$map backup=$backupfile target=$dst");
      execute_postmap($ci, $map, $inst, \%result);
      execute_reload_and_status($ci, $inst, \%result);
      $logger->info("RESTORE OK: instance=$inst map=$map backup=$backupfile target=$dst");
    }, $inst);
    1;
  } or do { $lock_err = $@; };

  if ($lock_err) {
    $logger->error("RESTORE FAILED: instance=$inst map=$map backup=$backupfile error=" . _single_line($lock_err));
    if ($lock_err =~ /Lock-Timeout/) {
      return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
    }
    $result{ok} = 0;
    $result{error} = "Fehler beim Restore: $lock_err";
    return $c->render(status => 500, json => \%result);
  }

  return $c->render(json => \%result);
};

# Map deregistrieren (nur configs.json) + Hinweise
post '/instances/:inst/delmap/*map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');

  my ($map, $err) = sanitize_map_name($c->stash('map'));
  return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
  return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
    if _deny_forbidden_map($map);

  my $ci = $config->{instances}{$inst}
    or return $c->render(status => 404, json => { ok => 0, error => 'Unknown instance' });

  my $cfg_label = 'configs.json';
  my $cfg_file  = $instances_cfg_file;

  my $cfg_write_err;
  my $removed_from_globs = 0;
  my $instances_data = {};
  my $has_wrapper    = 0;

  eval {
    with_config_lock(sub {
      $instances_data = -e $instances_cfg_file
        ? from_json(read_text($instances_cfg_file))
        : {};

      $has_wrapper = ref($instances_data->{instances}) eq 'HASH' ? 1 : 0;
      my $insts = $has_wrapper ? $instances_data->{instances} : $instances_data;
      die "Unknown instance '$inst'" unless exists $insts->{$inst};

      if (ref($insts->{$inst}{globs}) eq 'HASH' && exists $insts->{$inst}{globs}{$map}) {
        delete $insts->{$inst}{globs}{$map};
        _write_cfg_hash_atomic($instances_data);
        $removed_from_globs = 1;
        _rebuild_cfgmap_from($instances_data);
      }
    });
    1;
  } or do { $cfg_write_err = $@; };

  if ($cfg_write_err) {
    return $c->render(status => 500, json => { ok => 0, error => "Konfiguration konnte nicht aktualisiert werden: $cfg_write_err" });
  }

  my @matched_patterns;
  eval {
    my $insts   = $has_wrapper ? $instances_data->{instances} : $instances_data;
    my $globs_h = (ref($insts->{$inst}{globs}) eq 'HASH') ? $insts->{$inst}{globs} : {};

    unless ($removed_from_globs) {
      for my $glob (keys %$globs_h) {
        next if $glob eq $map;
        my $re = quotemeta($glob); $re =~ s/\\\*/.*/g;
        push @matched_patterns, $glob if $map =~ /\A$re\z/;
      }
    }
    1;
  } or do { $logger->warn("Pattern-Check fehlgeschlagen: $@"); };

  my ($action, $msg);
  if ($removed_from_globs) {
    $action = 'removed';
    $msg    = "Eintrag in $cfg_label → globs der Instanz '$inst' wurde für '$map' entfernt.";
  } elsif (@matched_patterns) {
    $action = 'pattern_only';
    $msg    = "Kein exakter Eintrag für '$map' in $cfg_label → globs der Instanz '$inst'. "
            . "Die Datei wird jedoch durch folgende Muster abgedeckt: "
            . join(', ', @matched_patterns) . ". Es wurde nichts geändert.";
  } else {
    $action = 'not_registered';
    $msg    = "Für '$map' existiert kein Eintrag in $cfg_label → globs der Instanz '$inst'. "
            . "Es wurde nichts geändert.";
  }

  $msg .= " Diese API löscht keine Dateien. Bitte bereinige Verweise in main.cf/master.cf bei Bedarf.";

  my %result = (
    ok                   => 1,
    instance             => $inst,
    map                  => $map,
    action               => $action,
    matched_patterns     => \@matched_patterns,
    changed_configs_json => $removed_from_globs ? true : false,
    action_required      => $msg,
    note                 => "Kein Reload und keine Datei-Löschung durchgeführt (Policy).",
    configs_file         => $cfg_file,
  );
  $c->res->headers->content_type('application/json; charset=UTF-8');
  return $c->render(json => \%result);
};

# ======== API: globs lesen ====================================================
get '/instances/:inst/globs' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  return $c->render(status=>404, json=>{ok=>0,error=>'Unknown instance'})
    unless exists $config->{instances}{$inst};

  my $cfg  = eval { _read_cfg_hash() };
  return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;

  my $node = _inst_node_rw($cfg, $inst);
  my $gl   = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};
  $c->render(json => { ok=>1, instance=>$inst, globs=>$gl });
};

# ======== API: globs upsert ===================================================
post '/instances/:inst/globs' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  return $c->render(status=>404, json=>{ok=>0,error=>'Unknown instance'})
    unless exists $config->{instances}{$inst};

  my $j = eval { $c->req->json }; $j = {} if $@ || !defined $j;

  my @items;
  if (ref($j) eq 'HASH' && %$j) {
    @items = ref($j->{items}) eq 'ARRAY' ? @{$j->{items}} : ($j);
  } else {
    if (defined(my $items_param = $c->param('items'))) {
      my $arr = eval { from_json($items_param) } || [];
      @items = @$arr if ref($arr) eq 'ARRAY';
    }
    if (!@items) {
      my $map  = $c->param('map')  // '';
      my $type = $c->param('type') // '';
      push @items, { map => $map, type => $type };
    }
  }

  unless (@items) {
    return $c->render(status=>400, json=>{ ok=>0, error=>'Payload fehlt oder ungültig' });
  }

  my @changes;
  my %seen_type;
  for my $it (@items) {
    return $c->render(status=>400, json=>{ok=>0,error=>'Jedes items-Element muss ein Objekt sein'})
      unless ref($it) eq 'HASH';

    my $map_raw  = $it->{map}  // '';
    my $type_raw = $it->{type} // '';

    return $c->render(status=>400, json=>{ok=>0,error=>'map und type müssen Strings sein'})
      if ref($map_raw) || ref($type_raw);

    return $c->render(status=>400, json=>{ok=>0,error=>'map fehlt'})  unless length $map_raw;
    return $c->render(status=>400, json=>{ok=>0,error=>'type fehlt'}) unless length $type_raw;

    my ($map, $e_map) = sanitize_glob_key($map_raw);
    return $c->render(status=>400, json=>{ok=>0,error=>"ungültiger map-key: ".($e_map||'?')})
      unless defined $map;

    my ($type_norm, $e_type) = sanitize_glob_val(lc $type_raw);
    return $c->render(status=>400, json=>{ok=>0,error=>"ungültiger type: ".($e_type||'?')})
      unless defined $type_norm;

    return $c->render(status=>400, json=>{ok=>0,error=>"ungültiger type: $type_norm"})
      unless $GLOB_TYPES{$type_norm};

    if (exists $seen_type{$map}) {
      return $c->render(status=>400, json=>{
        ok=>0,
        error=>"Map-Key '$map' ist im selben Request mit unterschiedlichen Typen definiert",
      }) if $seen_type{$map} ne $type_norm;
      next;
    }
    $seen_type{$map} = $type_norm;
    push @changes, [$map, $type_norm];
  }

  my (@applied, $cfg_err);
  eval {
    with_config_lock(sub {
      my $cfg = _read_cfg_hash();
      my $node = _inst_node_rw($cfg, $inst);
      $node->{globs} //= {};
      for my $ch (@changes) {
        my ($map,$type) = @$ch;
        die "Gesperrter Map-Name '$map'" if $map !~ /\*/ && _deny_forbidden_map($map);
        my $prev = $node->{globs}{$map};
        $node->{globs}{$map} = $type;
        push @applied, { map => $map, type => $type, action => (defined $prev ? 'updated' : 'created'), previous_type => $prev };
      }
      validate_config($global, (ref($cfg->{instances}) eq 'HASH' ? $cfg->{instances} : $cfg));
      _write_cfg_hash_atomic($cfg);
      _rebuild_cfgmap_from($cfg);
    });
    1;
  } or $cfg_err = $@;
  if ($cfg_err) {
    $logger->error("CONFIG UPDATE FAILED: instance=$inst error=" . _single_line($cfg_err));
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json aktualisieren: $cfg_err"});
  }

  $logger->info("CONFIG UPDATE OK: instance=$inst changes=" . scalar(@applied));
  return $c->render(json => { ok=>1, instance=>$inst, upserted=>\@applied });
};

# ======== API: globs delete (einzelner exakter Key; Punkte erlaubt) ==========
del '/instances/:inst/globs/#map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  return $c->render(status=>404, json=>{ok=>0,error=>'Unknown instance'})
    unless exists $config->{instances}{$inst};

  my ($map, $map_err) = sanitize_glob_key($c->stash('map'));
  return $c->render(status=>400, json=>{ok=>0,error=>$map_err}) if $map_err;

  my ($had, $cfg_err);
  eval {
    with_config_lock(sub {
      my $cfg  = _read_cfg_hash();
      my $node = _inst_node_rw($cfg, $inst);
      my $globs = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};

      # Exakter Registrierungsnachweis ist die einzige Löschfreigabe.
      # Wildcard-Muster werden hier bewusst nicht ausgewertet.
      $had = exists $globs->{$map} ? 1 : 0;
      return 1 unless $had;

      delete $globs->{$map};
      validate_config($global, (ref($cfg->{instances}) eq 'HASH' ? $cfg->{instances} : $cfg));
      _write_cfg_hash_atomic($cfg);
      _rebuild_cfgmap_from($cfg);
      return 1;
    });
    1;
  } or $cfg_err = $@;

  if ($cfg_err) {
    $logger->error("CONFIG DELETE FAILED: instance=$inst map=$map error=" . _single_line($cfg_err));
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json aktualisieren: $cfg_err"});
  }

  unless ($had) {
    $logger->info("CONFIG DELETE SKIPPED: instance=$inst map=$map reason=not_registered");
    return $c->render(
      status => 404,
      json   => {
        ok      => 0,
        instance=> $inst,
        map     => $map,
        removed => false,
        error   => 'Map key not registered',
      },
    );
  }

  $logger->info("CONFIG DELETE OK: instance=$inst map=$map removed=1");
  return $c->render(json => {
    ok      => 1,
    instance=> $inst,
    map     => $map,
    removed => true,
    note    => 'Only configs.json was changed; no Postfix file was deleted',
  });
};

# Health
get '/health' => sub {
  my $c = shift;
  my @required_dirs = ($tmp_dir);
  for my $name (keys %{ $config->{instances} }) {
    my $ci = $config->{instances}{$name};
    my $bdir = effective_backup_dir($ci, $name);
    push @required_dirs, $bdir if $bdir;
  }
  my @miss = grep { $_ && !-d $_ } @required_dirs;
  if (@miss) { $c->render(status => 500, json => { ok => 0, error => "Missing dirs: @miss" }); }
  else       { $c->render(json => { ok => 1, status => "ok" }); }
};

any '/*' => sub { shift->render(status => 404, json => { ok => 0, error => 'Not found' }) };

# -------------------- Start Server --------------------

my $url;
if ($ssl_enable && $ssl_cert && $ssl_key) {
  my $cert_q = url_escape($ssl_cert);
  my $key_q  = url_escape($ssl_key);
  $url = sprintf('https://%s?cert=%s&key=%s', $listen_addr, $cert_q, $key_q);
} else {
  $url = sprintf('http://%s', $listen_addr);
}

my $start_log_ok = eval {
  $logger->info("SERVICE START OK: version=$VERSION listen=$url require_https=".($require_https?1:0)." instances=".scalar(keys %$instances));
  1;
};
unless ($start_log_ok) {
  $logger->error("Logger-Fehler: " . _single_line($@ || 'unbekannter Fehler'));
}

app->start('daemon', '-l', $url);

