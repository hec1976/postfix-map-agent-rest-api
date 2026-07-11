#!/usr/bin/env perl
# Postfix Map Agent - REST
# Version: 1.4.3-hardened-compatible (2026-07-11)
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
# - Konsistentes Logging (Log4perl) statt warn
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

binmode STDOUT, ':encoding(UTF-8)';
binmode STDERR, ':encoding(UTF-8)';

use Mojolicious::Lite;
use JSON::MaybeXS;
use File::Basename qw(basename dirname);
use File::Copy qw(copy);
use POSIX qw(strftime setpgid);
use FindBin qw($Bin);
use Log::Log4perl qw(:easy);
use Try::Tiny;
use File::Temp qw(tempfile);
use File::Path qw(make_path);
use File::Spec;
use Encode qw(decode_utf8);
use Net::CIDR;
use Mojo::Util qw(url_escape);
use Mojo::JSON qw(true false);
use Fcntl qw(:mode O_CREAT O_EXCL O_WRONLY O_RDWR :flock);
use Time::HiRes qw(time sleep);
use IPC::Open3 qw(open3);
use IO::Select;
use Symbol qw(gensym);


use constant LOCK_TIMEOUT_S       => 3.0;
use constant COMMAND_TIMEOUT_S    => 30;
use constant STATUS_TIMEOUT_S     => 5.0;
use constant STATUS_POLL_S        => 0.25;
use constant MAX_COMMAND_OUTPUT_B => 1_048_576;

our $VERSION = '1.4.3-hardened-compatible';
# Umask bewusst restriktiv: Group-RW, Other none
umask 0007;

# Logger wird zweistufig initialisiert:
# - vor global.json/Log4perl in ein festes Bootstrap-Log
# - danach zusätzlich in das konfigurierte Hauptlog
my $BOOTSTRAP_LOG = '/var/log/mmbb/postfix-agent-startup.log';
my $logger;
my $logger_ready = 0;
my $in_die_handler = 0;

sub _single_line {
  my ($msg) = @_;
  $msg //= '';
  $msg =~ s/[\r\n]+/ | /g;
  $msg =~ s/^\s+|\s+$//g;
  return $msg;
}

sub _bootstrap_log {
  my ($level, $msg) = @_;
  $level //= 'ERROR';
  $msg = _single_line($msg);
  my $line = strftime('%Y/%m/%d %H:%M:%S', localtime) . " $level $msg\n";

  eval {
    my $dir = dirname($BOOTSTRAP_LOG);
    make_path($dir) unless -d $dir;
    open my $fh, '>>:encoding(UTF-8)', $BOOTSTRAP_LOG or return;
    print {$fh} $line;
    close $fh;
    1;
  };
}

sub _log_fatal {
  my ($msg) = @_;
  $msg = _single_line($msg);
  if ($logger_ready && $logger) {
    eval { $logger->error("FATAL: $msg") };
  }
  _bootstrap_log('ERROR', "FATAL: $msg");
}

# Unbehandelte Startfehler werden immer protokolliert. Fehler innerhalb eines
# eval-Blocks werden am jeweiligen Aufrufer gezielt geloggt, damit es keine
# irreführenden Doppelmeldungen gibt.
$SIG{__DIE__} = sub {
  my ($msg) = @_;
  return if $^S;
  return if $in_die_handler;
  $in_die_handler = 1;
  _log_fatal($msg);
  $in_die_handler = 0;
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

sub _random_secret {
  my $bytes = '';
  if (open my $fh, '<:raw', '/dev/urandom') {
    my $read = read($fh, $bytes, 48);
    close $fh;
    return unpack('H*', $bytes) if defined $read && $read == 48;
  }
  die "Sicherer Zufallsgenerator /dev/urandom ist nicht verfügbar";
}

sub _constant_time_eq {
  my ($a, $b) = @_;
  $a //= '';
  $b //= '';
  my $diff = length($a) ^ length($b);
  my $max  = length($a) > length($b) ? length($a) : length($b);
  for my $i (0 .. ($max ? $max - 1 : 0)) {
    my $ca = $i < length($a) ? ord(substr($a, $i, 1)) : 0;
    my $cb = $i < length($b) ? ord(substr($b, $i, 1)) : 0;
    $diff |= ($ca ^ $cb);
  }
  return $diff == 0;
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
  return oct($m) if "$m" =~ /^[0-7]{3,4}$/;  # "0644" -> 420
  return $m if "$m" =~ /^\d+$/;              # 420 -> 420
  return;
}

sub read_json_config {
  my ($file) = @_;

  my $text;
  eval { $text = read_text($file); 1 }
    or die "CONFIG READ FAILED: file=$file error=" . _single_line($@);

  my $data;
  eval { $data = JSON::MaybeXS->new(utf8=>0)->decode($text); 1 }
    or die "CONFIG JSON INVALID: file=$file error=" . _single_line($@);

  return $data;
}

# -------------------- Config laden --------------------

my $global_cfg_file    = "$Bin/global.json";
my $instances_cfg_file = "$Bin/configs.json";
die "Missing config $global_cfg_file\n"    unless -f $global_cfg_file;
die "Missing config $instances_cfg_file\n" unless -f $instances_cfg_file;

my $global         = read_json_config($global_cfg_file);
my $instances_raw  = read_json_config($instances_cfg_file);
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

# -------------------- Logging vorbereiten --------------------

my $logfile = $global->{logfile} // "/var/log/mmbb/postfix-agent.log";
die "Ungültiger Log-Pfad" if $logfile =~ /[\x00\r\n]/ || !File::Spec->file_name_is_absolute($logfile);
my $logdir  = dirname($logfile);
unless (-d $logdir) {
  eval { make_path($logdir) };
  die "Kann Log-Verzeichnis $logdir nicht anlegen: $@" if $@;
}
my $log_conf = qq(
log4perl.rootLogger                   = INFO, LOGFILE
log4perl.appender.LOGFILE             = Log::Log4perl::Appender::File
log4perl.appender.LOGFILE.filename    = $logfile
log4perl.appender.LOGFILE.mode        = append
log4perl.appender.LOGFILE.utf8        = 1
log4perl.appender.LOGFILE.layout      = Log::Log4perl::Layout::PatternLayout
log4perl.appender.LOGFILE.layout.ConversionPattern = %d %p %m%n
);
eval { Log::Log4perl->init(\$log_conf) } or die "Log4perl-Init fehlgeschlagen ($logfile): $@";
$logger = Log::Log4perl->get_logger();
$logger_ready = 1;

# Logfile-Owner/Group nachziehen (Modus via umask/UMask)
my $log_perm_err = set_file_ownership_and_mode($logfile, $global->{serviceUser}, $global->{serviceGroup});
$logger->warn("Logfile-Rechte konnten nicht vollständig gesetzt werden: $log_perm_err") if $log_perm_err;

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

# Backup-Fallback: backupDir/<inst>
sub effective_backup_dir {
  my ($ci, $inst) = @_;
  return $ci->{backup_dir} if $ci && $ci->{backup_dir};
  return File::Spec->catdir($global->{backupDir}, $inst) if $global->{backupDir};
  return; # kein Fallback
}

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
    my $dir = effective_backup_dir($instances->{$name}, $name) // next;
    unless (-d $dir) {
      eval { make_path($dir) };
      if ($@) { $logger->error("Backup-Verzeichnis $dir konnte nicht erstellt werden: $@"); next; }
    }
    my $err = set_dir_ownership_and_mode($dir, $owner, $group, $mode);
    $logger->warn($err) if $err;
  }
}

# tmp-dir
my $tmp_dir = $global->{tmpDir} // '/tmp';
unless (-d $tmp_dir) { eval { make_path($tmp_dir) }; die "Konnte tmp_dir $tmp_dir nicht anlegen: $@" if $@; }

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

hook before_dispatch => sub {
  my $c = shift;

  my $ips_rt = $config->{global}{allowed_ips};
  my @acl_rt = @{ (ref($ips_rt) eq 'ARRAY' && @$ips_rt ? $ips_rt : ['127.0.0.1']) };

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
  unless ($acl_ok) {
    return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
  }

  if ($c->req->method eq 'OPTIONS') {
    return $c->render(text => '', status => 204);
  }

  my $hdr_token = $c->req->headers->header('X-API-Token') // '';
  my $bearer    = ($c->req->headers->authorization // '') =~ /^Bearer\s+(.+)/i ? $1 : '';
  my $token     = $hdr_token || $bearer;
  unless (_constant_time_eq($token, $api_token)) {
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
  my $cfg = JSON::MaybeXS->new(utf8=>0)->decode( read_text($instances_cfg_file) );
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
  my $json = JSON::MaybeXS->new(utf8=>0, canonical=>1, pretty=>1)->encode($cfg);
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
  return 1 if ($name // '') =~ /\.(?:lmdb|db|dir|pag)$/i;
  return 0;
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
  for my $glob (keys %$globs) {
    next if $glob eq $file;
    my $type = $globs->{$glob};
    my $re = quotemeta($glob);
    $re =~ s/\\\*/.*/g;
    return $type if $file =~ /\A$re\z/;
  }
  return;
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

sub run_command_capture {
  my (%opt) = @_;
  my $label   = $opt{label}   // 'command';
  my $cmd     = $opt{command} // die "$label: command fehlt";
  my $timeout = $opt{timeout} // COMMAND_TIMEOUT_S;
  die "$label: ungültiger Befehl" if $cmd =~ /[\x00\r\n]/;

  my $stderr = gensym;
  my ($stdout, $pid);
  $pid = open3(undef, $stdout, $stderr, '/bin/sh', '-c', $cmd);
  eval { setpgid($pid, $pid) };
  my $selector = IO::Select->new($stdout, $stderr);
  my $deadline = time + $timeout;
  my $output = '';
  my $truncated = 0;

  while ($selector->count) {
    my $remaining = $deadline - time;
    if ($remaining <= 0) {
      kill 'TERM', -$pid;
      kill 'TERM',  $pid;
      sleep 0.20;
      kill 'KILL', -$pid;
      kill 'KILL',  $pid;
      waitpid($pid, 0);
      die "$label timeout nach ${timeout}s: $cmd";
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
      } else {
        $selector->remove($fh);
        close $fh;
      }
    }
  }
  waitpid($pid, 0);
  my $rc = $? >> 8;
  $output .= "\n[output truncated]" if $truncated;
  return ($rc, $output);
}

sub _status_is_running {
  my ($rc, $out) = @_;
  return 0 unless $rc == 0;
  return 1 if $out =~ /(?:is\s+running|^active\b|^running\b)/im;
  return 0;
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
  my $deadline = time + ($ci->{status_timeout} // $global->{status_timeout} // STATUS_TIMEOUT_S);
  my ($last_rc, $last_out) = (255, '');

  while (time < $deadline) {
    ($last_rc, $last_out) = run_command_capture(
      label   => 'status',
      command => $status_cmd,
      timeout => $ci->{status_command_timeout} // $global->{status_command_timeout} // COMMAND_TIMEOUT_S,
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
  if (exists $g->{allowed_ips}) {
    die "allowed_ips muss ein nicht-leeres Array sein"
      unless ref($g->{allowed_ips}) eq 'ARRAY' && @{$g->{allowed_ips}};
  }

  for my $inst (sort keys %$insts) {
    my $ci = $insts->{$inst};
    die "Instanz '$inst' muss ein Objekt sein" unless ref($ci) eq 'HASH';
    die "Instanz '$inst': ungültiger Instanzname" unless $inst =~ /\A[0-9A-Za-z._-]+\z/;
    for my $key (qw(config_dir map_dir backup_dir)) {
      die "Instanz '$inst': $key fehlt" unless defined($ci->{$key}) && length($ci->{$key});
      die "Instanz '$inst': $key enthält Steuerzeichen" if $ci->{$key} =~ /[\x00\r\n]/;
      die "Instanz '$inst': $key muss absolut sein ($ci->{$key})" unless File::Spec->file_name_is_absolute($ci->{$key});
    }
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

# -------------------- Backups --------------------

sub backup_file {
  my ($file, $dir, $max, $ci) = @_;
  die "Backup-Quelldatei fehlt: $file" unless -f $file;
  _assert_not_symlink($file, 'Backup-Quelldatei');
  die "Backup-Verzeichnis ist nicht konfiguriert" unless defined($dir) && length($dir);

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

  copy($file, $dst) or die "Backup fehlgeschlagen ($file -> $dst): $!";
  my $bk_mode = effective_backup_mode();
  my $err = set_file_ownership_and_mode($dst, $global->{serviceUser}, $global->{serviceGroup}, $bk_mode);
  die "Backup-Berechtigungen für $dst fehlgeschlagen: $err" if $err;
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
  sysopen(my $lfh, $lpath, O_RDWR|O_CREAT, 0660)
    or die "Lockfile open failed $lpath: $!";

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
  sysopen(my $lfh, $lpath, O_RDWR|O_CREAT, 0660)
    or die "Config-Lockfile open failed $lpath: $!";
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
        $seen{$e} = 1 if -f $p && !-l $p;
      }
      closedir $dh;
    }
  } else {
    for my $glob (keys %$globs) {
      for my $f (glob "$ci->{map_dir}/$glob") {
        my $bn = basename($f);
        next if _deny_forbidden_map($bn);
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
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $path;
  unless (-r $path) { return $c->render(status => 404, json => { ok => 0, error => 'Not found' }); }
  my $text = read_text($path);
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
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $fullpath;
  unless ($backup_file && -f $fullpath && -r $fullpath) { return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }); }

  my $mode = $c->param('mode') // 'text';
  if ($mode eq 'download') {
    my $bytes = read_raw($fullpath);
    $c->res->headers->content_disposition(qq{attachment; filename="$backup_file"});
    $c->res->headers->content_type('application/octet-stream');
    return $c->render(data => $bytes);
  } elsif ($mode eq 'json') {
    my $content = read_text($fullpath);
    $content =~ s/\r\n/\n/g;
    return $c->render(json => { ok => 1, name => $backup_file, size => length($content), content => $content });
  } else {
    my $content = read_text($fullpath);
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
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $path;

  # ---- Inhalt einlesen (JSON / x-www-form-urlencoded / raw) ----
  my $new_content;
  my $ct = $c->req->headers->content_type // '';
  my $json;
  if ($ct =~ m{\bapplication/json\b}i) {
    $json = eval { $c->req->json };
    $logger->warn("JSON parse failed: $@") if $@;
  }
  if (defined $json) {
    if (ref($json) eq 'HASH' && exists $json->{content}) { $new_content = $json->{content}; }
    elsif (!ref($json))                                   { $new_content = "$json"; }
    else {
      $new_content = JSON::MaybeXS->new(utf8=>0, canonical=>1)->encode($json);
    }
  }
  $new_content //= $c->param('content');
  $new_content //= decode_utf8($c->req->body // '');
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

  # ---- alten Inhalt lesen ----
  my $old_content = '';
  my $read_error = 0;
  try {
    $old_content = (-e $path) ? read_text($path) : '';
  } catch {
    $read_error = $_; $logger->error("Fehler beim Lesen von $path: $_");
  };
  if ($read_error) {
    $result{ok} = 0; $result{error} = "Fehler beim Lesen: $read_error";
    return $c->render(json => \%result, status => 500);
  }

  # ---- Minimalinhalt, wenn NEU & leerer Body ----
  if (!-e $path) {
    $new_content = "#\n" unless defined($new_content) && $new_content ne '';
  }

  if ($new_content ne $old_content) {
    $result{changed} = 1;

    my $lock_err;
    eval {
      with_map_lock($ci, $map, 1, sub {
        my $bdir = effective_backup_dir($ci, $inst);

        if (-e $path) {
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

    $logger->info("MAP SAVE OK: instance=$inst map=$map changed=1");
    return $c->render(json => \%result);
  }

  $result{write}  = 'skipped';
  $result{backup} = 'skipped';
  $logger->info("MAP SAVE SKIPPED: instance=$inst map=$map reason=no_change");
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
  return $c->render(status=>403, json=>{ ok=>0, error=>'symlink not allowed' }) if -l $src;

  my $dst = "$map_dir/$map";
  $logger->info("RESTORE START: instance=$inst map=$map backup=$backupfile target=$dst");

  my %result = ( ok => 1, restored => $backupfile, target => $dst );
  return $c->render(status=>403, json=>{ ok=>0, error=>'restore target symlink not allowed' }) if -l $dst;

  my $lock_err;
  eval {
    with_map_lock($ci, $map, 1, sub {
      my $restore_content = read_text($src);
      if (-f $dst) {
        _assert_not_symlink($dst, 'Restore-Ziel');
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
        ? JSON::MaybeXS->new(utf8=>0)->decode( read_text($instances_cfg_file) )
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
      my $arr = eval { JSON::MaybeXS->new->decode($items_param) } || [];
      @items = @$arr if ref($arr) eq 'ARRAY';
    }
    if (!@items) {
      my $map  = $c->param('map')  // '';
      my $type = $c->param('type') // '';
      push @items, { map => $map, type => $type };
    }
  }

  unless (@items && ref($items[0]) eq 'HASH') {
    return $c->render(status=>400, json=>{ ok=>0, error=>'Payload fehlt oder ungültig' });
  }

  my @changes;
  my %seen;
  for my $it (@items) {
    my $map_raw  = $it->{map}  // '';
    my $type_raw = $it->{type} // '';

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

    my $key = "$map\x1F$type_norm";
    next if $seen{$key}++;
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

# ======== API: globs delete (einzelner Key) ==================================
del '/instances/:inst/globs/:map' => sub {
  my $c    = shift;
  my $inst = $c->stash('inst');
  my $map  = $c->stash('map');
  return $c->render(status=>404, json=>{ok=>0,error=>'Unknown instance'})
    unless exists $config->{instances}{$inst};

  my ($had, $cfg_err);
  eval {
    with_config_lock(sub {
      my $cfg = _read_cfg_hash();
      my $node = _inst_node_rw($cfg, $inst);
      $had = (ref($node->{globs}) eq 'HASH') && exists $node->{globs}{$map};
      delete $node->{globs}{$map} if $had;
      _write_cfg_hash_atomic($cfg);
      _rebuild_cfgmap_from($cfg);
    });
    1;
  } or $cfg_err = $@;
  if ($cfg_err) {
    $logger->error("CONFIG DELETE FAILED: instance=$inst map=$map error=" . _single_line($cfg_err));
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json aktualisieren: $cfg_err"});
  }
  $logger->info("CONFIG DELETE OK: instance=$inst map=$map removed=" . ($had ? 1 : 0));
  $c->render(json => { ok=>1, instance=>$inst, map=>$map, removed=>($had?JSON::MaybeXS::true:JSON::MaybeXS::false) });
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

try {
  $logger->info("SERVICE START OK: version=$VERSION listen=$url require_https=".($require_https?1:0)." instances=".scalar(keys %$instances));
  set_file_ownership_and_mode($logfile, $global->{serviceUser}, $global->{serviceGroup});
} catch {
  $logger->error("Logger-Fehler: $_");
};

app->start('daemon', '-l', $url);
