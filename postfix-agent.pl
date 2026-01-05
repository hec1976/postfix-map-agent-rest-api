# Postfix Map Agent - REST
# Version: 1.5.4 (2026-01-05, Mojo-only, async subprocess)
#
# Fixes ggü. 1.5.1:
# - Instanz-Aufloesung wieder wie frueher: wenn genau 1 Instanz existiert, wird sie automatisch verwendet
# - "default" wird bei Single als Alias akzeptiert, falls keine echte default Instanz existiert
# - reload_config und _rebuild_cfgmap_from halten die Instanz-Map konsistent (kein Single-Break nach Reload/Write)
# - Locks/FS arbeiten immer mit dem effektiv aufgeloesten Instanznamen
# - Lesefehler-Ausgaben robuster: read_raw/read_text melden $@ oder $! (Mojo File Fehler landen oft in $@)

# Verhalten:
# - Logik analog zu 1.3.x: Single ohne "default"-Key funktioniert wieder wie gewohnt, Multi verlangt eine eindeutige Instanz
# - Multi-Instanz Verhalten bleibt unveraendert
# Version: 1.5.1 (2026-01-04, Mojo-only, async subprocess)
#
# Änderungen ggü. 1.3.3:
# - Logging umgestellt auf Mojo::Log (keine Log4perl-Abhaengigkeit mehr)
# - Log-Format kompatibel gehalten: YYYY/MM/DD HH:MM:SS LEVEL Nachricht
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
# - Konsistentes Logging (Mojo::Log) statt warn
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
use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::JSON qw(decode_json encode_json true false);
use Mojo::Util qw(url_escape secure_compare steady_time decode);
use Mojo::Promise;
use Mojo::IOLoop::Subprocess;
use Mojo::IOLoop;
use Try::Tiny;
use Net::CIDR;
use Fcntl qw(:mode O_CREAT O_EXCL O_WRONLY O_RDWR :flock);
use Time::HiRes qw(time sleep);
use Text::ParseWords qw(shellwords);

use constant RELOAD_GRACE_S => 0.35;
use constant LOCK_TIMEOUT_S => 3.0;
our $VERSION = '1.5.3';

# Umask bewusst restriktiv: Group-RW, Other none
umask 0007;

# -------------------- I/O Basis-Helfer --------------------
sub read_raw {
    my ($file) = @_;
    my $data = eval { path($file)->slurp };
    die "Kann $file nicht lesen: " . ($@ || $!) unless defined $data;
    return $data;
}

sub read_text {
    my ($file) = @_;
    my $data = eval { path($file)->slurp('UTF-8') };
    die "Kann $file nicht lesen: " . ($@ || $!) unless defined $data;
    return $data;
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
    my $text = read_text($file);
    my $data = decode_json($text);
    return $data;
}

# -------------------- Config laden --------------------
my $home = app->home;
my $global_cfg_file    = $home->rel_file('global.json');
my $instances_cfg_file = $home->rel_file('configs.json');
die "Missing config $global_cfg_file\n"    unless -f $global_cfg_file;
die "Missing config $instances_cfg_file\n" unless -f $instances_cfg_file;
my $global         = read_json_config($global_cfg_file);
my $instances_raw  = read_json_config($instances_cfg_file);
my $instances      = (ref($instances_raw->{instances}) eq 'HASH')
                     ? $instances_raw->{instances}
                     : $instances_raw;

# Rueckwaerts kompatibel: Single-Format als default behandeln
$instances = wrap_instances_hash_if_needed($instances);

# Harte Defaults für globale Berechtigungen (nur falls nicht gesetzt)
$global->{serviceUser}      //= 'root';
$global->{serviceGroup}     //= 'root';
$global->{fileMode_service} //= '0644';  # Maps
$global->{fileMode_backup}  //= '0660';  # Backups

# Secret für Mojo (Session/Signer)
app->secrets([ $global->{secret} // 'change-this-long-random-secret-please' ]);
app->max_request_size(2 * 1024 * 1024);

# -------------------- Logging vorbereiten --------------------
my $logfile = $global->{logfile} // "/var/log/mmbb/postfix-agent.log";
my $logdir  = path($logfile)->dirname->to_string;
unless (-d $logdir) {
    eval { path($logdir)->make_path };
    die "Kann Log-Verzeichnis $logdir nicht anlegen: $@" if $@;
}
eval {
    open my $lfh, '>>', $logfile or die $!;
    close $lfh;
    1;
} or die "Kann Logfile $logfile nicht oeffnen: $@";

my $logger = Mojo::Log->new(path => $logfile, level => 'info');

sub _ts_log {
    my ($t) = @_;
    $t //= time;
    my @lt = localtime($t);
    return sprintf('%04d/%02d/%02d %02d:%02d:%02d', $lt[5]+1900, $lt[4]+1, $lt[3], $lt[2], $lt[1], $lt[0]);
}

sub _ts_compact {
    my ($t) = @_;
    $t //= time;
    my @lt = localtime($t);
    return sprintf('%04d%02d%02d_%02d%02d%02d', $lt[5]+1900, $lt[4]+1, $lt[3], $lt[2], $lt[1], $lt[0]);
}

$logger->format(sub {
    my ($time, $level, @lines) = @_;
    my $ts  = _ts_log($time);
    my $lvl = uc($level // 'info');
    return join('', map { my $m = $_; chomp $m; "$ts $lvl $m\n" } @lines);
});

sub run_cmd_subprocess_p {
    my ($cmd_str) = @_;
    $cmd_str =~ s/^\s+|\s+$//g;

    # Zerlegt den String in eine Liste, z.B.:
    # "/usr/sbin/postmap /etc/map" -> ("/usr/sbin/postmap", "/etc/map")
    my @cmd = shellwords($cmd_str);

    return Mojo::Promise->reject('empty command') unless @cmd;

    my $p  = Mojo::Promise->new;
    my $sp = Mojo::IOLoop::Subprocess->new;

    $sp->run(
        sub {
            my ($subproc) = @_;

            # STDERR auf STDOUT umleiten, damit wir beides einfangen (entspricht 2>&1)
            open(local *STDERR, ">&", STDOUT) or die "Can't dup STDOUT: $!";

            # Öffne Pipe vom Befehl in Listenform -> KEINE Shell-Interpretation von ; | & etc.
            open(my $fh, "-|", @cmd) or die "Can't execute @cmd: $!";

            my $output = do { local $/; <$fh> };
            close($fh);
            my $rc = $? >> 8;

            return { rc => $rc, output => $output // '' };
        },
        sub {
            my ($subproc, $err, $res) = @_;
            if ($err) { return $p->reject($err); }
            return $p->resolve($res);
        }
    );
    return $p;
}

sub run_promise {
    my ($c, $cb) = @_;
    $c->render_later;

    return Mojo::Promise->resolve
        ->then(sub { $cb->(); })
        ->catch(sub {
            my ($err) = @_;
            $err = "$err";
            $logger->error("Unhandled error: $err");
            $c->render(status => 500, json => { ok => 0, error => 'Internal error' });
        });
}

# Logfile-Owner/Group nachziehen (Modus via umask/UMask)
eval {
    set_file_ownership_and_mode($logfile, $global->{serviceUser}, $global->{serviceGroup});
};

# -------------------- FS-Rechte & Ownership --------------------
sub set_file_ownership_and_mode {
    my ($path, $user, $group, $mode) = @_;
    my $err = '';
    if ($user || $group) {
        my ($uid, $gid);
        $uid = getpwnam($user)  if defined $user && $user ne '';
        $gid = getgrnam($group) if defined $group && $group ne '';
        if (defined($uid) || defined($gid)) {
            chown(defined $uid ? $uid : -1, defined $gid ? $gid : -1, $path)
                or $err .= "chown $user:$group fehlgeschlagen: $!; ";
        } else {
            $err .= "unbekannter user/group ($user:$group); ";
        }
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
    my ($uid, $gid);
    $uid = getpwnam($user)  if defined $user && $user ne '';
    $gid = getgrnam($group) if defined $group && $group ne '';
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

# Backup-Fallback: backupDir/<inst>
sub effective_backup_dir {
    my ($ci, $inst) = @_;
    return $ci->{backup_dir} if $ci && $ci->{backup_dir};
    return path($global->{backupDir}, $inst)->to_string if $global->{backupDir};
    return; # kein Fallback
}

# Globale Dienstverzeichnisse anlegen/absichern
if (my $dconf = $global->{dirs}) {
    my $folders = $dconf->{service_folder};
    $folders = [$folders] unless ref $folders eq 'ARRAY';
    my $owner = $global->{serviceUser};
    my $group = $global->{serviceGroup};
    my $mode  = $global->{dirs}{service_mode};
    foreach my $fldkey (@$folders) {
        my $dir = $global->{$fldkey} // next;
        unless (-d $dir) {
            eval { path($dir)->make_path };
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
    my $mode  = $global->{dirs}{service_mode};
    for my $name (keys %$instances) {
        my $dir = effective_backup_dir($instances->{$name}, $name) // next;
        unless (-d $dir) {
            eval { path($dir)->make_path };
            if ($@) { $logger->error("Backup-Verzeichnis $dir konnte nicht erstellt werden: $@"); next; }
        }
        my $err = set_dir_ownership_and_mode($dir, $owner, $group, $mode);
        $logger->warn($err) if $err;
    }
}

# tmp-dir
my $tmp_dir = $global->{tmpDir} // '/tmp';
unless (-d $tmp_dir) { eval { path($tmp_dir)->make_path }; die "Konnte tmp_dir $tmp_dir nicht anlegen: $@" if $@; }

# Zusammengeführte Config (mutable via reload_config / _rebuild_cfgmap_from)
my $config = { global => $global, instances => $instances };

# -------------------- Atomare Writes --------------------
sub _atomic_write_impl {
    my ($target, $content, $user, $group, $mode, $umask_only) = @_;

    my $dir = path($target)->dirname->to_string;
    die "Verzeichnis nicht beschreibbar: $dir" unless -w $dir;

    my $tmpfile;
    my $max_tries = 128;

    for (1..$max_tries) {
        my $rand = int(rand(1_000_000_000));
        my $candidate = path($dir)->child(".tmp_${$}_$rand")->to_string;

        if (sysopen(my $fh, $candidate, O_CREAT|O_EXCL|O_WRONLY, 0666)) {
            binmode($fh, ':encoding(UTF-8)');
            print $fh $content;
            close $fh or die "close($candidate) failed: $!";
            $tmpfile = $candidate;
            last;
        }
    }

    die "atomic_write: konnte keine Temp-Datei erstellen in $dir" unless $tmpfile;

    # Ownership setzen, Mode nur wenn NICHT umask-only gewuenscht
    if ($umask_only) {
        set_file_ownership_and_mode($tmpfile, $user, $group);
    } else {
        set_file_ownership_and_mode($tmpfile, $user, $group, $mode);
    }

    rename $tmpfile, $target or die "rename($tmpfile -> $target) failed: $!";

    if ($umask_only) {
        set_file_ownership_and_mode($target, $user, $group);
    } else {
        set_file_ownership_and_mode($target, $user, $group, $mode);
    }

    return 1;
}

sub atomic_write {
    my ($path, $content, $user, $group, $mode) = @_;
    return _atomic_write_impl($path, $content, $user, $group, $mode, 0);
}

sub atomic_write_umask {
    my ($path, $content, $user, $group) = @_;
    return _atomic_write_impl($path, $content, $user, $group, undef, 1);
}

sub normalize_inst {
    my ($inst) = @_;
    $inst = '' unless defined $inst;
    $inst =~ s/^\s+|\s+$//g;
    return $inst;
}

# Instanz-Aufloesung analog zur alten Logik:
# - Wenn Instanz angegeben: verwenden (Unknown -> spaeter 404)
# - Wenn Instanz fehlt oder "default" ist und es genau 1 Instanz gibt: diese eine nehmen
# - Wenn Instanz fehlt und mehrere existieren: Fehler (Instance required)
sub resolve_inst_name {
    my ($inst_in) = @_;
    my $inst = normalize_inst($inst_in);

    my @names = sort keys %{ $config->{instances} // {} };

    # kein inst angegeben
    if ($inst eq '') {
        return $names[0] if @names == 1;
        return '';
    }

    # "default" als bequemer Alias, aber nur wenn genau eine Instanz existiert
    if ($inst eq 'default' && !exists $config->{instances}{default} && @names == 1) {
        return $names[0];
    }

    return $inst;
}

sub get_instance_or_render {
    my ($c, $inst_in) = @_;
    my $inst = resolve_inst_name($inst_in);

    if (!defined $inst || $inst eq '') {
        $c->render(status => 400, json => { ok => 0, error => 'Instance required' });
        return;
    }

    my $ci = $config->{instances}{$inst};
    unless ($ci) {
        $c->render(status => 404, json => { ok => 0, error => 'Unknown instance' });
        return;
    }

    return ($inst, $ci);
}

# Status-Parser (systemctl, postmulti, postfix-script)
# Ziel: "running" sicher erkennen, auch wenn Prefix davor steht
sub parse_service_status {
    my ($out, $rc) = @_;
    my $txt = lc(($out // ''));
    $txt =~ s/\r//g;

    return 'stopped' if $txt =~ /\bnot\s+running\b/;
    return 'stopped' if $txt =~ /\bstopp?ed\b/;
    return 'running' if $txt =~ /\brunning\b/;
    return 'running' if $txt =~ /\bactive\b/;

    # Fallback: rc==0 aber Text nicht eindeutig
    return ($rc == 0) ? 'unknown-ok' : 'unknown-fail';
}


sub _looks_like_instance_node {
  my ($h) = @_;
  return 0 unless $h && ref($h) eq 'HASH';
  for my $k (qw(map_dir config_dir globs postmap_by_type reload_cmd status_cmd backup_dir lock_dir)) {
    return 1 if exists $h->{$k};
  }
  return 0;
}

sub wrap_instances_hash_if_needed {
  my ($insts) = @_;
  return $insts unless $insts && ref($insts) eq 'HASH';

  # Wenn es bereits wie instances->{default} aussieht, nichts tun
  return $insts if exists $insts->{default};

  # Wenn es wie eine Single-Instanz aussieht, als default wrappen
  return { default => $insts } if _looks_like_instance_node($insts);

  return $insts;
}

# -------------------- Netz & Auth --------------------
my $listen_addr   = $config->{global}{listen}        // '0.0.0.0:5000';
my $ssl_enable    = $config->{global}{ssl_enable}    // 0;
my $ssl_cert      = $config->{global}{ssl_cert_file} // '';
my $ssl_key       = $config->{global}{ssl_key_file}  // '';
my $require_https = $config->{global}{require_https} // 0;

# API-Token ist Pflicht (hart)
my $api_token = $ENV{API_TOKEN} // ($global->{api_token} // '');
die "FATAL: API_TOKEN nicht gesetzt (ENV API_TOKEN oder global.json api_token)\n"
    unless defined $api_token && length $api_token;

hook before_dispatch => sub {
    my $c = shift;
    my $ips_rt = $config->{global}{allowed_ips};
    my @acl_rt = @{ (ref($ips_rt) eq 'ARRAY' ? $ips_rt : ['127.0.0.1']) };
    my $origin = $c->req->headers->origin // '*';
    $c->res->headers->header('Access-Control-Allow-Origin'  => $origin);
    $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS');
    $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, X-API-Token, Authorization');
    $c->res->headers->header('Access-Control-Max-Age'       => '86400');
    $c->res->headers->header('Vary'                         => 'Origin');
    if ($c->req->method eq 'OPTIONS') {
        return $c->render(text => '', status => 204);
    }
    if ($require_https) {
        my $is_https = ($c->req->url->to_abs->scheme // '') eq 'https' || ($c->req->is_secure // 0);
        unless ($is_https) {
            return $c->render(status => 403, json => { ok => 0, error => 'HTTPS required' });
        }
    }
    unless (Net::CIDR::cidrlookup($c->tx->remote_address, @acl_rt)) {
        return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
    }
    my $hdr_token = $c->req->headers->header('X-API-Token') // '';
    my $bearer    = ($c->req->headers->authorization // '') =~ /^Bearer\s+(.+)/i ? $1 : '';
    my $token     = $hdr_token || $bearer;
    unless (secure_compare($token, $api_token)) {
        return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' });
    }
};

# -------------------- JSON Helpers (Mojo::JSON, canonical + pretty) --------------------
sub _json_canonicalize {
    my ($v) = @_;
    return $v unless ref $v;

    if (ref $v eq 'HASH') {
        my %out;
        for my $k (sort keys %$v) {
            $out{$k} = _json_canonicalize($v->{$k});
        }
        return \%out;
    }
    if (ref $v eq 'ARRAY') {
        return [ map { _json_canonicalize($_) } @$v ];
    }
    return $v;
}

sub _json_pretty {
    my ($json) = @_;
    # Simple JSON pretty printer (string-safe), no external deps.
    my $out = '';
    my $indent = 0;
    my $in_str = 0;
    my $esc = 0;

    my $nl = "\n";
    my $sp = '  ';

    for (my $i = 0; $i < length($json); $i++) {
        my $ch = substr($json, $i, 1);

        if ($in_str) {
            $out .= $ch;
            if ($esc) { $esc = 0; next; }
            if ($ch eq "\\") { $esc = 1; next; }
            if ($ch eq '"') { $in_str = 0; next; }
            next;
        }

        if ($ch eq '"') { $in_str = 1; $out .= $ch; next; }

        if ($ch =~ /\s/) { next; }

        if ($ch eq '{' || $ch eq '[') {
            $out .= $ch . $nl;
            $indent++;
            $out .= ($sp x $indent);
            next;
        }
        if ($ch eq '}' || $ch eq ']') {
            $out .= $nl;
            $indent-- if $indent > 0;
            $out .= ($sp x $indent) . $ch;
            next;
        }
        if ($ch eq ',') {
            $out .= $ch . $nl . ($sp x $indent);
            next;
        }
        if ($ch eq ':') {
            $out .= $ch . ' ';
            next;
        }

        $out .= $ch;
    }

    $out .= $nl unless $out =~ /\n\z/;
    return $out;
}

sub json_encode_pretty_canonical {
    my ($data) = @_;
    my $canon = _json_canonicalize($data);
    my $min   = encode_json($canon);
    return _json_pretty($min);
}

# -------------------- Config-Helfer (reload & raw read/write) ----------------
sub reload_config {
    my $raw_global    = decode_json( read_text($global_cfg_file) );
    my $raw_instances = decode_json( read_text($instances_cfg_file) );
    $raw_global->{serviceUser}      //= 'root';
    $raw_global->{serviceGroup}     //= 'root';
    $raw_global->{fileMode_service} //= '0644';
    $raw_global->{fileMode_backup}  //= '0660';
    my $inst_hash =
        (ref($raw_instances->{instances}) eq 'HASH') ? $raw_instances->{instances}
                                                     : $raw_instances;
    $global    = $raw_global;
    $instances = wrap_instances_hash_if_needed($inst_hash);
    $config    = { global => $global, instances => $instances };
}

sub _read_cfg_hash {
    my $cfg = decode_json( read_text($instances_cfg_file) );
    return $cfg;
}

sub _inst_node_rw {
    my ($cfg, $inst) = @_;
    my $node = (ref($cfg->{instances}) eq 'HASH') ? ($cfg->{instances}{$inst} //= {}) : ($cfg->{$inst} //= {});
    return $node;
}

sub _write_cfg_hash_atomic {
    my ($cfg) = @_;
    my $json = json_encode_pretty_canonical($cfg);
    atomic_write_umask($instances_cfg_file, $json, $global->{serviceUser}, $global->{serviceGroup});
}

sub _rebuild_cfgmap_from {
    my ($cfg) = @_;
    my $insts = (ref($cfg->{instances}) eq 'HASH') ? $cfg->{instances} : $cfg;
  $insts = wrap_instances_hash_if_needed($insts);
    $instances = $insts;
    $config->{instances} = $insts;
}

# -------------------- Map-Typen & Sanitizer --------------------
my %GLOB_TYPES = map { $_ => 1 } qw(regexp pcre cidr lmdb hash btree db);

sub sanitize_map_name {
    my ($raw) = @_;
    my $name = path($raw // '')->basename;
    return (undef, 'Empty name') unless defined $name && length $name;

    # Nur simple Dateinamen erlauben
    return (undef, 'Invalid characters') unless $name =~ /\A[0-9A-Za-z._-]{1,255}\z/;
    return (undef, 'Path traversal detected') if $name =~ /\A\.+\z/;     # ".", ".."
    return (undef, 'Path traversal detected') if $name =~ m{[\\/]} || $name =~ /\.\./;

    return ($name, undef);
}

# Verbotene Dateinamen (NICHT als Maps editier-/abrufbar)
my %FORBIDDEN = map { $_ => 1 } qw(main.cf master.cf);

sub _deny_forbidden_map {
    my ($name) = @_;
    return $FORBIDDEN{ lc $name };
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
        (my $re = $glob) =~ s/\./\\./g; $re =~ s/\*/.*/g;
        return $type if $file =~ /^$re$/;
    }
    return;
}

# -------------------- Kommandoplätze --------------------
sub expand_cmd {
    my ($ci, $inst, $cmd) = @_;
    return '' unless defined $cmd && length $cmd;
    my $bdir = effective_backup_dir($ci, $inst) // ($ci->{backup_dir} // '');
    $cmd =~ s/\{inst\}/$inst/g;
    $cmd =~ s/\{config_dir\}/$ci->{config_dir}/g;
    $cmd =~ s/\{map_dir\}/$ci->{map_dir}/g;
    $cmd =~ s/\{backup_dir\}/$bdir/g;
    return $cmd;
}

sub postmap_cmd {
    my ($ci, $file, $inst) = @_;
    my $type = map_type_for_file($ci, $file) or return;
    my $template = $ci->{postmap_by_type}{$type} or return;
    my $path = "$ci->{map_dir}/$file"; $path =~ s{//+}{/}g;
    my $cmd = $template;
    $cmd =~ s/\{config_dir\}/$ci->{config_dir}/g;
    $cmd =~ s/\{path\}/$path/g;
    $cmd =~ s/\{inst\}/$inst/g;
    return $cmd;
}

# -------------------- Backups --------------------
sub backup_file {
    my ($file, $dir, $max, $ci) = @_;
    $logger->info("backup_file: file=$file dir=$dir max=$max");
    unless (-f $file) { $logger->error("Kein Backup, da Datei $file nicht existiert."); return; }
    unless (-d $dir) {
        $logger->warn("Backup-Verzeichnis $dir nicht vorhanden - wird angelegt.");
        eval { path($dir)->make_path };
        if ($@) { $logger->error("Backup-Verzeichnis $dir konnte nicht erstellt werden: $@"); return; }
        my $err = set_dir_ownership_and_mode($dir, $global->{serviceUser}, $global->{serviceGroup}, $global->{dirs}{service_mode});
        $logger->warn("set_dir_ownership_and_mode($dir): $err") if $err;
    }
    my $ts  = _ts_compact();
    my $dst = "$dir/" . path($file)->basename . ".bak.$ts";
    $logger->info("Erstelle Backup von $file nach $dst");
    try {
        my $data = path($file)->slurp;
        path($dst)->spurt($data);
        my $bk_mode = effective_backup_mode();
        my $err = set_file_ownership_and_mode($dst, $global->{serviceUser}, $global->{serviceGroup}, $bk_mode);
        $logger->info("Set owner/mode for $dst: user=$global->{serviceUser} group=$global->{serviceGroup} mode=$bk_mode");
        $logger->error("Fehler bei set_file_ownership_and_mode ($dst): $err") if $err;
    } catch {
        $logger->error("Backup fehlgeschlagen: $_");
        return;
    };
    my @bak = glob "$dir/" . path($file)->basename . ".bak.*";
    @bak = sort { (stat($a))[9] <=> (stat($b))[9] } @bak; # mtime
    if ($max && @bak > $max) {
        my $to_delete = @bak - $max;
        for my $del (@bak[0 .. $to_delete-1]) {
            unlink $del or $logger->warn("Konnte altes Backup nicht löschen: $del ($!)");
        }
    }
}

# -------------------- Locks (per Map & Instanz) --------------------
sub _lock_dir_for {
    my ($ci, $inst) = @_;
    $inst = normalize_inst($inst);

    return $ci->{lock_dir} if $ci && $ci->{lock_dir};
    return $config->{global}{lockDir} if $config->{global}{lockDir};
    my $base = $config->{global}{tmpDir} // '/tmp';
    return File::Spec->catdir($base, 'postfix-agent-locks', $inst);
}

sub _map_lock_path {
    my ($ci, $inst, $map) = @_;
    my $ldir = _lock_dir_for($ci, $inst);
    return path($ldir, "$map.lock")->to_string;
}

sub with_map_lock {
    my ($ci, $map, $exclusive, $code, $inst) = @_;
    $inst = normalize_inst($inst);
    my $ldir = _lock_dir_for($ci, $inst);
    unless (-d $ldir) {
        path($ldir)->make_path;
        my $mode = $config->{global}{dirs}{service_mode};
        my $err = set_dir_ownership_and_mode($ldir, $config->{global}{serviceUser}, $config->{global}{serviceGroup}, $mode);
        $logger->warn("Lockdir perms: $err") if $err;
    }
    my $lpath = _map_lock_path($ci, $inst, $map);
    sysopen(my $lfh, $lpath, O_RDWR|O_CREAT, 0660)
        or die "Lockfile open failed $lpath: $!";
    my $e = set_file_ownership_and_mode($lpath, $config->{global}{serviceUser}, $config->{global}{serviceGroup});
    $logger->warn("Lockfile chown/chmod: $e") if $e;
    my $want = $exclusive ? LOCK_EX : LOCK_SH;
    my $t0 = time;
    while (1) {
        if (flock($lfh, $want | LOCK_NB)) {
            my $ret; my $err;
            eval { $ret = $code->(); 1 } or $err = $@;

            # Wenn Callback eine Promise liefert, halten wir den Lock bis zum Ende.
            if (!$err && $ret && ref($ret) && eval { $ret->isa('Mojo::Promise') }) {
                my $p = Mojo::Promise->new;
                $ret->then(sub {
                    my (@v) = @_;
                    flock($lfh, LOCK_UN); close $lfh;
                    $p->resolve(@v);
                })->catch(sub {
                    my ($e) = @_;
                    flock($lfh, LOCK_UN); close $lfh;
                    $p->reject($e);
                });
                return $p;
            }

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

# -------------------- Routen --------------------
get '/' => sub {
    my $c = shift;
    return run_promise($c, sub {
        $c->render(json => { info => 'Postfix Agent', version => $VERSION });
    });
};

get '/instances' => sub {
    my $c = shift;
    return run_promise($c, sub {
        $c->render(json => { instances => [sort keys %{ $config->{instances} }]} );
    });
};

get '/instances/:inst/maps' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my %seen;
        my $globs = $ci->{globs} // {};
        my $want_all = ($c->param('all') // '') eq '1';
        if ($want_all || !%$globs) {
            if (opendir(my $dh, $ci->{map_dir})) {
                while (my $e = readdir($dh)) {
                    next if $e =~ /^\./;
                    next if _deny_forbidden_map($e);
                    my $p = "$ci->{map_dir}/$e";
                    $seen{$e} = 1 if -f $p;
                }
                closedir $dh;
            }
        } else {
            for my $glob (keys %$globs) {
                for my $f (glob "$ci->{map_dir}/$glob") {
                    my $bn = path($f)->basename;
                    next if _deny_forbidden_map($bn);
                    $seen{$bn} = 1 if -f $f;
                }
            }
        }
        $c->render(json => { ok => 1, maps => [sort keys %seen] });
    });
};

# Map anzeigen (Text, UTF-8)
get '/instances/:inst/map/*map' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my ($map, $err) = sanitize_map_name($c->stash('map'));
        return $c->render(status=>400, json=>{ ok=>0, error=>$err }) if $err;
        return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
            if _deny_forbidden_map($map);
        my $path = "$ci->{map_dir}/$map";
        unless (-r $path) { return $c->render(status => 404, json => { ok => 0, error => 'Not found' }); }
        my $text = read_text($path);
        $c->res->headers->content_type('text/plain; charset=UTF-8');
        $c->render(data => $text);
    });
};

# Backups auflisten
get '/instances/:inst/backup/*map' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my ($base, $err) = sanitize_map_name($c->stash('map'));
        return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
        return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
            if _deny_forbidden_map($base);
        my $backup_dir = effective_backup_dir($ci, $inst)
            or return $c->render(status => 404, json => { ok => 0, error => 'No backup_dir' });
        my @files = glob("$backup_dir/$base.bak.*");
        @files = sort { (stat($b))[9] <=> (stat($a))[9] } @files; # mtime DESC
        @files = map { s{^$backup_dir/}{}r } @files;
        $c->render(json => { ok => 1, backups => \@files });
    });
};

# Backup-Vorschau/-Download
get '/instances/:inst/backupfile/*backup' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my ($backup_file, $err) = sanitize_map_name($c->stash('backup') // '');
        return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
        my $backup_dir  = effective_backup_dir($ci, $inst);
        unless ($backup_dir && -d $backup_dir) { return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }); }
        my $fullpath = "$backup_dir/$backup_file";
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
    });
};

# Map speichern / anlegen (UTF-8)
post '/instances/:inst/map/*map' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
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
        my $path = "$ci->{map_dir}/$map";
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
                $new_content = encode_json(_json_canonicalize($json));
            }
        }
        $new_content //= $c->param('content');
        $new_content //= decode('UTF-8', $c->req->body // '');
        $new_content =~ s/\r\n/\n/g if defined $new_content;
        # ---- map_dir sicherstellen ----
        my $dir = path($path)->dirname->to_string;
        unless (-d $dir) {
            eval { path($dir)->make_path };
            if ($@) {
                return $c->render(status => 500, json => { ok => 0, error => 'map_dir create failed', details => { dir => $dir, msg => "$@", inst => $inst } });
            }
            my $err = set_dir_ownership_and_mode($dir, $global->{serviceUser}, $global->{serviceGroup}, $global->{dirs}{service_mode});
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
            my $lock_ret;
            my $ok_lock = eval {
                $lock_ret = with_map_lock($ci, $map, 1, sub {
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

                    my $p = Mojo::Promise->resolve;

                    if (my $pm_cmd = postmap_cmd($ci, $map, $inst)) {
                        $p = $p->then(sub {
                            return run_cmd_subprocess_p($pm_cmd)->then(sub {
                                my ($r) = @_;
                                my $pm_rc  = $r->{rc} // 255;
                                my $pm_out = $r->{output} // '';
                                $result{postmap} = {
                                    executed => 1, command => $pm_cmd,
                                    rc => $pm_rc, output => $pm_out,
                                    result => ($pm_rc == 0) ? 'ok' : 'fail',
                                };
                                die "postmap rc=$pm_rc: $pm_out" if $pm_rc != 0;
                                return 1;
                            });
                        });
                    }

                    if ($ci->{reload_on_change}) {
                        my $reload_cmd = expand_cmd($ci, $inst, $ci->{reload_cmd} // '');
                        if ($reload_cmd) {
                            $p = $p->then(sub {
                                return run_cmd_subprocess_p($reload_cmd)->then(sub {
                                    my ($r) = @_;
                                    my $reload_rc  = $r->{rc} // 255;
                                    my $reload_out = $r->{output} // '';
                                    $result{reload} = {
                                        executed => 1, command => $reload_cmd,
                                        rc => $reload_rc, output => $reload_out,
                                        result => ($reload_rc == 0) ? 'ok' : 'fail',
                                    };
                                    die "reload rc=$reload_rc: $reload_out" if $reload_rc != 0;
                                    return 1;
                                });
                            });
                        } else {
                            $result{reload} = { executed => 0 };
                        }

                        $p = $p->then(sub {
                            my $t = Mojo::Promise->new;
                            Mojo::IOLoop->timer(RELOAD_GRACE_S => sub { $t->resolve(1) });
                            return $t;
                        });

                        my $status_cmd = expand_cmd($ci, $inst, $ci->{status_cmd} // '');
                        if ($status_cmd) {
                            $p = $p->then(sub {
                                return run_cmd_subprocess_p($status_cmd)->then(sub {
                                    my ($r) = @_;
                                    my $status_rc  = $r->{rc} // 255;
                                    my $status_out = $r->{output} // '';
                                    $result{status} = {
                                        executed => 1, command => $status_cmd,
                                        rc => $status_rc, output => $status_out,
                                    };
                                    my $st = parse_service_status($status_out, $status_rc);
                                    $result{status}{result} = $st;

                                    return 1 if $st eq 'running';

                                    # Toleranz wie frueher: rc==0 aber Output nicht eindeutig -> nicht hart failen
                                    return 1 if $st eq 'unknown-ok';

                                    die "Status not running (rc=$status_rc): $status_out";
                                });
                            });
                        } else {
                            $result{status} = { executed => 0 };
                        }
                    }

                    return $p;
                }, $inst);
                1;
            };

            if (!$ok_lock) {
                my $lock_err = $@;
                if ($lock_err =~ /Lock-Timeout/) {
                    return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
                }
                $result{ok} = 0; $result{error} = "$lock_err";
                return $c->render(json => \%result, status => 500);
            }

            if ($lock_ret && ref($lock_ret) && eval { $lock_ret->isa('Mojo::Promise') }) {
                return $lock_ret->then(sub {
                    return $c->render(json => \%result);
                })->catch(sub {
                    my ($e) = @_;
                    $e = "$e";
                    if ($e =~ /Lock-Timeout/) {
                        return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
                    }
                    $result{ok} = 0; $result{error} = $e;
                    return $c->render(json => \%result, status => 500);
                });
            }

            return $c->render(json => \%result);
        }
        $result{write}  = 'skipped';
        $result{backup} = 'skipped';
        return $c->render(json => \%result);
    });
};

# --------- RESTORE ---------
post '/instances/:inst/restore/*backupfile' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my ($backupfile, $err) = sanitize_map_name($c->stash('backupfile') // '');
        return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
        my $backup_dir = effective_backup_dir($ci, $inst);
        my $map_dir    = $ci->{map_dir};
        return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }) unless $backup_dir && -d $backup_dir;
        return $c->render(status => 500, json => { ok => 0, error => 'No map dir' })    unless $map_dir    && -d $map_dir;
        my $src = "$backup_dir/$backupfile";
        return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }) unless -f $src;
        (my $map = $backupfile) =~ s/\.bak.*$//;
        return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' })
            if _deny_forbidden_map($map);
        my $dst = "$map_dir/$map";
        my %result = ( ok => 1, restored => $backupfile, target => $dst );
        my $lock_err;
        my $lock_ret;
        my $ok_lock = eval {
            $lock_ret = with_map_lock($ci, $map, 1, sub {
                my $data = path($src)->slurp;
                atomic_write(
                    $dst,
                    $data,
                    $global->{serviceUser},
                    $global->{serviceGroup},
                    $global->{fileMode_service}
                );

                my $p = Mojo::Promise->resolve;
                if (my $pm_cmd = postmap_cmd($ci, $map, $inst)) {
                    $p = $p->then(sub {
                        return run_cmd_subprocess_p($pm_cmd)->then(sub {
                            my ($r) = @_;
                            my $pm_rc  = $r->{rc} // 255;
                            my $pm_out = $r->{output} // '';
                            $result{postmap} = {
                                executed => 1, command => $pm_cmd,
                                rc => $pm_rc, output => $pm_out,
                                result => ($pm_rc == 0) ? 'ok' : 'fail',
                            };
                            die "postmap rc=$pm_rc: $pm_out" if $pm_rc != 0;
                            return 1;
                        });
                    });
                } else {
                    $result{postmap} = { executed => 0 };
                }

                if ($ci->{reload_on_change}) {
                    my $reload_cmd = expand_cmd($ci, $inst, $ci->{reload_cmd} // '');
                    if ($reload_cmd) {
                        $p = $p->then(sub {
                            return run_cmd_subprocess_p($reload_cmd)->then(sub {
                                my ($r) = @_;
                                my $reload_rc  = $r->{rc} // 255;
                                my $reload_out = $r->{output} // '';
                                $result{reload} = {
                                    executed => 1, command => $reload_cmd,
                                    rc => $reload_rc, output => $reload_out,
                                    result => ($reload_rc == 0) ? 'ok' : 'fail',
                                };
                                die "reload rc=$reload_rc: $reload_out" if $reload_rc != 0;
                                return 1;
                            });
                        });
                    } else {
                        $result{reload} = { executed => 0 };
                    }

                    $p = $p->then(sub {
                        my $t = Mojo::Promise->new;
                        Mojo::IOLoop->timer(RELOAD_GRACE_S => sub { $t->resolve(1) });
                        return $t;
                    });

                    my $status_cmd = expand_cmd($ci, $inst, $ci->{status_cmd} // '');
                    if ($status_cmd) {
                        $p = $p->then(sub {
                            return run_cmd_subprocess_p($status_cmd)->then(sub {
                                my ($r) = @_;
                                my $status_rc  = $r->{rc} // 255;
                                my $status_out = $r->{output} // '';
                                $result{status} = {
                                    executed => 1, command => $status_cmd,
                                    rc => $status_rc, output => $status_out,
                                };
                                my $st = parse_service_status($status_out, $status_rc);
                                    $result{status}{result} = $st;

                                    return 1 if $st eq 'running';

                                    # Toleranz wie frueher: rc==0 aber Output nicht eindeutig -> nicht hart failen
                                    return 1 if $st eq 'unknown-ok';

                                    die "Status not running (rc=$status_rc): $status_out";
                            });
                        });
                    } else {
                        $result{status} = { executed => 0 };
                    }
                }

                return $p;
            }, $inst);
            1;
        };

        if (!$ok_lock) {
            my $lock_err = $@;
            if ($lock_err =~ /Lock-Timeout/) {
                return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
            }
            $result{ok} = 0; $result{error} = "$lock_err";
            return $c->render(json => \%result, status => 500);
        }

        if ($lock_ret && ref($lock_ret) && eval { $lock_ret->isa('Mojo::Promise') }) {
            return $lock_ret->then(sub {
                return $c->render(json => \%result);
            })->catch(sub {
                my ($e) = @_;
                $e = "$e";
                if ($e =~ /Lock-Timeout/) {
                    return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' });
                }
                $result{ok} = 0; $result{error} = $e;
                return $c->render(json => \%result, status => 500);
            });
        }

        return $c->render(json => \%result);
    });
};

# Map deregistrieren (nur configs.json) + Hinweise
post '/instances/:inst/delmap/*map' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
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
        my $node;
        try {
            # 1. Konfigurationsdatei einlesen
            $instances_data = -e $instances_cfg_file
                ? decode_json( read_text($instances_cfg_file) )
                : {};
            $logger->debug("Konfiguration geladen: $instances_cfg_file");

            # 2. Struktur prüfen (Wrapper oder flach)
            $has_wrapper = ref($instances_data->{instances}) eq 'HASH' ? 1 : 0;

            # Node der Instanz ermitteln (Multi-Wrapper, Multi-flach, oder Single-flach als default)
            if ($has_wrapper) {
                $node = $instances_data->{instances}{$inst};
            } else {
                if (ref($instances_data->{$inst}) eq 'HASH') {
                    $node = $instances_data->{$inst};
                } elsif ($inst eq 'default' && _looks_like_instance_node($instances_data)) {
                    $node = $instances_data;
                }
            }
            unless ($node && ref($node) eq 'HASH') {
                die "Unknown instance '$inst'";
            }

            # 3. Map aus globs entfernen (falls vorhanden)
            if (ref($node->{globs}) eq 'HASH' && exists $node->{globs}{$map}) {
                $logger->info("Entferne Map '$map' aus globs der Instanz '$inst'");
                delete $node->{globs}{$map};
                _write_cfg_hash_atomic($instances_data);
                $removed_from_globs = 1;
                _rebuild_cfgmap_from($instances_data);
                $logger->info("Map '$map' erfolgreich aus globs entfernt und Konfiguration neu geladen");
            } else {
                $logger->debug("Map '$map' nicht in globs der Instanz '$inst' gefunden (keine Änderung nötig)");
            }
        } catch {
            my $error = $_;
            $cfg_write_err = "Fehler beim Aktualisieren der Konfiguration für Instanz '$inst' (Map: '$map'): $error";
            $logger->error($cfg_write_err);
        };
        if ($cfg_write_err) {
            return $c->render(status => 500, json => { ok => 0, error => "Konfiguration konnte nicht aktualisiert werden: $cfg_write_err" });
        }
        my @matched_patterns;
        eval {
            my $globs_h = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};
            unless ($removed_from_globs) {
                for my $glob (keys %$globs_h) {
                    next if $glob eq $map;
                    my $re = $glob; $re =~ s/\./\\./g; $re =~ s/\*/.*/g;
                    push @matched_patterns, $glob if $map =~ /^$re$/;
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
    });
};

# ======== API: globs lesen ====================================================
get '/instances/:inst/globs' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my $inst = resolve_inst_name($c->stash('inst'));
        return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
        my $cfg  = eval { _read_cfg_hash() };
        return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;
        my $node = _inst_node_rw($cfg, $inst);
        my $gl   = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};
        $c->render(json => { ok=>1, instance=>$inst, globs=>$gl });
    });
};

# ======== API: globs upsert ===================================================
post '/instances/:inst/globs' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my $inst = resolve_inst_name($c->stash('inst'));
        return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
        my $j = eval { $c->req->json }; $j = {} if $@ || !defined $j;
        my @items;
        if (ref($j) eq 'HASH' && %$j) {
            @items = ref($j->{items}) eq 'ARRAY' ? @{$j->{items}} : ($j);
        } else {
            if (defined(my $items_param = $c->param('items'))) {
                my $arr = eval { decode_json($items_param) } || [];
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
        my $cfg  = eval { _read_cfg_hash() };
        return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;
        my $node = _inst_node_rw($cfg, $inst);
        $node->{globs} //= {};
        my @applied;
        for my $ch (@changes) {
            my ($map,$type) = @$ch;
            my $prev = $node->{globs}{$map};
            $node->{globs}{$map} = $type;
            push @applied, { map => $map, type => $type, action => (defined $prev ? 'updated' : 'created'), previous_type => $prev };
        }
        eval { _write_cfg_hash_atomic($cfg); 1 } or
            return $c->render(status=>500, json=>{ok=>0,error=>"configs.json schreiben: $@"});
        eval { _rebuild_cfgmap_from($cfg); 1 };
        return $c->render(json => { ok=>1, instance=>$inst, upserted=>\@applied });
    });
};

# ======== API: globs delete (einzelner Key) ==================================
del '/instances/:inst/globs/:map' => sub {
    my $c    = shift;
    my $inst = resolve_inst_name($c->stash('inst'));
    return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
    my $map  = $c->stash('map');
    my $cfg  = eval { _read_cfg_hash() };
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;
    my $node = _inst_node_rw($cfg, $inst);
    my $had  = (ref($node->{globs}) eq 'HASH') && exists $node->{globs}{$map};
    delete $node->{globs}{$map} if $had;
    eval { _write_cfg_hash_atomic($cfg); 1 } or
        return $c->render(status=>500, json=>{ok=>0,error=>"configs.json schreiben: $@"});
    _rebuild_cfgmap_from($cfg);
    $c->render(json => { ok=>1, instance=>$inst, map=>$map, removed=>($had?true:false) });
};

# Health
get '/health' => sub {
    my $c = shift;
    return run_promise($c, sub {
        my @required_dirs = ($tmp_dir);
        for my $name (keys %{ $config->{instances} }) {
            my $ci = $config->{instances}{$name};
            my $bdir = effective_backup_dir($ci, $name);
            push @required_dirs, $bdir if $bdir;
        }
        my @miss = grep { $_ && !-d $_ } @required_dirs;
        if (@miss) { $c->render(status => 500, json => { ok => 0, error => "Missing dirs: @miss" }); }
        else       { $c->render(json => { ok => 1, status => "ok" }); }
    });
};

any '/*' => sub {
    my $c = shift;
    return run_promise($c, sub {
        $c->render(status => 404, json => { ok => 0, error => 'Not found' });
    });
};

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
    $logger->info("Listening at $url (require_https=".($require_https?1:0).")");
    set_file_ownership_and_mode($logfile, $global->{serviceUser}, $global->{serviceGroup});
} catch {
    $logger->error("Logger-Fehler: $_");
};
app->start('daemon', '-l', $url);
