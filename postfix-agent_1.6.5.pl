#!/usr/bin/env perl
use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::JSON qw(decode_json to_json true false);
use Mojo::Util qw(url_escape secure_compare decode);
use Mojo::Promise;
use Mojo::IOLoop;
use Mojo::IOLoop::Subprocess;
use Try::Tiny;
use Net::CIDR;
use Fcntl qw(O_CREAT O_EXCL O_WRONLY O_RDWR :flock);
use Time::HiRes qw(time sleep);
use Text::ParseWords qw(shellwords);
use File::Spec;

use constant RELOAD_GRACE_S => 0.35;
use constant LOCK_TIMEOUT_S => 3.0;

our $VERSION = '1.6.5';

umask 0007;

# -------------------- Helpers --------------------
sub _num_seconds {
    my ($v, $default) = @_;
    $default //= 0.35;
    return ($v + 0) if defined $v && $v =~ /\A\d+(?:\.\d+)?\z/;
    return ($default + 0);
}

sub _normalize_mode {
    my ($m) = @_;
    return unless defined $m;
    return oct($m) if "$m" =~ /^[0-7]{3,4}$/;
    return $m if "$m" =~ /^\d+$/;
    return;
}

sub _trim { my $s = $_[0] // ''; $s =~ s/^\s+|\s+$//g; $s }

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

sub read_json_config { decode_json(read_text($_[0])) }
sub json_pretty      { to_json($_[0], { pretty => 1, canonical => 1 }) }

sub set_file_ownership_and_mode {
    my ($p, $user, $group, $mode) = @_;
    my $err = '';

    if ($user || $group) {
        my ($uid, $gid);
        $uid = getpwnam($user)  if defined $user && $user ne '';
        $gid = getgrnam($group) if defined $group && $group ne '';
        if (defined($uid) || defined($gid)) {
            chown(defined $uid ? $uid : -1, defined $gid ? $gid : -1, $p)
              or $err .= "chown $user:$group fehlgeschlagen: $!; ";
        } else {
            $err .= "unbekannter user/group ($user:$group); ";
        }
    }

    if (defined(my $oct = _normalize_mode($mode))) {
        chmod $oct, $p or $err .= "chmod " . sprintf('%04o',$oct) . " fehlgeschlagen: $!; ";
    }

    return $err;
}

sub ensure_dir {
    my (%a) = @_;
    my $dir  = $a{dir}  // '';
    my $user = $a{user};
    my $grp  = $a{group};
    my $mode = $a{mode};
    die "ensure_dir: empty dir" unless $dir;

    unless (-d $dir) {
        eval { path($dir)->make_path };
        die "Kann Verzeichnis $dir nicht anlegen: $@" if $@;
    }

    my $err = '';
    my ($uid, $gid);
    $uid = getpwnam($user) if defined $user && $user ne '';
    $gid = getgrnam($grp)  if defined $grp  && $grp  ne '';

    if (defined($uid) || defined($gid)) {
        chown(defined $uid ? $uid : -1, defined $gid ? $gid : -1, $dir)
          or $err .= "chown $user:$grp auf $dir fehlgeschlagen: $!; ";
    }

    if (defined(my $oct = _normalize_mode($mode))) {
        my $cur = (stat($dir))[2] & 07777;
        if ($cur != $oct) {
            chmod($oct, $dir) or $err .= "chmod " . sprintf('%04o',$oct) . " auf $dir fehlgeschlagen: $!; ";
        }
    }

    return $err;
}

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

# -------------------- Config --------------------
my $home = app->home;
my $global_cfg_file    = $home->rel_file('global.json');
my $instances_cfg_file = $home->rel_file('configs.json');

die "Missing config $global_cfg_file\n"    unless -f $global_cfg_file;
die "Missing config $instances_cfg_file\n" unless -f $instances_cfg_file;

my $global        = read_json_config($global_cfg_file);
my $instances_raw = read_json_config($instances_cfg_file);

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
    return $insts if exists $insts->{default};
    return { default => $insts } if _looks_like_instance_node($insts);
    return $insts;
}

my $instances = (ref($instances_raw->{instances}) eq 'HASH') ? $instances_raw->{instances} : $instances_raw;
$instances = wrap_instances_hash_if_needed($instances);

$global->{serviceUser}      //= 'root';
$global->{serviceGroup}     //= 'root';
$global->{fileMode_service} //= '0644';
$global->{fileMode_backup}  //= '0660';

app->secrets([ $global->{secret} // 'change-this-long-random-secret-please' ]);
app->max_request_size(2 * 1024 * 1024);

my $config = { global => $global, instances => $instances };

sub effective_service_user  { $global->{serviceUser} }
sub effective_service_group { $global->{serviceGroup} }
sub effective_file_mode     { $global->{fileMode_service} }
sub effective_backup_mode   { $global->{fileMode_backup} // $global->{fileMode_service} }

sub effective_backup_dir {
    my ($ci, $inst) = @_;
    return $ci->{backup_dir} if $ci && $ci->{backup_dir};
    return path($global->{backupDir}, $inst)->to_string if $global->{backupDir};
    return;
}

# -------------------- Logging --------------------
my $logfile = $global->{logfile} // "/var/log/postfix-agent.log";
my $logdir  = path($logfile)->dirname->to_string;
ensure_dir(dir => $logdir) unless -d $logdir;

eval { open(my $lfh, '>>', $logfile) or die $!; close $lfh; 1; }
  or die "Kann Logfile $logfile nicht oeffnen: $@";

my $logger = Mojo::Log->new(path => $logfile, level => 'info');
$logger->format(sub {
    my ($time, $level, @lines) = @_;
    my $ts  = _ts_log($time);
    my $lvl = uc($level // 'info');
    return join('', map { my $m = $_; chomp $m; "$ts $lvl $m\n" } @lines);
});
eval { set_file_ownership_and_mode($logfile, $global->{serviceUser}, $global->{serviceGroup}); 1; };

# -------------------- Directories --------------------
if (my $dconf = $global->{dirs}) {
    my $folders = $dconf->{service_folder};
    $folders = [$folders] unless ref $folders eq 'ARRAY';
    for my $fldkey (@$folders) {
        my $dir = $global->{$fldkey} // next;
        my $e = ensure_dir(dir=>$dir, user=>$global->{serviceUser}, group=>$global->{serviceGroup}, mode=>$global->{dirs}{service_mode});
        $logger->warn($e) if $e;
    }
}

for my $name (keys %$instances) {
    my $ci  = $instances->{$name};
    my $dir = effective_backup_dir($ci, $name) // next;
    my $e = ensure_dir(dir=>$dir, user=>$global->{serviceUser}, group=>$global->{serviceGroup}, mode=>$global->{dirs}{service_mode});
    $logger->warn($e) if $e;
}

my $tmp_dir = $global->{tmpDir} // '/tmp';
ensure_dir(dir => $tmp_dir) unless -d $tmp_dir;

# -------------------- Atomic write --------------------
sub _atomic_write_impl {
    my ($target, $content, $user, $group, $mode, $umask_only) = @_;
    my $dir = path($target)->dirname->to_string;
    die "Verzeichnis nicht beschreibbar: $dir" unless -w $dir;

    my $tmpfile;
    for (1..128) {
        my $rand = int(rand(1_000_000_000));
        my $cand = path($dir)->child(".tmp_${$}_$rand")->to_string;
        if (sysopen(my $fh, $cand, O_CREAT|O_EXCL|O_WRONLY, 0666)) {
            binmode($fh, ':encoding(UTF-8)');
            print $fh $content;
            close $fh or die "close($cand) failed: $!";
            $tmpfile = $cand;
            last;
        }
    }
    die "atomic_write: konnte keine Temp-Datei erstellen in $dir" unless $tmpfile;

    $umask_only ? set_file_ownership_and_mode($tmpfile, $user, $group)
               : set_file_ownership_and_mode($tmpfile, $user, $group, $mode);

    rename $tmpfile, $target or die "rename($tmpfile -> $target) failed: $!";

    $umask_only ? set_file_ownership_and_mode($target, $user, $group)
               : set_file_ownership_and_mode($target, $user, $group, $mode);

    return 1;
}
sub atomic_write       { _atomic_write_impl($_[0],$_[1],$_[2],$_[3],$_[4],0) }
sub atomic_write_umask { _atomic_write_impl($_[0],$_[1],$_[2],$_[3],undef,1) }

# -------------------- Instance selection --------------------
sub normalize_inst { my $i = $_[0]; $i = '' unless defined $i; $i =~ s/^\s+|\s+$//g; $i }
sub resolve_inst_name {
    my $inst = normalize_inst($_[0]);
    my @names = sort keys %{ $config->{instances} // {} };
    return $names[0] if $inst eq '' && @names == 1;
    return ''        if $inst eq '';
    return $names[0] if $inst eq 'default' && !exists $config->{instances}{default} && @names == 1;
    return $inst;
}
sub get_instance_or_render {
    my ($c, $inst_in) = @_;
    my $inst = resolve_inst_name($inst_in);
    return ($c->render(status=>400, json=>{ok=>0,error=>'Instance required'}), undef, undef) unless $inst;
    my $ci = $config->{instances}{$inst};
    return ($c->render(status=>404, json=>{ok=>0,error=>'Unknown instance'}), undef, undef) unless $ci;
    return (undef, $inst, $ci);
}

# -------------------- Status parse --------------------
sub parse_service_status {
    my ($out, $rc) = @_;
    my $t = lc($out // '');
    $t =~ s/\r//g; $t =~ s/^\s+|\s+$//g;

    return (defined $rc && $rc == 0) ? 'unknown-ok' : 'unknown-fail' if $t eq '';
    return 'running' if $t =~ /\b(active|running)\b/;
    return 'running' if $t =~ /\bpid:\s*\d+\b/;
    return 'running' if $t =~ /\bpostfix\s+mail\s+system\s+is\s+running\b/;

    if ($t =~ /\b(not\s+running|inactive|dead|failed|stopp?ed)\b/) {
        return 'unknown-ok' if defined $rc && $rc == 0;
        return 'stopped';
    }

    return 'running' if defined $rc && $rc == 0;
    return 'stopped' if defined $rc && $rc == 1;
    return 'unknown-fail';
}

# -------------------- Auth + CORS --------------------
my $listen_addr   = $config->{global}{listen}        // '0.0.0.0:5000';
my $ssl_enable    = $config->{global}{ssl_enable}    // 0;
my $ssl_cert      = $config->{global}{ssl_cert_file} // '';
my $ssl_key       = $config->{global}{ssl_key_file}  // '';
my $require_https = $config->{global}{require_https} // 0;

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

    return $c->render(text => '', status => 204) if $c->req->method eq 'OPTIONS';

    if ($require_https) {
        my $is_https = ($c->req->url->to_abs->scheme // '') eq 'https' || ($c->req->is_secure // 0);
        return $c->render(status => 403, json => { ok => 0, error => 'HTTPS required' }) unless $is_https;
    }

    return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' })
      unless Net::CIDR::cidrlookup($c->tx->remote_address, @acl_rt);

    my $hdr_token = $c->req->headers->header('X-API-Token') // '';
    my $bearer    = ($c->req->headers->authorization // '') =~ /^Bearer\s+(.+)/i ? $1 : '';
    my $token     = $hdr_token || $bearer;

    return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' })
      unless secure_compare($token, $api_token);
};

# -------------------- configs.json RW helpers --------------------
sub cfg_load { decode_json(read_text($instances_cfg_file)) }

sub cfg_node {
    my ($cfg, $inst) = @_;
    return (ref($cfg->{instances}) eq 'HASH')
      ? ($cfg->{instances}{$inst} //= {})
      : ($cfg->{$inst} //= {});
}

sub cfg_save {
    my ($cfg) = @_;
    atomic_write_umask($instances_cfg_file, json_pretty($cfg), $global->{serviceUser}, $global->{serviceGroup});
}

sub cfg_rebuild_instances {
    my ($cfg) = @_;
    my $insts = (ref($cfg->{instances}) eq 'HASH') ? $cfg->{instances} : $cfg;
    $insts = wrap_instances_hash_if_needed($insts);
    $instances = $insts;
    $config->{instances} = $insts;

    for my $n (keys %{$config->{instances}}) {
        delete $config->{instances}{$n}{_glob_re_cache};
        delete $config->{instances}{$n}{_glob_re_order};
    }
}

# -------------------- Sanitizer (vereinheitlicht) --------------------
my %GLOB_TYPES = map { $_ => 1 } qw(regexp pcre cidr lmdb hash btree db);
my %FORBIDDEN  = map { $_ => 1 } qw(main.cf master.cf);
sub deny_forbidden_map { $FORBIDDEN{ lc($_[0] // '') } ? 1 : 0 }

sub sanitize_generic {
    my (%a) = @_;
    my $v = $a{basename} ? path($a{raw} // '')->basename : ($a{raw} // '');
    $v = _trim($v);

    return (undef, "Empty") unless length $v;
    return (undef, "Invalid characters") unless $v =~ $a{re_ok};

    if ($a{no_path}) {
        return (undef, "Path traversal detected") if $v =~ /\A\.+\z/;
        return (undef, "Path traversal detected") if $v =~ m{[\\/]} || $v =~ /\.\./;
    }
    if ($a{no_slash}) {
        return (undef, "Path traversal detected") if $v =~ m{/|\\|\.\.};
    }

    $v = lc($v) if $a{lower};
    return ($v, undef);
}

sub sanitize_map_name  { sanitize_generic(raw=>$_[0], basename=>1, re_ok=>qr/\A[0-9A-Za-z._-]{1,255}\z/, no_path=>1) }
sub sanitize_glob_key  { sanitize_generic(raw=>$_[0], re_ok=>qr/\A[0-9A-Za-z._*\-]{1,255}\z/, no_slash=>1) }
sub sanitize_glob_val  { sanitize_generic(raw=>$_[0], re_ok=>qr/\A[a-z0-9_\-]{1,32}\z/i, lower=>1) }

# -------------------- Glob regex cache --------------------
sub _compile_glob_to_re {
    my ($glob) = @_;
    (my $re = $glob) =~ s/\./\\./g;
    $re =~ s/\*/.*/g;
    return qr/^$re$/;
}

sub _ensure_glob_cache {
    my ($ci) = @_;
    return if $ci->{_glob_re_cache};

    my $gl = $ci->{globs};
    $gl = {} unless $gl && ref($gl) eq 'HASH';

    my %cache;
    my @order;
    for my $k (keys %$gl) {   # bewusst unsortiert, wie "frueher"
        next unless defined $k && length $k;
        next unless $k =~ /\*/;
        $cache{$k} = _compile_glob_to_re($k);
        push @order, $k;
    }

    $ci->{_glob_re_cache} = \%cache;
    $ci->{_glob_re_order} = \@order;
}

sub map_type_for_file {
    my ($ci, $file) = @_;
    my $globs = $ci->{globs} // {};
    return $globs->{$file} if exists $globs->{$file};

    _ensure_glob_cache($ci);
    my $cache = $ci->{_glob_re_cache} // {};
    my $order = $ci->{_glob_re_order} // [];

    for my $glob (@$order) {
        my $re = $cache->{$glob} or next;
        return $globs->{$glob} if $file =~ $re;
    }
    return;
}

# -------------------- Commands + Backup --------------------
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
    my $tmpl = $ci->{postmap_by_type}{$type} or return;

    my $p = "$ci->{map_dir}/$file"; $p =~ s{//+}{/}g;
    (my $cmd = $tmpl) =~ s/\{config_dir\}/$ci->{config_dir}/g;
    $cmd =~ s/\{path\}/$p/g;
    $cmd =~ s/\{inst\}/$inst/g;
    return $cmd;
}

sub backup_file {
    my ($file, $dir, $max) = @_;
    return unless -f $file;

    my $e = ensure_dir(dir=>$dir, user=>$global->{serviceUser}, group=>$global->{serviceGroup}, mode=>$global->{dirs}{service_mode});
    $logger->warn($e) if $e;

    my $dst = "$dir/" . path($file)->basename . ".bak." . _ts_compact();
    try {
        path($dst)->spew(path($file)->slurp);
        my $bm = effective_backup_mode();
        my $er = set_file_ownership_and_mode($dst, $global->{serviceUser}, $global->{serviceGroup}, $bm);
        $logger->warn($er) if $er;
    } catch {
        $logger->error("Backup fehlgeschlagen: $_");
        return;
    };

    return unless $max;
    my @bak = sort { (stat($a))[9] <=> (stat($b))[9] } glob("$dir/" . path($file)->basename . ".bak.*");
    my $to_delete = @bak - $max;
    for my $del (@bak[0 .. $to_delete-1]) {
        unlink $del or $logger->warn("Konnte altes Backup nicht loeschen: $del ($!)");
    }
}

# -------------------- Subprocess runner + promise wrapper --------------------
sub run_cmd_subprocess_p {
    my ($cmd_str) = @_;
    $cmd_str //= '';
    $cmd_str =~ s/^\s+|\s+$//g;

    my @cmd = shellwords($cmd_str);
    return Mojo::Promise->reject('empty command') unless @cmd;

    my $p  = Mojo::Promise->new;
    my $sp = Mojo::IOLoop::Subprocess->new;

    $sp->run(
        sub {
            open(local *STDERR, ">&", STDOUT) or die "Can't dup STDOUT: $!";
            open(my $fh, "-|", @cmd) or die "Can't execute @cmd: $!";
            my $output = do { local $/; <$fh> };
            close($fh);
            my $rc = $? >> 8;
            return { rc => $rc, output => $output // '' };
        },
        sub {
            my ($subproc, $err, $res) = @_;
            return $p->reject($err) if $err;
            return $p->resolve($res);
        }
    );

    return $p;
}

sub run_promise {
    my ($c, $cb) = @_;
    $c->render_later;
    return Mojo::Promise->resolve->then(sub { $cb->(); })->catch(sub {
        my ($err) = @_;
        $logger->error("Unhandled error: $err");
        $c->render(status => 500, json => { ok => 0, error => 'Internal error' });
    });
}

sub run_cmd_into_result_p {
    my (%a) = @_;
    my $cmd   = $a{cmd}   // '';
    my $slot  = $a{slot}  // {};
    my $mode  = $a{mode}  // 'strict';
    my $label = $a{label} // 'cmd';

    return Mojo::Promise->resolve(1) unless $cmd;

    return run_cmd_subprocess_p($cmd)->then(sub {
        my ($r) = @_;
        my $rc  = $r->{rc} // 255;
        my $out = $r->{output} // '';

        %$slot = (executed=>1, command=>$cmd, rc=>$rc, output=>$out, result=>($rc==0?'ok':'fail'));

        if ($mode eq 'warn' && $rc != 0) {
            $slot->{result}  = 'warn';
            $slot->{warning} = "$label rc=$rc (will verify via status)";
            return 1;
        }

        die "$label rc=$rc: $out" if $rc != 0;
        return 1;
    })->catch(sub {
        my ($e) = @_;
        %$slot = ( executed => 1, result => 'fail', error => "$e" );
        return 1;
    });
}

# -------------------- Locks --------------------
sub _lock_dir_for {
    my ($ci, $inst) = @_;
    $inst = normalize_inst($inst);

    return $ci->{lock_dir} if $ci && $ci->{lock_dir};
    return $config->{global}{lockDir} if $config->{global}{lockDir};

    my $base = $config->{global}{tmpDir} // '/tmp';
    return File::Spec->catdir($base, 'postfix-agent-locks', $inst);
}

sub with_map_lock {
    my ($ci, $map, $exclusive, $code, $inst) = @_;
    $inst = normalize_inst($inst);

    my $ldir = _lock_dir_for($ci, $inst);
    my $e = ensure_dir(dir=>$ldir, user=>$config->{global}{serviceUser}, group=>$config->{global}{serviceGroup}, mode=>$config->{global}{dirs}{service_mode});
    $logger->warn($e) if $e;

    my $lpath = path($ldir, "$map.lock")->to_string;

    my $newfile = 0;
    if (!-e $lpath) {
        $newfile = 1;
        sysopen(my $tfh, $lpath, O_CREAT|O_EXCL|O_WRONLY, 0660) or $newfile = 0;
        close $tfh if $newfile;
    }

    sysopen(my $lfh, $lpath, O_RDWR|O_CREAT, 0660) or die "Lockfile open failed $lpath: $!";
    if ($newfile) {
        my $er = set_file_ownership_and_mode($lpath, $config->{global}{serviceUser}, $config->{global}{serviceGroup});
        $logger->warn("Lockfile chown/chmod: $er") if $er;
    }

    my $want = $exclusive ? LOCK_EX : LOCK_SH;
    my $t0 = time;

    while (1) {
        if (flock($lfh, $want | LOCK_NB)) {
            my ($ret, $err);
            eval { $ret = $code->(); 1 } or $err = $@;

            if (!$err && $ret && ref($ret) && eval { $ret->isa('Mojo::Promise') }) {
                my $p = Mojo::Promise->new;
                $ret->then(sub { flock($lfh, LOCK_UN); close $lfh; $p->resolve(@_); })
                    ->catch(sub { flock($lfh, LOCK_UN); close $lfh; $p->reject($_[0]); });
                return $p;
            }

            flock($lfh, LOCK_UN); close $lfh;
            die $err if $err;
            return $ret;
        }

        if ((time - $t0) > LOCK_TIMEOUT_S()) {
            close $lfh;
            die "Lock-Timeout ($map)";
        }
        sleep 0.05;
    }
}

# -------------------- Status verify --------------------
sub _status_verify_p {
    my ($ci, $inst, $result) = @_;
    my $grace = _num_seconds($config->{global}{reload_grace_s}, RELOAD_GRACE_S());
    my $status_cmd = expand_cmd($ci, $inst, $ci->{status_cmd} // '');

    return Mojo::Promise->resolve(1)->then(sub {
        my $t = Mojo::Promise->new;
        Mojo::IOLoop->timer($grace => sub { $t->resolve(1) });
        return $t;
    })->then(sub {
        if (!$status_cmd) { $result->{status} = { executed => 0 }; return 1; }

        return run_cmd_subprocess_p($status_cmd)->then(sub {
            my ($r) = @_;
            my $rc  = $r->{rc} // 255;
            my $out = $r->{output} // '';
            $out =~ s/\r//g; $out =~ s/^\s+|\s+$//g;

            $result->{status} = { executed=>1, command=>$status_cmd, rc=>$rc, output=>$out };
            my $st = parse_service_status($out, $rc);
            $result->{status}{result} = $st;

            return 1 if $st eq 'running';
            if ($st eq 'unknown-ok') { $result->{status}{warning} = 'Status nicht eindeutig (toleriert)'; return 1; }
            if ($rc == 0)            { $result->{status}{warning} = 'Status meldet nicht running, aber rc=0 (toleriert)'; return 1; }

            $result->{status}{warning} = "Status meldet '$st' (rc=$rc)";
            return 1;
        });
    })->catch(sub {
        my ($err) = @_;
        $logger->warn("Status-Check fehlgeschlagen: $err");
        $result->{status} = { executed => 1, result => 'fail', error => "$err" };
        return Mojo::Promise->resolve(1);
    });
}

# -------------------- Apply change engine --------------------
sub apply_map_change_p {
    my (%a) = @_;
    my ($ci, $inst, $map, $result, $writecb) = @a{qw/ci inst map result writecb/};

    return with_map_lock($ci, $map, 1, sub {
        $writecb->();

        my $p = Mojo::Promise->resolve(1);
        my $pm_cmd = postmap_cmd($ci, $map, $inst);

        $result->{postmap} //= { executed => 0 };
        $p = $p->then(sub { run_cmd_into_result_p(cmd=>$pm_cmd, slot=>$result->{postmap}, mode=>'strict', label=>'postmap') });

        if ($ci->{reload_on_change}) {
            my $reload_cmd = expand_cmd($ci, $inst, $ci->{reload_cmd} // '');
            $result->{reload} //= { executed => 0 };
            $p = $p->then(sub { run_cmd_into_result_p(cmd=>$reload_cmd, slot=>$result->{reload}, mode=>'warn', label=>'reload') })
                   ->then(sub { _status_verify_p($ci, $inst, $result) });
        } else {
            $result->{reload} //= { executed => 0 };
            $result->{status} //= { executed => 0 };
        }

        return $p;
    }, $inst);
}

sub render_lock_error_or_500 {
    my ($c, $err, $result_opt) = @_;
    $err = "$err";
    return $c->render(status => 423, json => { ok => 0, error => 'Map locked (timeout)' }) if $err =~ /Lock-Timeout/;

    if ($result_opt && ref($result_opt) eq 'HASH') {
        $result_opt->{ok} = 0;
        $result_opt->{error} = $err;
        return $c->render(status => 500, json => $result_opt);
    }
    return $c->render(status => 500, json => { ok => 0, error => $err });
}

# -------------------- Handler subs (Route bodies klein halten) --------------------
sub h_root      { my ($c)=@_; $c->render(json => { info => 'Postfix Agent', version => $VERSION }) }
sub h_instances { my ($c)=@_; $c->render(json => { instances => [ sort keys %{ $config->{instances} } ] }) }

sub h_list_maps {
    my ($c, $inst, $ci) = @_;
    my %seen;
    my $globs = $ci->{globs} // {};
    my $want_all = ($c->param('all') // '') eq '1';

    if ($want_all || !%$globs) {
        if (opendir(my $dh, $ci->{map_dir})) {
            while (my $e = readdir($dh)) {
                next if $e =~ /^\./;
                next if deny_forbidden_map($e);
                my $p = "$ci->{map_dir}/$e";
                $seen{$e} = 1 if -f $p;
            }
            closedir $dh;
        }
    } else {
        for my $glob (keys %$globs) {
            for my $f (glob "$ci->{map_dir}/$glob") {
                my $bn = path($f)->basename;
                next if deny_forbidden_map($bn);
                $seen{$bn} = 1 if -f $f;
            }
        }
    }

    $c->render(json => { ok => 1, maps => [ sort keys %seen ] });
}

sub h_get_map {
    my ($c, $inst, $ci) = @_;
    my ($map, $err) = sanitize_map_name($c->stash('map'));
    return $c->render(status=>400, json=>{ ok=>0, error=>$err }) if $err;
    return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' }) if deny_forbidden_map($map);

    my $p = "$ci->{map_dir}/$map";
    return $c->render(status => 404, json => { ok => 0, error => 'Not found' }) unless -r $p;

    $c->res->headers->content_type('text/plain; charset=UTF-8');
    $c->render(data => read_text($p));
}

sub h_list_backups {
    my ($c, $inst, $ci) = @_;
    my ($base, $err) = sanitize_map_name($c->stash('map'));
    return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
    return $c->render(status=>400, json=>{ ok=>0, error=>'forbidden map name' }) if deny_forbidden_map($base);

    my $backup_dir = effective_backup_dir($ci, $inst)
      or return $c->render(status => 404, json => { ok => 0, error => 'No backup_dir' });

    my @files = glob("$backup_dir/$base.bak.*");
    @files = sort { (stat($b))[9] <=> (stat($a))[9] } @files;
    @files = map { s{^\Q$backup_dir\E/}{}r } @files;

    $c->render(json => { ok => 1, backups => \@files });
}

sub h_get_backupfile {
    my ($c, $inst, $ci) = @_;
    my ($backup_file, $err) = sanitize_map_name($c->stash('backup') // '');
    return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;

    my $backup_dir = effective_backup_dir($ci, $inst);
    return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }) unless $backup_dir && -d $backup_dir;

    my $fullpath = "$backup_dir/$backup_file";
    return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }) unless -f $fullpath && -r $fullpath;

    my $mode = $c->param('mode') // 'text';
    if ($mode eq 'download') {
        my $bytes = read_raw($fullpath);
        $c->res->headers->content_disposition(qq{attachment; filename="$backup_file"});
        $c->res->headers->content_type('application/octet-stream');
        return $c->render(data => $bytes);
    }
    if ($mode eq 'json') {
        my $content = read_text($fullpath);
        $content =~ s/\r\n/\n/g;
        return $c->render(json => { ok => 1, name => $backup_file, size => length($content), content => $content });
    }

    $c->res->headers->content_type('text/plain; charset=UTF-8');
    $c->render(data => read_text($fullpath));
}

sub h_save_map {
    my ($c, $inst, $ci) = @_;

    my %result = (
        ok => 1, error => '', changed => 0,
        backup => 'skipped', write => 'skipped',
        postmap => { executed => 0 },
        reload  => { executed => 0 },
        status  => { executed => 0 },
    );

    my ($map, $san_err) = sanitize_map_name($c->stash('map'));
    if ($san_err) { $result{ok}=0; $result{error}=$san_err; return $c->render(status=>400, json=>\%result); }
    return $c->render(status => 400, json => { ok => 0, error => 'forbidden map name' }) if deny_forbidden_map($map);

    my $path = "$ci->{map_dir}/$map";

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
        else                                                  { $new_content = to_json($json, { canonical => 1 }); }
    }

    $new_content //= $c->param('content');
    $new_content //= decode('UTF-8', $c->req->body // '');
    $new_content =~ s/\r\n/\n/g if defined $new_content;

    my $dir = path($path)->dirname->to_string;
    if (!-d $dir) {
        my $e = ensure_dir(dir=>$dir, user=>$global->{serviceUser}, group=>$global->{serviceGroup}, mode=>$global->{dirs}{service_mode});
        $logger->warn($e) if $e;
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

    if (-e $path && !-w $path) { $result{ok}=0; $result{error}='Not found or not writable'; return $c->render(status=>403, json=>\%result); }

    my ($old, $read_error) = ('', 0);
    try { $old = (-e $path) ? read_text($path) : ''; }
    catch { $read_error = $_; $logger->error("Fehler beim Lesen von $path: $_"); };

    if ($read_error) { $result{ok}=0; $result{error}="Fehler beim Lesen: $read_error"; return $c->render(status=>500, json=>\%result); }

    $new_content = "#\n" if (!-e $path) && !(defined($new_content) && $new_content ne '');
    if ($new_content eq $old) { $result{write}='skipped'; $result{backup}='skipped'; return $c->render(json=>\%result); }

    $result{changed} = 1;

    my $p = eval {
        apply_map_change_p(
            ci=>$ci, inst=>$inst, map=>$map, result=>\%result,
            writecb => sub {
                my $bdir = effective_backup_dir($ci, $inst);
                if (-e $path) { backup_file($path, $bdir, $ci->{max_backups} // 5); $result{backup}='ok'; }
                else          { $result{backup}='not_existing'; }

                atomic_write($path, $new_content, effective_service_user(), effective_service_group(), effective_file_mode());
                $result{write} = 'ok';
            }
        );
    };
    return render_lock_error_or_500($c, $@, \%result) unless $p;

    return $p->then(sub { $c->render(json => \%result) })
             ->catch(sub { render_lock_error_or_500($c, $_[0], \%result) });
}

sub h_restore_backup {
    my ($c, $inst, $ci) = @_;

    my ($backupfile, $err) = sanitize_map_name($c->stash('backupfile') // '');
    return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;

    my $backup_dir = effective_backup_dir($ci, $inst);
    my $map_dir    = $ci->{map_dir};
    return $c->render(status => 500, json => { ok => 0, error => 'No backup dir' }) unless $backup_dir && -d $backup_dir;
    return $c->render(status => 500, json => { ok => 0, error => 'No map dir' })    unless $map_dir    && -d $map_dir;

    my $src = "$backup_dir/$backupfile";
    return $c->render(status => 404, json => { ok => 0, error => 'Backup file not found' }) unless -f $src;

    (my $map = $backupfile) =~ s/\.bak.*$//;
    return $c->render(status => 400, json => { ok => 0, error => 'forbidden map name' }) if deny_forbidden_map($map);

    my $dst = "$map_dir/$map";
    my %result = ( ok => 1, restored => $backupfile, target => $dst );

    my $p = eval {
        apply_map_change_p(
            ci=>$ci, inst=>$inst, map=>$map, result=>\%result,
            writecb => sub {
                atomic_write($dst, path($src)->slurp, $global->{serviceUser}, $global->{serviceGroup}, $global->{fileMode_service});
            }
        );
    };
    return render_lock_error_or_500($c, $@, \%result) unless $p;

    return $p->then(sub { $c->render(json => \%result) })
             ->catch(sub { render_lock_error_or_500($c, $_[0], \%result) });
}

sub h_delmap {
    my ($c, $inst, $ci) = @_;

    my ($map, $err) = sanitize_map_name($c->stash('map'));
    return $c->render(status => 400, json => { ok => 0, error => $err }) if $err;
    return $c->render(status => 400, json => { ok => 0, error => 'forbidden map name' }) if deny_forbidden_map($map);

    my $cfg = eval { cfg_load() };
    return $c->render(status => 500, json => { ok => 0, error => "configs.json lesen: $@" }) if $@;

    my $node = cfg_node($cfg, $inst);
    my $gl   = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};
    $node->{globs} = $gl;

    my $removed = 0;
    if (exists $gl->{$map}) { delete $gl->{$map}; $removed = 1; }

    eval { cfg_save($cfg); 1 } or return $c->render(status => 500, json => { ok => 0, error => "configs.json schreiben: $@" });
    eval { cfg_rebuild_instances($cfg); 1 };

    my @matched_patterns;
    if (!$removed) {
        _ensure_glob_cache($ci);
        my $cache = $ci->{_glob_re_cache} // {};
        my $order = $ci->{_glob_re_order} // [];
        for my $glob (@$order) {
            my $re = $cache->{$glob} or next;
            push @matched_patterns, $glob if $map =~ $re;
        }
    }

    my ($action, $msg);
    if ($removed) {
        $action = 'removed';
        $msg = "Eintrag in configs.json globs der Instanz '$inst' wurde fuer '$map' entfernt.";
    } elsif (@matched_patterns) {
        $action = 'pattern_only';
        $msg = "Kein exakter Eintrag fuer '$map' in configs.json globs der Instanz '$inst'. Datei ist aber durch Muster abgedeckt: "
             . join(', ', @matched_patterns) . ". Es wurde nichts geaendert.";
    } else {
        $action = 'not_registered';
        $msg = "Fuer '$map' existiert kein Eintrag in configs.json globs der Instanz '$inst'. Es wurde nichts geaendert.";
    }
    $msg .= " Diese API loescht keine Dateien. Bitte bereinige Verweise in main.cf/master.cf bei Bedarf.";

    $c->render(json => {
        ok                   => 1,
        instance             => $inst,
        map                  => $map,
        action               => $action,
        matched_patterns     => \@matched_patterns,
        changed_configs_json => $removed ? true : false,
        action_required      => $msg,
        note                 => "Kein Reload und keine Datei-Loeschung durchgefuehrt (Policy).",
        configs_file         => $instances_cfg_file,
    });
}

sub h_globs_get {
    my ($c, $inst) = @_;
    my $cfg = eval { cfg_load() };
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;
    my $node = cfg_node($cfg, $inst);
    my $gl   = (ref($node->{globs}) eq 'HASH') ? $node->{globs} : {};
    $c->render(json => { ok=>1, instance=>$inst, globs=>$gl });
}

sub _collect_glob_items_from_req {
    my ($c) = @_;
    my $j = eval { $c->req->json };
    $j = {} if $@ || !defined $j;

    my @items;
    if (ref($j) eq 'HASH' && %$j) {
        @items = ref($j->{items}) eq 'ARRAY' ? @{$j->{items}} : ($j);
    } else {
        if (defined(my $items_param = $c->param('items'))) {
            my $arr = eval { decode_json($items_param) } || [];
            @items = @$arr if ref($arr) eq 'ARRAY';
        }
        push @items, { map => ($c->param('map') // ''), type => ($c->param('type') // '') } unless @items;
    }
    return @items;
}

sub h_globs_upsert {
    my ($c, $inst) = @_;

    my @items = _collect_glob_items_from_req($c);
    return $c->render(status=>400, json=>{ ok=>0, error=>'Payload fehlt oder ungueltig' })
      unless @items && ref($items[0]) eq 'HASH';

    my (@changes, %seen);
    for my $it (@items) {
        my $map_raw  = $it->{map}  // '';
        my $type_raw = $it->{type} // '';
        return $c->render(status=>400, json=>{ok=>0,error=>'map fehlt'})  unless length $map_raw;
        return $c->render(status=>400, json=>{ok=>0,error=>'type fehlt'}) unless length $type_raw;

        my ($map, $e_map) = sanitize_glob_key($map_raw);
        return $c->render(status=>400, json=>{ok=>0,error=>"ungueltiger map-key: ".($e_map||'?')}) unless defined $map;

        my ($type_norm, $e_type) = sanitize_glob_val($type_raw);
        return $c->render(status=>400, json=>{ok=>0,error=>"ungueltiger type: ".($e_type||'?')}) unless defined $type_norm;
        return $c->render(status=>400, json=>{ok=>0,error=>"ungueltiger type: $type_norm"}) unless $GLOB_TYPES{$type_norm};

        my $key = "$map\x1F$type_norm";
        next if $seen{$key}++;
        push @changes, [$map, $type_norm];
    }

    my $cfg = eval { cfg_load() };
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;

    my $node = cfg_node($cfg, $inst);
    $node->{globs} //= {};

    my @applied;
    for my $ch (@changes) {
        my ($map,$type) = @$ch;
        my $prev = $node->{globs}{$map};
        $node->{globs}{$map} = $type;
        push @applied, { map=>$map, type=>$type, action => (defined $prev ? 'updated' : 'created'), previous_type => $prev };
    }

    eval { cfg_save($cfg); 1 } or return $c->render(status=>500, json=>{ok=>0,error=>"configs.json schreiben: $@"});
    eval { cfg_rebuild_instances($cfg); 1 };

    $c->render(json => { ok=>1, instance=>$inst, upserted=>\@applied });
}

sub h_globs_delete {
    my ($c, $inst) = @_;
    my $map = $c->stash('map');

    my $cfg = eval { cfg_load() };
    return $c->render(status=>500, json=>{ok=>0,error=>"configs.json lesen: $@"}) if $@;

    my $node = cfg_node($cfg, $inst);
    my $had  = (ref($node->{globs}) eq 'HASH') && exists $node->{globs}{$map};
    delete $node->{globs}{$map} if $had;

    eval { cfg_save($cfg); 1 } or return $c->render(status=>500, json=>{ok=>0,error=>"configs.json schreiben: $@"});
    eval { cfg_rebuild_instances($cfg); 1 };

    $c->render(json => { ok=>1, instance=>$inst, map=>$map, removed=>($had?true:false) });
}

sub h_health {
    my ($c) = @_;
    my @required_dirs = ($tmp_dir);
    for my $name (keys %{ $config->{instances} }) {
        my $ci = $config->{instances}{$name};
        my $bdir = effective_backup_dir($ci, $name);
        push @required_dirs, $bdir if $bdir;
    }
    my @miss = grep { $_ && !-d $_ } @required_dirs;
    return $c->render(status => 500, json => { ok => 0, error => "Missing dirs: @miss" }) if @miss;
    $c->render(json => { ok => 1, status => "ok" });
}

# -------------------- Routes --------------------
get '/' => sub {
    my $c = shift;
    run_promise($c, sub { h_root($c) });
};

get '/instances' => sub {
    my $c = shift;
    run_promise($c, sub { h_instances($c) });
};

get '/instances/:inst/maps' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_list_maps($c, $inst, $ci);
    });
};

get '/instances/:inst/map/*map' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_get_map($c, $inst, $ci);
    });
};

get '/instances/:inst/backup/*map' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_list_backups($c, $inst, $ci);
    });
};

get '/instances/:inst/backupfile/*backup' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_get_backupfile($c, $inst, $ci);
    });
};

post '/instances/:inst/map/*map' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_save_map($c, $inst, $ci);
    });
};

post '/instances/:inst/restore/*backupfile' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_restore_backup($c, $inst, $ci);
    });
};

post '/instances/:inst/delmap/*map' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($r, $inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return if $r;
        h_delmap($c, $inst, $ci);
    });
};

get '/instances/:inst/globs' => sub {
    my $c = shift;
    run_promise($c, sub {
        my $inst = resolve_inst_name($c->stash('inst'));
        return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
        h_globs_get($c, $inst);
    });
};

post '/instances/:inst/globs' => sub {
    my $c = shift;
    run_promise($c, sub {
        my $inst = resolve_inst_name($c->stash('inst'));
        return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
        h_globs_upsert($c, $inst);
    });
};

del '/instances/:inst/globs/:map' => sub {
    my $c = shift;
    my $inst = resolve_inst_name($c->stash('inst'));
    return $c->render(status=>400, json=>{ok=>0,error=>'Instance required'}) unless $inst;
    h_globs_delete($c, $inst);
};

get '/health' => sub {
    my $c = shift;
    run_promise($c, sub { h_health($c) });
};

any '/*' => sub {
    my $c = shift;
    run_promise($c, sub { $c->render(status => 404, json => { ok => 0, error => 'Not found' }); });
};

# -------------------- Start Server --------------------
my $url;
if ($ssl_enable && $ssl_cert && $ssl_key) {
    $url = sprintf('https://%s?cert=%s&key=%s', $listen_addr, url_escape($ssl_cert), url_escape($ssl_key));
} else {
    $url = sprintf('http://%s', $listen_addr);
}
$logger->info("Listening at $url (require_https=" . ($require_https?1:0) . ")");
app->start('daemon', '-l', $url);
