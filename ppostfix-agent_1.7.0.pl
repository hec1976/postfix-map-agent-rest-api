#!/usr/bin/env perl
use strict;
use warnings;
use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::JSON qw(decode_json encode_json true false);
use Mojo::Util qw(url_escape secure_compare steady_time decode);
use Mojo::Promise;
use Mojo::IOLoop::Subprocess;
use Net::CIDR;
use Fcntl qw(:mode O_CREAT O_EXCL O_WRONLY O_RDWR :flock);
use Time::HiRes qw(time);
use Text::ParseWords qw(shellwords);
use File::Spec;
use Try::Tiny;

use constant {
    RELOAD_GRACE_S  => 0.35,
    LOCK_TIMEOUT_S  => 3.0,
    VERSION         => '1.7.0',
};

# --- Globale Helfer ---
sub _num_seconds {
    my ($v, $default) = @_;
    $default //= 0.35;
    my $fallback = $default + 0;
    return $v + 0 if defined $v && $v =~ /\A\d+(?:\.\d+)?\z/;
    return $fallback;
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

# --- I/O & Config ---
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
    return oct($m) if "$m" =~ /^[0-7]{3,4}$/;
    return $m if "$m" =~ /^\d+$/;
    return;
}

sub read_json_config {
    my ($file) = @_;
    my $text = read_text($file);
    return decode_json($text);
}

sub wrap_instances_hash_if_needed {
    my ($insts) = @_;
    return $insts unless $insts && ref($insts) eq 'HASH';
    return $insts if exists $insts->{default};
    return { default => $insts } if _looks_like_instance_node($insts);
    return $insts;
}

sub _looks_like_instance_node {
    my ($h) = @_;
    return 0 unless $h && ref($h) eq 'HASH';
    for my $k (qw(map_dir config_dir globs postmap_by_type reload_cmd status_cmd backup_dir lock_dir)) {
        return 1 if exists $h->{$k};
    }
    return 0;
}

# --- Logging ---
sub setup_logger {
    my $logfile = app->config->{global}{logfile} // "/var/log/mmbb/postfix-agent.log";
    my $logdir  = path($logfile)->dirname->to_string;
    unless (-d $logdir) {
        eval { path($logdir)->make_path };
        die "Kann Log-Verzeichnis $logdir nicht anlegen: $@" if $@;
    }
    eval { open my $lfh, '>>', $logfile or die $!; close $lfh; 1 }
        or die "Kann Logfile $logfile nicht öffnen: $@";

    my $logger = Mojo::Log->new(path => $logfile, level => 'info');
    $logger->format(sub {
        my ($time, $level, @lines) = @_;
        my $ts  = _ts_log($time);
        my $lvl = uc($level // 'info');
        return join('', map { my $m = $_; chomp $m; "$ts $lvl $m\n" } @lines);
    });
    app->log($logger);
}

# --- FS & Permissions ---
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

sub atomic_write {
    my ($path, $content, $user, $group, $mode) = @_;
    my $dir = path($path)->dirname->to_string;
    die "Verzeichnis nicht beschreibbar: $dir" unless -w $dir;
    my $tmpfile;
    for (1..128) {
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
    set_file_ownership_and_mode($tmpfile, $user, $group, $mode);
    rename $tmpfile, $path or die "rename($tmpfile -> $path) failed: $!";
    set_file_ownership_and_mode($path, $user, $group, $mode);
    return 1;
}

# --- Command Execution ---
sub run_cmd_subprocess_p {
    my ($cmd_str) = @_;
    $cmd_str //= '';
    $cmd_str =~ s/^\s+|\s+$//g;
    my @cmd = shellwords($cmd_str);
    return Mojo::Promise->reject('empty command') unless @cmd;
    my $p = Mojo::Promise->new;
    Mojo::IOLoop::Subprocess->new->run(
        sub {
            my ($subproc) = @_;
            open(local *STDERR, ">&", STDOUT) or die "Can't dup STDOUT: $!";
            open(my $fh, "-|", @cmd) or die "Can't execute @cmd: $!";
            my $output = do { local $/; <$fh> };
            close($fh);
            return { rc => $? >> 8, output => $output // '' };
        },
        sub {
            my ($subproc, $err, $res) = @_;
            $err ? $p->reject($err) : $p->resolve($res);
        }
    );
    return $p;
}

# --- API Helpers ---
sub render_error {
    my ($c, $status, $error, $details) = @_;
    app->log->error($error) if $status >= 500;
    $c->render(
        status => $status,
        json   => {
            ok      => 0,
            error   => $error,
            ($details ? (details => $details) : ())
        }
    );
}

sub run_promise {
    my ($c, $cb) = @_;
    $c->render_later;
    Mojo::Promise->resolve
        ->then(sub { $cb->() })
        ->catch(sub {
            my ($err) = @_;
            app->log->error("Unhandled error: $err");
            $c->render(status => 500, json => { ok => 0, error => 'Internal error' });
        });
}

# --- Map & Glob Helpers ---
sub sanitize_map_name {
    my ($raw) = @_;
    my $name = path($raw // '')->basename;
    return (undef, 'Empty name') unless defined $name && length $name;
    return (undef, 'Invalid characters') unless $name =~ /\A[0-9A-Za-z._-]{1,255}\z/;
    return (undef, 'Path traversal detected') if $name =~ /\A\.+\z/ || $name =~ m{[\\/]} || $name =~ /\.\./;
    return ($name, undef);
}

my %FORBIDDEN = map { $_ => 1 } qw(main.cf master.cf);
sub _deny_forbidden_map { my ($name) = @_; return $FORBIDDEN{ lc $name }; }

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

# --- Locking ---
sub with_map_lock {
    my ($ci, $map, $exclusive, $code, $inst) = @_;
    my $ldir = _lock_dir_for($ci, $inst);
    unless (-d $ldir) {
        path($ldir)->make_path;
        my $mode = app->config->{global}{dirs}{service_mode};
        my $err = set_dir_ownership_and_mode($ldir, effective_service_user(), effective_service_group(), $mode);
        app->log->warn("Lockdir perms: $err") if $err;
    }
    my $lpath = _map_lock_path($ci, $inst, $map);
    sysopen(my $lfh, $lpath, O_RDWR|O_CREAT, 0660)
        or die "Lockfile open failed $lpath: $!";
    my $e = set_file_ownership_and_mode($lpath, effective_service_user(), effective_service_group());
    app->log->warn("Lockfile chown/chmod: $e") if $e;
    my $want = $exclusive ? LOCK_EX : LOCK_SH;
    my $t0 = time;
    while (1) {
        if (flock($lfh, $want | LOCK_NB)) {
            my $ret; my $err;
            eval { $ret = $code->(); 1 } or $err = $@;
            if (!$err && $ret && ref($ret) && eval { $ret->isa('Mojo::Promise') }) {
                my $p = Mojo::Promise->new;
                $ret->then(sub { flock($lfh, LOCK_UN); close $lfh; $p->resolve(@_); })
                   ->catch(sub { flock($lfh, LOCK_UN); close $lfh; $p->reject(@_); });
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

sub _lock_dir_for {
    my ($ci, $inst) = @_;
    return $ci->{lock_dir} if $ci && $ci->{lock_dir};
    return app->config->{global}{lockDir} if app->config->{global}{lockDir};
    my $base = app->config->{global}{tmpDir} // '/tmp';
    return File::Spec->catdir($base, 'postfix-agent-locks', $inst);
}

sub _map_lock_path {
    my ($ci, $inst, $map) = @_;
    my $ldir = _lock_dir_for($ci, $inst);
    return path($ldir, "$map.lock")->to_string;
}

# --- Status & Postmap ---
sub parse_service_status {
    my ($out, $rc) = @_;
    my $txt = lc(($out // ''));
    $txt =~ s/\r//g;
    $txt =~ s/^\s+|\s+$//g;
    return 'running' if $txt =~ /\bis\s+running\b/ || $txt =~ /\bactive\b/ || ($rc // 0) == 0;
    return 'stopped' if $txt =~ /\bnot\s+running\b/ || $txt =~ /\binactive\b/ || $txt =~ /\bstopp?ed\b/ || $txt =~ /\bdead\b/ || $txt =~ /\bfailed\b/ || ($rc // 1) == 1;
    return 'unknown-fail';
}

sub _status_verify_p {
    my ($ci, $inst, $result) = @_;
    my $p = Mojo::Promise->resolve;
    my $grace = _num_seconds(app->config->{global}{reload_grace_s}, RELOAD_GRACE_S());
    $p = $p->then(sub {
        my $t = Mojo::Promise->new;
        Mojo::IOLoop->timer($grace => sub { $t->resolve(1) });
        return $t;
    });
    my $status_cmd = expand_cmd($ci, $inst, $ci->{status_cmd} // '');
    if (!$status_cmd) {
        $result->{status} = { executed => 0 };
        return $p;
    }
    $p = $p->then(sub {
        run_cmd_subprocess_p($status_cmd)->then(sub {
            my ($r) = @_;
            $result->{status} = {
                executed => 1,
                command  => $status_cmd,
                rc       => $r->{rc} // 255,
                output   => $r->{output} // '',
            };
            my $st = parse_service_status($r->{output}, $r->{rc});
            $result->{status}{result} = $st;
            return 1;
        });
    })->catch(sub {
        my ($err) = @_;
        app->log->warn("Status-Check fehlgeschlagen: $err");
        $result->{status} = {
            executed => 1,
            result   => 'fail',
            error    => "$err"
        };
        return Mojo::Promise->resolve(1);
    });
    return $p;
}

sub _run_postmap_and_reload {
    my ($ci, $inst, $map, $result) = @_;
    my $p = Mojo::Promise->resolve;
    if (my $pm_cmd = postmap_cmd($ci, $map, $inst)) {
        $p = $p->then(sub {
            run_cmd_subprocess_p($pm_cmd)->then(sub {
                my ($r) = @_;
                $result->{postmap} = {
                    executed => 1,
                    command  => $pm_cmd,
                    rc       => $r->{rc} // 255,
                    output   => $r->{output} // '',
                    result   => ($r->{rc} == 0) ? 'ok' : 'fail',
                };
                die "postmap failed" if $r->{rc} != 0;
                return 1;
            });
        })->catch(sub {
            my ($err) = @_;
            $result->{postmap} = {
                executed => 1,
                result   => 'fail',
                error    => "$err"
            };
            return 1;
        });
    }
    if ($ci->{reload_on_change}) {
        my $reload_cmd = expand_cmd($ci, $inst, $ci->{reload_cmd} // '');
        if ($reload_cmd) {
            $p = $p->then(sub {
                run_cmd_subprocess_p($reload_cmd)->then(sub {
                    my ($r) = @_;
                    $result->{reload} = {
                        executed => 1,
                        command  => $reload_cmd,
                        rc       => $r->{rc} // 255,
                        output   => $r->{output} // '',
                        result   => 'ok',
                    };
                    if ($r->{rc} != 0) {
                        $result->{reload}{result}  = 'warn';
                        $result->{reload}{warning} = "reload rc=$r->{rc}";
                    }
                    return 1;
                });
            })->catch(sub {
                my ($err) = @_;
                $result->{reload} = {
                    executed => 1,
                    result   => 'fail',
                    error    => "$err"
                };
                return 1;
            });
        }
    }
    $p = $p->then(sub { _status_verify_p($ci, $inst, $result) });
    return $p;
}

# --- Config Helpers ---
sub effective_service_user   { return app->config->{global}{serviceUser}; }
sub effective_service_group  { return app->config->{global}{serviceGroup}; }
sub effective_file_mode      { return app->config->{global}{fileMode_service}; }
sub effective_backup_mode    { return app->config->{global}{fileMode_backup} // effective_file_mode(); }
sub effective_backup_dir {
    my ($ci, $inst) = @_;
    return $ci->{backup_dir} if $ci && $ci->{backup_dir};
    return path(app->config->{global}{backupDir}, $inst)->to_string if app->config->{global}{backupDir};
    return;
}

# --- Backup ---
sub backup_file {
    my ($file, $dir, $max, $ci) = @_;
    unless (-f $file) { app->log->error("Kein Backup, da Datei $file nicht existiert."); return; }
    unless (-d $dir) {
        app->log->warn("Backup-Verzeichnis $dir nicht vorhanden, wird angelegt.");
        eval { path($dir)->make_path };
        if ($@) { app->log->error("Backup-Verzeichnis $dir konnte nicht erstellt werden: $@"); return; }
        my $err = set_dir_ownership_and_mode($dir, effective_service_user(), effective_service_group(), app->config->{global}{dirs}{service_mode});
        app->log->warn("set_dir_ownership_and_mode($dir): $err") if $err;
    }
    my $ts  = _ts_compact();
    my $dst = "$dir/" . path($file)->basename . ".bak.$ts";
    app->log->info("Erstelle Backup von $file nach $dst");
    try {
        my $data = path($file)->slurp;
        path($dst)->spew($data);
        my $bk_mode = effective_backup_mode();
        my $err = set_file_ownership_and_mode($dst, effective_service_user(), effective_service_group(), $bk_mode);
        app->log->error("Fehler bei set_file_ownership_and_mode ($dst): $err") if $err;
    } catch {
        app->log->error("Backup fehlgeschlagen: $_");
        return;
    };
    my @bak = glob "$dir/" . path($file)->basename . ".bak.*";
    @bak = sort { (stat($a))[9] <=> (stat($b))[9] } @bak;
    if ($max && @bak > $max) {
        my $to_delete = @bak - $max;
        for my $del (@bak[0 .. $to_delete-1]) {
            unlink $del or app->log->warn("Konnte altes Backup nicht löschen: $del ($!)");
        }
    }
}

# --- Instanz-Resolution ---
sub normalize_inst {
    my ($inst) = @_;
    $inst = '' unless defined $inst;
    $inst =~ s/^\s+|\s+$//g;
    return $inst;
}

sub resolve_inst_name {
    my ($inst_in) = @_;
    my $inst = normalize_inst($inst_in);
    my @names = sort keys %{ app->config->{instances} // {} };
    if ($inst eq '') {
        return $names[0] if @names == 1;
        return '';
    }
    if ($inst eq 'default' && !exists app->config->{instances}{default} && @names == 1) {
        return $names[0];
    }
    return $inst;
}

sub get_instance_or_render {
    my ($c, $inst_in) = @_;
    my $inst = resolve_inst_name($inst_in);
    if (!defined $inst || $inst eq '') {
        return $c->render(status => 400, json => { ok => 0, error => 'Instance required' });
    }
    my $ci = app->config->{instances}{$inst};
    unless ($ci) {
        return $c->render(status => 404, json => { ok => 0, error => 'Unknown instance' });
    }
    return ($inst, $ci);
}

# --- Routen ---
get '/' => sub {
    my $c = shift;
    $c->render(json => { info => 'HEC Postfix Agent', version => VERSION });
};

get '/instances' => sub {
    my $c = shift;
    $c->render(json => { instances => [sort keys %{ app->config->{instances} }] });
};

get '/instances/:inst/maps' => sub {
    my $c = shift;
    run_promise($c, sub {
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

post '/instances/:inst/map/*map' => sub {
    my $c = shift;
    run_promise($c, sub {
        my ($inst, $ci) = get_instance_or_render($c, $c->stash('inst'));
        return unless $ci;
        my ($map, $san_err) = sanitize_map_name($c->stash('map'));
        if ($san_err) {
            return render_error($c, 400, $san_err);
        }
        return render_error($c, 400, 'forbidden map name') if _deny_forbidden_map($map);
        my $path = "$ci->{map_dir}/$map";
        my $new_content = $c->param('content') // decode('UTF-8', $c->req->body // '');
        $new_content =~ s/\r\n/\n/g;
        unless (-w path($path)->dirname) {
            return render_error($c, 403, 'Directory not writable');
        }
        my %result = (ok => 1, changed => 0, backup => 'skipped', write => 'skipped');
        try {
            my $old_content = (-e $path) ? read_text($path) : '';
            return $c->render(json => \%result) if $new_content eq $old_content;
            $result{changed} = 1;
            my $lock_ret = with_map_lock($ci, $map, 1, sub {
                backup_file($path, effective_backup_dir($ci, $inst), $ci->{max_backups} // 5, $ci);
                atomic_write($path, $new_content, effective_service_user(), effective_service_group(), effective_file_mode());
                $result{backup} = 'ok';
                $result{write}  = 'ok';
                return _run_postmap_and_reload($ci, $inst, $map, \%result);
            }, $inst);
            if (ref($lock_ret) && eval { $lock_ret->isa('Mojo::Promise') }) {
                return $lock_ret->then(sub { $c->render(json => \%result) })
                               ->catch(sub {
                                   my ($e) = @_;
                                   if ($e =~ /Lock-Timeout/) {
                                       return render_error($c, 423, 'Map locked (timeout)');
                                   }
                                   return render_error($c, 500, "$e");
                               });
            }
            $c->render(json => \%result);
        } catch {
            if ($_ =~ /Lock-Timeout/) {
                return render_error($c, 423, 'Map locked (timeout)');
            }
            return render_error($c, 500, "$_");
        };
    });
};

# --- Start ---
my $home = app->home;
my $global_cfg_file    = $home->rel_file('global.json');
my $instances_cfg_file = $home->rel_file('configs.json');
die "Missing config $global_cfg_file\n"    unless -f $global_cfg_file;
die "Missing config $instances_cfg_file\n" unless -f $instances_cfg_file;

app->config->{global}    = read_json_config($global_cfg_file);
app->config->{instances} = wrap_instances_hash_if_needed(read_json_config($instances_cfg_file));

# Defaults setzen
app->config->{global}{serviceUser}      //= 'root';
app->config->{global}{serviceGroup}     //= 'root';
app->config->{global}{fileMode_service} //= '0644';
app->config->{global}{fileMode_backup}  //= '0660';

# API-Token prüfen
my $api_token = $ENV{API_TOKEN} // (app->config->{global}{api_token} // '');
die "FATAL: API_TOKEN nicht gesetzt (ENV API_TOKEN oder global.json api_token)\n" unless $api_token;

# CORS & Auth
hook before_dispatch => sub {
    my $c = shift;
    my $ips_rt = app->config->{global}{allowed_ips};
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
    unless (Net::CIDR::cidrlookup($c->tx->remote_address, @acl_rt)) {
        return render_error($c, 403, 'Forbidden');
    }
    my $hdr_token = $c->req->headers->header('X-API-Token') // '';
    my $bearer    = ($c->req->headers->authorization // '') =~ /^Bearer\s+(.+)/i ? $1 : '';
    my $token     = $hdr_token || $bearer;
    unless (secure_compare($token, $api_token)) {
        return render_error($c, 401, 'Unauthorized');
    }
};

# Logger
setup_logger();

# Start
my $listen_addr = app->config->{global}{listen} // '0.0.0.0:5000';
my $url = "http://$listen_addr";
app->log->info("HEC Postfix Agent v" . VERSION . " listens at $url");
app->start('daemon', '-l', $url);
