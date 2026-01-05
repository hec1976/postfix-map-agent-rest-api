#!/usr/bin/env perl
# Config Manager - REST (Mojo-optimiert, actions schema, hardened)
# Version: 1.7.5 (2026-01-05)
#
# FIX 1.7.5:
# - FIX: parse_postmulti_status erkennt nun Instanz-Präfixe (z.B. postfix-xxxx/...)
# - IMPROVE: Fallback auf RC=0 bei Status-Abfrage#
#
# FIX 1.7.4:
# - FIX: postmulti actions now re-check status after stop/start/reload
# - FIX: postmulti status parsed from output, not exit code
#
# Changelog 1.7.3:
# - REMOVE: Time::HiRes (steady_time aus Mojo::Util reicht)
# - REMOVE: POSIX::strftime (Mojo::Date für Zeitstempel)
# - REMOVE: _fsync_dir (atomares move_to macht es überflüssig)
# - REFACTOR: Pfad-Kanonisierung mit path($p)->realpath
# - KEEP: shellwords aus Text::ParseWords (nicht in Mojo::Util verfügbar)
# - FIX: daemon-reload fuehrt jetzt systemctl daemon-reload aus (nicht restart)
# - FIX: STDIN Redirect in _systemctl_promise mit sauberem open()
# - FIX: make_path Nutzung kompatibler gemacht (ohne mode-Argumente, chmod danach)
# - CLEANUP: read_all Wrapper entfernt, direkt path(...)->slurp
# - KEEP: Alle Features aus 1.7.2

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::Promise;
use Mojo::Util qw(secure_compare steady_time);
use Mojo::JSON qw(decode_json encode_json);
use Mojo::Date;

use FindBin qw($Bin);
use Net::CIDR ();
use Text::ParseWords qw(shellwords);

use IPC::Open3;
use Symbol qw(gensym);

# Schutzmechanismus, um mehrfache Deklarationen zu vermeiden
{
    # ---------------- Umask (grundlegend) ----------------
    umask 0007;

    # ---------------- Version & Globale Variablen ----------------
    our $VERSION = '1.7.5';

    our $globalfile  = "$Bin/global.json";
    our $configsfile = "$Bin/configs.json";

    # ---------------- Systemctl (konfigurierbar) ----------------
    our $SYSTEMCTL       = '/usr/bin/systemctl';
    our $SYSTEMCTL_FLAGS = '';

    # ---------------- Logging (Mojolicious) ----------------
    our $log = Mojo::Log->new;
    $log->level('info');

    # ---------------- Konfiguration laden ----------------

    our $global = eval { decode_json(path($globalfile)->slurp) };
    die "global.json ungueltig: $@" if $@ || ref($global) ne 'HASH';

    our $configs = eval { decode_json(path($configsfile)->slurp) };
    die "configs.json ungueltig: $@" if $@ || ref($configs) ne 'HASH';

    # Systemctl-Konfiguration ueberschreiben, falls definiert
    $SYSTEMCTL       = $global->{systemctl} if defined $global->{systemctl} && $global->{systemctl} ne '';
    $SYSTEMCTL_FLAGS = exists $ENV{SYSTEMCTL_FLAGS}
        ? $ENV{SYSTEMCTL_FLAGS}
        : (defined $global->{systemctl_flags} ? $global->{systemctl_flags} : '');

    # ---------------- Logging-Konfiguration ----------------
    our $logfile = $global->{logfile} // "/var/log/config-manager.log";
    our $logdir  = path($logfile)->dirname;

    unless (-d $logdir) {
        eval { $logdir->make_path; 1 };
    chmod 0755, $logdir->to_string if -d $logdir->to_string;
    }

    if (-d $logdir) {
        $log->path($logfile);
        $log->info("Logging in Datei $logfile aktiviert.");
    } else {
        $log->warn("Konnte Log-Verzeichnis $logdir nicht nutzen. Logging auf STDERR.");
    }

    # ---------------- Mojolicious Secrets ----------------
    our $sec = $global->{secret};
    our @secrets = ref($sec) eq 'ARRAY' ? @$sec : ($sec // 'change-this-long-random-secret-please');
    app->secrets(\@secrets);

    if (grep { defined($_) && $_ eq 'change-this-long-random-secret-please' } @secrets) {
        $log->warn('[config-manager] WARNING: Standard-Mojolicious Secret wird verwendet! Bitte in global.json anpassen.');
    }

    # ---------------- Security & Verzeichnisse ----------------
    our $api_token   = defined $ENV{API_TOKEN} && $ENV{API_TOKEN} ne '' ? $ENV{API_TOKEN} : $global->{api_token};
    our $allowed_ips = $global->{allowed_ips} // [];
    $allowed_ips = [] unless ref($allowed_ips) eq 'ARRAY';

    our $tmpDir     = $global->{tmpDir}    // "$Bin/tmp";
    our $backupRoot = $global->{backupDir} // "$Bin/backup";

    # Verzeichnisse erstellen, falls nicht vorhanden
    eval { path($backupRoot)->make_path; 1 } or die "Backup-Verzeichnis $backupRoot fehlt/nicht erstellbar";
    chmod 0750, $backupRoot if -d $backupRoot;
    eval { path($tmpDir)->make_path; 1 }     or die "Tmp-Verzeichnis $tmpDir fehlt/nicht erstellbar";
    chmod 0750, $tmpDir if -d $tmpDir;

    our $maxBackups          = $global->{maxBackups} // 10;
    our $path_guard          = lc($ENV{PATH_GUARD} // ($global->{path_guard} // 'off'));
    our $apply_meta_enabled  = $global->{apply_meta}          // 0;
    our $auto_create_backups = $global->{auto_create_backups} // 0;

    # ---------------- Erlaubte Pfadwurzeln ----------------
    our @ALLOWED_CANON = ();
    if (ref($global->{allowed_roots}) eq 'ARRAY') {
        my %seen;
        for my $r (@{$global->{allowed_roots}}) {
            for my $cr (_canon_root($r)) {
                next if $seen{$cr}++;
                push @ALLOWED_CANON, $cr;
            }
        }
    }
    if (@ALLOWED_CANON) { $log->info('ALLOWED_ROOTS=' . join(',', @ALLOWED_CANON)); }
    else { $log->info('ALLOWED_ROOTS=(leer)'); }

    # ==================================================
    # HILFSFUNKTIONEN
    # ==================================================

    # --- Pfad-Kanonisierung ---
    sub _canon_root {
        my ($p) = @_;
        return () unless defined $p && length $p;
        my $rp = path($p)->realpath;
        return () unless defined $rp && length $rp;
        $rp =~ s{/*$}{};
        $rp .= '/';
        return $rp;
    }

    sub _canon_dir_of_path {
        my ($p) = @_;
        return () unless defined $p && length $p;
        my $rp = -e $p ? path($p)->realpath : path($p)->dirname->realpath;
        return () unless defined $rp && length $rp;
        $rp =~ s{/*$}{};
        $rp .= '/';
        return $rp;
    }

    # --- Berechtigungen ---
    sub _mode_str {
        my ($p) = @_;
        return undef unless -e $p;
        return sprintf('%04o', (stat($p))[2] & 07777);
    }

    sub _cur_umask {
        my $o = umask();
        umask($o);
        return $o;
    }

    # --- Pfadpruefung ---
    sub _is_allowed_path {
        my ($p) = @_;
        return 0 if -l $p;
        return 1 if $path_guard eq 'off';

        return ($path_guard eq 'audit')
            ? do { $log->warn("PATH-GUARD audit: keine allowed_roots"); 1 }
            : 0
            unless @ALLOWED_CANON;

        my $dircanon = _canon_dir_of_path($p);
        return 0 unless $dircanon;

        for my $root (@ALLOWED_CANON) {
            return 1 if ($dircanon eq $root) || (index($dircanon, $root) == 0);
        }

        if ($path_guard eq 'audit') {
            $log->warn("PATH-GUARD audit: $p ausserhalb allowed_roots");
            return 1;
        }
        return 0;
    }

    # --- Benutzer/Gruppen-IDs ---
    sub _name2uid {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getpwnam($n))[2]);
    }
    sub _name2gid {
        my ($n) = @_;
        return undef unless defined $n && length $n;
        return $n =~ /^\d+$/ ? 0 + $n : scalar((getgrnam($n))[2]);
    }

    # --- Metadaten anwenden ---
    sub _apply_meta {
        my ($e, $p) = @_;

        my $auto_wanted = (defined $e->{user} || defined $e->{group} || defined $e->{mode}) ? 1 : 0;
        my $enabled = defined $e->{apply_meta} ? $e->{apply_meta} : ($apply_meta_enabled || $auto_wanted);

        unless ($enabled) { $log->info("APPLY_META uebersprungen (deaktiviert) fuer Pfad=$p"); return; }

        die "Pfad nicht erlaubt" unless _is_allowed_path($p);
        die "Symlinks werden abgelehnt" if -l $p;

        my $uid = _name2uid($e->{user});
        my $gid = _name2gid($e->{group});

        my $mode;
        if (defined $e->{mode}) {
            my $m = "$e->{mode}";
            $m =~ s/^0+//;
            die "Ungueltiger Modus: $e->{mode}" unless $m =~ /^[0-7]{3,4}$/;
            $mode = oct($m);
        }

        if (defined $uid || defined $gid) {
            my $u = defined($uid) ? $uid : -1;
            my $g = defined($gid) ? $gid : -1;
            chown($u, $g, $p) or die "chown fehlgeschlagen: $!";
        }
        chmod($mode, $p) if defined $mode;
        return;
    }

    # --- Backup-Verzeichnis ---
    sub _backup_dir_for {
        my ($name) = @_;
        my $sub = $name;
        $sub =~ s{[^A-Za-z0-9._-]+}{_}g;
        return "$backupRoot/$sub";
    }

    # --- systemctl mit Subprocess, nonblocking, sauberer Timeout ---
    sub _systemctl_promise {
        my ($timeout, @cmd) = @_;
        $timeout = 30 unless defined $timeout && $timeout =~ /^\d+$/;

        return Mojo::Promise->new(sub {
            my ($resolve, $reject) = @_;

            Mojo::IOLoop->subprocess(
                sub {
                    my ($subprocess) = @_;

                    local $SIG{ALRM} = sub { die "__TIMEOUT__\n" };
                    alarm $timeout;

                    open(STDIN, '<', '/dev/null') or die "open /dev/null: $!";

                    system @cmd;

                    alarm 0;
                    return $?;
                },
                sub {
                    my ($subprocess, $err, $raw_rc) = @_;

                    if (defined $err && length $err) {
                        if ($err =~ /__TIMEOUT__/) {
                            $log->warn("systemctl Timeout nach ${timeout}s: @cmd");
                            return $resolve->(-1);
                        }
                        $log->error("systemctl Subprocess Fehler: $err cmd=@cmd");
                        return $reject->($err);
                    }

                    $raw_rc //= 0;

                    if (($raw_rc & 127) > 0) {
                        my $sig = $raw_rc & 127;
                        $log->warn("systemctl mit Signal $sig beendet: @cmd");
                        return $resolve->(128 + $sig);
                    }

                    my $rc = ($raw_rc >> 8);
                    return $resolve->($rc);
                }
            );
        });
    }

    # --- Skript-Ausfuehrung mit Promise ---
    sub _script_promise {
        my ($c, @argv) = @_;

        return Mojo::Promise->new(sub {
            my ($resolve) = @_;

            Mojo::IOLoop->subprocess(
                sub {
                    my ($subprocess) = @_;
                    $subprocess->system(@argv);
                },
                sub {
                    my ($subprocess, $err, @results) = @_;
                    $resolve->($subprocess->exit_code);
                }
            );
        });
    }

	sub _capture_cmd_promise {
		my ($timeout, @cmd) = @_;
		$timeout = 10 unless defined $timeout && $timeout =~ /^\d+$/;

		return Mojo::Promise->new(sub {
			my ($resolve) = @_;
			Mojo::IOLoop->subprocess(
				sub {
					local $SIG{ALRM} = sub { die "__TIMEOUT__\n" };
					alarm $timeout;

					# Setze einen Standard-Pfad, damit postmulti alle Postfix-Tools findet
					local $ENV{PATH} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
					
					# Führe den Befehl aus und fange STDOUT + STDERR ein
					# Wir bauen den Befehl sicher zusammen
					my $cmd_line = join(' ', map { "'$_'" } @cmd) . ' 2>&1';
					my $output = `$cmd_line`; 
					my $rc = ($? >> 8);
					
					alarm 0;
					return { rc => $rc, out => $output // "" };
				},
				sub {
					my ($subprocess, $err, $res) = @_;
					$res ||= { rc => -1, out => $err // "unknown error" };
					$resolve->($res);
				}
			);
		});
	}

    # --- Konfigurations-Mapping ---
    our %cfgmap;

    sub _derive_actions {
        my ($entry) = @_;
        my %actions;

        if (ref($entry->{actions}) eq 'HASH') {
            while (my ($k, $v) = each %{$entry->{actions}}) {
                $actions{$k} = (ref($v) eq 'ARRAY') ? [@$v] : [];
            }
            return \%actions;
        }

        if (ref($entry->{commands}) eq 'HASH') {
            while (my ($k, $v) = each %{$entry->{commands}}) {
                $actions{$k} = (ref($v) eq 'ARRAY') ? [@$v] : [];
            }
            return \%actions;
        }

        if (ref($entry->{command_args}) eq 'HASH') {
            my @tokens = ref($entry->{commands}) eq 'ARRAY' ? @{$entry->{commands}} : keys %{$entry->{command_args}};
            for my $t (@tokens) {
                my $arr = $entry->{command_args}{$t};
                $actions{$t} = (ref($arr) eq 'ARRAY') ? [@$arr] : [];
            }
            return \%actions;
        }

        if (ref($entry->{commands}) eq 'ARRAY' && grep { $_ eq 'run' } @{$entry->{commands}}) {
            $actions{run} = [];
        }

        return \%actions;
    }

    sub _rebuild_cfgmap_from {
        my ($cfg) = @_;
        %cfgmap = ();

        while (my ($name, $entry) = each %{$cfg}) {
            next if !defined $name || $name =~ m{[/\\]} || $name =~ m{\.\.};

            my $actions = _derive_actions($entry);

            $cfgmap{$name} = {
                %$entry,
                id         => $name,
                service    => $entry->{service}  // $name,
                category   => $entry->{category} // 'uncategorized',
                path       => $entry->{path},
                actions    => $actions,
                backup_dir => _backup_dir_for($name),
            };
        }
        return;
    }

    # --- Atomares Schreiben ---
    sub write_atomic {
        my ($p, $bytes) = @_;
        my $file = path($p);
        my $tmp  = $file->dirname->child(".tmp_" . $file->basename . ".$$");
        $tmp->spurt($bytes);
        $tmp->move_to($file);
        return 'atomic';
    }

    sub safe_write_file {
        my ($p, $bytes) = @_;
        my $method = 'atomic';

        my $ok = eval { write_atomic($p, $bytes); 1 };
        if (!$ok) {
            $method = 'plain';
            path($p)->spew($bytes);
        }
        return $method;
    }

	sub parse_postmulti_status {
		my ($stdout, $stderr, $rc) = @_;
		my $txt = lc(($stdout // "") . ($stderr // ""));

		# Suche einfach nach den Schlüsselwörtern, egal wo sie stehen
		if ($txt =~ /is\s+running/ || $txt =~ /pid:\s*\d+/) {
			return "running";
		}
		
		if ($txt =~ /not\s+running/ || $txt =~ /inactive/ || $txt =~ /stopped/) {
			return "stopped";
		}

		# Wenn der Output leer ist (out=), vertrauen wir dem Exit-Code:
		# Postfix status: 0 = running, 1 = stopped
		if (defined $rc) {
			return "running" if $rc == 0 && ($txt =~ /postfix/ || $txt eq "");
			return "stopped" if $rc == 1;
		}

		return "unknown";
	}

    # ==================================================
    # REQUEST-HELFER & ACCESS-CONTROL
    # ==================================================

    sub _req_meta {
        my ($c) = @_;
        return {
            req_id => $c->stash('req_id') // '',
            ip     => $c->stash('client_ip') // '',
            method => $c->req->method // '',
            path   => $c->req->url->path->to_string // '',
        };
    }

    sub _fmt_req {
        my ($c) = @_;
        my $m = _req_meta($c);
        return sprintf('req_id=%s ip=%s %s %s', $m->{req_id}, $m->{ip}, $m->{method}, $m->{path});
    }

    # --- Client-IP ---
    our %TRUSTED = map { $_ => 1 } (ref($global->{trusted_proxies}) eq 'ARRAY' ? @{$global->{trusted_proxies}} : ());

    sub _client_ip {
        my ($c) = @_;
        my $rip = $c->tx->remote_address // '';
        if ($TRUSTED{$rip}) {
            my $xff = $c->req->headers->header('X-Forwarded-For') // '';
            if ($xff) {
                my @ips = map { s/^\s+|\s+$//gr } split /,/, $xff;
                return $ips[0] // $rip;
            }
        }
        return $rip;
    }

    # --- CORS ---
    our %ALLOW_ORIGIN = map { $_ => 1 } (ref($global->{allow_origins}) eq 'ARRAY' ? @{$global->{allow_origins}} : ());

    # ==================================================
    # ROUTES
    # ==================================================

    # --- Root (mit Routen-Auflistung) ---
    get '/' => sub {
        my $c = shift;
        my @routes_list;

        foreach my $route (@{app->routes->children}) {
            next unless ref $route;
            my $methods = $route->via;
            my $method_str = (ref $methods eq 'ARRAY' && @$methods)
                ? join(', ', map { uc } @$methods)
                : 'ANY';
            my $p = $route->to_string;
            push @routes_list, { method => $method_str, path => $p };
        }

        @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

        $c->render(json => {
            ok            => 1,
            name          => 'config-manager',
            version       => $VERSION,
            api_endpoints => \@routes_list
        });
    };

    # --- Konfigurationen auflisten ---
    get '/configs' => sub {
        my $c = shift;
        my @list;

        for my $name (sort keys %cfgmap) {
            my $e = $cfgmap{$name};
            my $filename = path($e->{path})->basename;
            my ($ext) = $filename =~ /\.([^.]+)$/;
            my @tokens = sort keys %{$e->{actions} // {}};

            push @list, {
                id       => $name,
                filename => $filename,
                filetype => lc($ext // 'txt'),
                category => $e->{category},
                actions  => \@tokens
            };
        }

        $c->render(json => { ok => 1, configs => \@list });
    };

    # --- Konfiguration lesen ---
    get '/config/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        if ($name =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannt: $name" }, status => 404);
        my $p = $e->{path};

        return $c->render(json => { ok => 0, error => "Pfad nicht erlaubt" }, status => 400) unless _is_allowed_path($p);
        return $c->render(json => { ok => 0, error => "Datei fehlt: $p" }, status => 404) unless -f $p;

        my $data = path($p)->slurp;
        $c->res->headers->content_type('application/octet-stream');
        $c->render(data => $data);
    };

    # --- Konfiguration schreiben ---
    post '/config/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        if ($name =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannt: $name" }, status => 404);
        my $p = $e->{path};

        return $c->render(json => { ok => 0, error => "Pfad nicht erlaubt" }, status => 400) unless _is_allowed_path($p);

        my $content = $c->req->body // '';
        if (($c->req->headers->content_type // '') =~ m{application/json}i) {
            my $j = eval { $c->req->json };
            if (!$@ && ref($j) eq 'HASH' && exists $j->{content}) {
                $content = $j->{content} // '';
            }
        }

        my $bdir = $e->{backup_dir};

        unless (-d $bdir) {
            if ($auto_create_backups) {
                eval { path($bdir)->make_path; 1 };
        chmod 0750, $bdir if -d $bdir;
            }
            unless (-d $bdir) {
                return $c->render(json => { ok => 0, error => "Backup-Verzeichnis fehlt" }, status => 500);
            }
        }

		# Backup erstellen
		if (-f $p) {
			my $ts = Mojo::Date->new->to_datetime;

			# FIX 1.7.4: GUI Format YYYYMMDD_HHMMSS
			if ($ts =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
				$ts = "$1$2$3_$4$5$6";
			} else {
				# Fallback, falls Format anders ist
				$ts =~ s/[^0-9]//g;
				$ts = substr($ts, 0, 8) . "_" . substr($ts, 8, 6) if length($ts) >= 14;
			}

			my $bfile = "$bdir/" . path($p)->basename . ".bak.$ts";

			eval { path($p)->copy_to($bfile); 1 };

			my @b = sort { $b cmp $a } grep { defined } glob("$bdir/" . path($p)->basename . ".bak.*");
			if (@b > $maxBackups) {
				unlink @b[$maxBackups .. $#b];
			}
		}


        my $method;
        eval { $method = safe_write_file($p, $content); 1 }
            or return $c->render(json => { ok => 0, error => "Schreibfehler: $@" }, status => 500);

        my $meta_wanted = defined $e->{apply_meta}
            ? $e->{apply_meta}
            : ($apply_meta_enabled || defined($e->{user}) || defined($e->{group}) || defined($e->{mode}));

        eval { _apply_meta($e, $p); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = _mode_str($p);
        my ($uid, $gid)  = ((stat($p))[4], (stat($p))[5]);

        $c->render(json => {
            ok        => 1,
            saved     => $name,
            path      => $p,
            method    => $method,
            requested => {
                user       => $e->{user},
                group      => $e->{group},
                mode       => $e->{mode},
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false)
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    # --- Backups auflisten ---
    get '/backups/*name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        if ($name =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannte Konfiguration: $name" }, status => 404);

        my $bdir = $e->{backup_dir};
        return $c->render(json => { ok => 0, error => "Backup-Verzeichnis fehlt: $bdir" }, status => 500) unless -d $bdir;

        my $base = path($e->{path})->basename;
        my @files = sort { $b cmp $a } grep { defined } glob("$bdir/$base.bak.*");
        @files = map { s{^\Q$bdir\E/}{}r } @files;

        $c->render(json => { ok => 1, backups => \@files });
    };

    # --- Backup-Inhalt lesen ---
    get '/backupcontent/*name/*filename' => sub {
        my $c = shift;
        my $name = $c->stash('name');
        my $filename = $c->stash('filename');

        if ($name =~ m{[/\\]} || $filename =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name/Filename' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannte Konfiguration: $name" }, status => 404);

        my $bdir = $e->{backup_dir};
        my $base = path($e->{path})->basename;

        return $c->render(json => { ok => 0, error => 'Ungueltiger Backup-Name' }, status => 400)
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $file = "$bdir/$filename";
        return $c->render(json => { ok => 0, error => 'Backup nicht gefunden' }, status => 404) unless -f $file;

        my $content = path($file)->slurp;
        $c->render(json => { ok => 1, content => $content });
    };

    # --- Backup wiederherstellen ---
    post '/restore/*name/*filename' => sub {
        my $c = shift;
        my $name = $c->stash('name');
        my $filename = $c->stash('filename');

        if ($name =~ m{[/\\]} || $filename =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name/Filename' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannte Konfiguration: $name" }, status => 404);

        my $base = path($e->{path})->basename;
        my $bdir = $e->{backup_dir};

        return $c->render(json => { ok => 0, error => 'Ungueltiger Backup-Name' }, status => 400)
            unless $filename =~ /^\Q$base\E\.bak\.(\d{8}_\d{6}|\d{14}|\d+)$/;

        my $src  = "$bdir/$filename";
        my $dest = $e->{path};

        return $c->render(json => { ok => 0, error => 'Backup nicht gefunden' }, status => 404) unless -f $src;
        return $c->render(json => { ok => 0, error => 'Pfad nicht erlaubt' }, status => 400) unless _is_allowed_path($dest);

        path($src)->copy_to($dest)
            or return $c->render(json => { ok => 0, error => "Wiederherstellung fehlgeschlagen: $!" }, status => 500);

        eval { _apply_meta($e, $dest); 1 } or $log->warn("Fehler bei apply_meta: $@");

        my $applied_mode = _mode_str($dest);
        my ($uid, $gid)  = ((stat($dest))[4], (stat($dest))[5]);

        my $meta_wanted = defined $e->{apply_meta}
            ? $e->{apply_meta}
            : ($apply_meta_enabled || defined($e->{user}) || defined($e->{group}) || defined($e->{mode}));

        $c->render(json => {
            ok       => 1,
            restored => $name,
            from     => $filename,
            requested => {
                user       => $e->{user},
                group      => $e->{group},
                mode       => $e->{mode},
                apply_meta => ($meta_wanted ? Mojo::JSON::true : Mojo::JSON::false)
            },
            applied => { uid => $uid, gid => $gid, mode => $applied_mode }
        });
    };

    # --- Aktion ausfuehren (Promise-Kette mit catch) ---
    post '/action/*name/*cmd' => sub {
        my $c = shift;
        my ($name, $cmd) = ($c->stash('name'), $c->stash('cmd'));

        if (!defined $name || $name =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltige Anfrage' }, status => 400);
        }

        my $e = $cfgmap{$name} or return $c->render(json => { ok => 0, error => "Unbekannt" }, status => 404);

        my $svc    = $e->{service} // $name;
		my $is_postmulti = ($svc =~ m{^exec:/usr/sbin/postmulti$});
        my $actmap = $e->{actions};

        return $c->render(json => { ok => 0, error => 'Aktion nicht erlaubt' }, status => 400)
            unless ref($actmap) eq 'HASH' && exists $actmap->{$cmd};

        my @extra = @{$actmap->{$cmd}};
        for (@extra) {
            if ($_ !~ /^[A-Za-z0-9._:+@\/=\-,]+$/) {
                return $c->render(json => { ok => 0, error => "Ungueltiges Argument" }, status => 400);
            }
        }

        # Haupt-Promise fuer die gesamte Aktion
        my $action_promise;

        if ($cmd eq 'daemon-reload') {
            $action_promise = _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'daemon-reload');

        }
        elsif ($svc =~ m{^(bash|sh|perl|exec):(/.+)$}) {
            my ($runner, $script) = ($1, $2);
            return $c->render(json => { ok => 0, error => "Skript nicht gefunden: $script" }, status => 404) unless -f $script;

            if ($runner eq 'exec' && $script =~ m{/systemctl$}) {
                return $c->render(json => { ok => 0, error => 'Subcommand verboten' }, status => 400)
                    if ($extra[0] // '') =~ /^(poweroff|reboot|halt)$/;
            }

            my @argv =
                  $runner eq 'perl' ? ('/usr/bin/perl', $script, @extra)
                : $runner eq 'bash' ? ('/bin/bash', $script, @extra)
                : $runner eq 'sh'   ? ('/bin/sh',   $script, @extra)
                :                    ($script, @extra);

            $action_promise = _script_promise($c, @argv);
        }
        elsif ($svc eq 'systemctl') {
            # FIX 1.7.1: service="systemctl" bedeutet "systemctl <cmd> <extra...>"
            if ($cmd =~ /^(poweroff|reboot|halt)$/) {
                return $c->render(json => { ok => 0, error => 'Verboten' }, status => 400);
            }
            $action_promise = _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), $cmd, @extra);
        }
        elsif ($cmd eq 'stop_start') {
            $action_promise =
                _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'stop', $svc)
                ->then(sub {
                    return _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'start', $svc);
                });
        }
        elsif ($cmd eq 'restart') {
            $action_promise = _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'restart', $svc);
        }
        elsif ($cmd eq 'reload') {
            $action_promise =
                _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'is-active', $svc)
                ->then(sub {
                    my ($rc) = @_;
                    if ($rc == 0) {
                        return _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'reload', $svc);
                    }
                    return Mojo::Promise->reject("Dienst nicht aktiv");
                });
        }
        else {
            $action_promise = _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), $cmd, $svc);
        }

        $action_promise
            ->then(sub {
                my ($rc) = @_;

                if ($cmd eq 'daemon-reload' || $svc eq 'systemctl') {
                    $c->render(json => $rc == 0 ? { ok => 1 } : { ok => 0, error => "Rueckgabewert=$rc" });
                }
                elsif ($svc =~ m{^(bash|sh|perl|exec):} && ($extra[0] // '') eq 'is-active') {
                    $c->render(json => { ok => 1, status => ($rc == 0 ? 'running' : 'stopped'), rc => $rc });
                }
                elsif ($cmd eq 'stop_start' || $cmd eq 'restart' || $cmd eq 'reload') {
                    return _systemctl_promise(30, $SYSTEMCTL, shellwords($SYSTEMCTL_FLAGS // ''), 'is-active', $svc)
                        ->then(sub {
                            my ($active_rc) = @_;
                            $c->render(json => {
                                ok     => 1,
                                action => $cmd,
                                status => ($active_rc == 0 ? 'running' : 'stopped')
                            });
                        });
                }
				else {
					if ($is_postmulti) {

						my ($bin) = ($svc =~ m{^exec:(/.+)$});
						
						# VERSUCH: Sudo hinzufügen, falls rc=1 & out=empty ein Dauerzustand ist
						# Wenn du kein sudo brauchst, nimm es aus dem Array raus.
						my @status_args = ('/usr/bin/sudo', $bin, '-i', $name, '-p', 'status');

						if ($cmd eq 'stop' || $cmd eq 'start' || $cmd eq 'reload') {
							select(undef, undef, undef, 0.5);
						}

						return _capture_cmd_promise(10, $bin, @status_args)
							->then(sub {
								my ($res) = @_;

								$log->info("postmulti status output name=$name rc=$res->{rc} out=" . ($res->{out} // ''));
								my $state = parse_postmulti_status($res->{out}, '', $res->{rc});

								my $ok = 0;
								if ($cmd eq 'stop') {
									$ok = ($state eq 'stopped') ? 1 : 0;
								} elsif ($cmd eq 'status') {
									$ok = 1;
								} else {
									$ok = ($state eq 'running') ? 1 : 0;
								}

								$c->render(json => {
									ok     => $ok,
									action => $cmd,
									state  => $state,
									rc     => $res->{rc},
									output => $res->{out},
								});
							});

					}

					# Default-Verhalten (alles andere)
					$c->render(json => {
						ok => ($rc == 0 ? 1 : 0),
						rc => $rc,
						($rc != 0 ? (error => "Fehler bei $cmd") : ())
					});

				}

            })
            ->catch(sub {
                my ($err) = @_;
                $log->error("Fehler bei Aktion $cmd: $err");
                $c->render(json => { ok => 0, error => "Interner Fehler: $err" }, status => 500);
            });
    };

    # --- Raw configs ---
    get '/raw/configs' => sub { shift->render(data => path($configsfile)->slurp); };

    post '/raw/configs' => sub {
        my $c = shift;
        my $raw = $c->req->body // '';

        eval { decode_json($raw); 1 }
            or return $c->render(json => { ok => 0, error => 'Ungueltiges JSON' }, status => 400);

        safe_write_file($configsfile, $raw);

        my $newcfg = decode_json($raw);
        _rebuild_cfgmap_from($newcfg);

        $c->render(json => { ok => 1, reload => 1 });
    };

    post '/raw/configs/reload' => sub {
        my $c = shift;
        my $cfg = eval { decode_json(path($configsfile)->slurp) }
            or return $c->render(json => { ok => 0, error => 'JSON-Fehler' }, status => 500);

        _rebuild_cfgmap_from($cfg);
        $c->render(json => { ok => 1, reloaded => 1 });
    };

    del '/raw/configs/:name' => sub {
        my $c = shift;
        my $name = $c->stash('name');

        if ($name =~ m{[/\\]}) {
            return $c->render(json => { ok => 0, error => 'Ungueltiger Name' }, status => 400);
        }

        my $cfg = decode_json(path($configsfile)->slurp);
        return $c->render(status => 404, json => { ok => 0 }) unless delete $cfg->{$name};

        safe_write_file($configsfile, encode_json($cfg));
        _rebuild_cfgmap_from($cfg);

        $c->render(json => { ok => 1 });
    };

    # --- Health-Check ---
    get '/health' => sub { shift->render(json => { ok => 1, status => 'ok' }); };

    # --- 404 ---
    any '/*whatever' => sub { shift->render(json => { ok => 0, error => '404 Not Found' }, status => 404); };

    # ---------------- Hooks ----------------
    app->hook(before_dispatch => sub {
        my $c = shift;
        $c->stash(req_id => sprintf('%x-%x', int(time() * 1000), $$));
        $c->stash(t0     => steady_time());
        $c->stash(client_ip => _client_ip($c));

        my $origin = $c->req->headers->origin // '*';
        if (%ALLOW_ORIGIN) {
            $c->res->headers->header('Access-Control-Allow-Origin' => ($ALLOW_ORIGIN{$origin} ? $origin : 'null'));
        } else {
            $c->res->headers->header('Access-Control-Allow-Origin' => $origin);
        }
        $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS');
        $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, X-API-Token, Authorization');
        $c->res->headers->header('Access-Control-Max-Age'       => '86400');

        $log->info(sprintf('REQUEST %s', _fmt_req($c)));
        return $c->render(text => '', status => 204) if $c->req->method eq 'OPTIONS';

        # IP-ACL
        if ($allowed_ips && @{$allowed_ips}) {
            my $rip = $c->stash('client_ip') // '';
            unless (Net::CIDR::cidrlookup($rip, @{$allowed_ips})) {
                $log->info(sprintf('REQUEST %s -> 403 Forbidden', _fmt_req($c)));
                return $c->render(status => 403, json => { ok => 0, error => 'Forbidden' });
            }
        }

        # Token-Auth (mit secure_compare)
        if (defined $api_token && length $api_token) {
            my $hdr    = $c->req->headers->header('X-API-Token') // '';
            my $auth   = $c->req->headers->authorization // '';
            my $bearer = $auth =~ /^Bearer\s+(.+)/i ? $1 : '';
            my $token  = $hdr || $bearer;

            unless ($token && secure_compare($token, $api_token)) {
                $log->info(sprintf('REQUEST %s -> 401 Unauthorized', _fmt_req($c)));
                return $c->render(status => 401, json => { ok => 0, error => 'Unauthorized' });
            }
        }
    });

    app->hook(after_dispatch => sub {
        my $c = shift;
        my $t0 = $c->stash('t0') // steady_time();
        my $dt = steady_time() - $t0;
        my $code = $c->res->code // 200;
        $log->info(sprintf('RESPONSE %s status=%d time=%.3fs', _fmt_req($c), $code, $dt));
    });

    # ---------------- Initialisierung ----------------
    _rebuild_cfgmap_from($configs);

    $log->info(sprintf(
        'START version=%s umask=%04o path_guard=%s apply_meta=%d entries=%d',
        $VERSION, _cur_umask(), $path_guard, ($apply_meta_enabled ? 1 : 0), scalar(keys %cfgmap)
    ));

    # ---------------- Server starten ----------------
    my $listen_url = "http://$global->{listen}";
    if ($global->{ssl_enable}) {
        $listen_url = "https://$global->{listen}?cert=$global->{ssl_cert_file}&key=$global->{ssl_key_file}";
    }
    app->start('daemon', '-l', $listen_url);		
}
