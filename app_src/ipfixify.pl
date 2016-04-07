#!perl

package PerlSvc;

use strict;
use Class::Load::XS;
use Data::Dumper;
use Date::Parse;
use Getopt::Long;
use ipfixify::definitions;
use ipfixify::help;
use ipfixify::ipfix;
use ipfixify::parse;
use ipfixify::sysmetrics;
use ipfixify::util;
use Net::Ping;
use Net::Syslog;
use Plixer::Net::Packet;
use Plixer::Process;
use POE;
use POE qw/Wheel::FollowTail/;
use POE::Component::Server::Syslog;
use POE::Driver::SysRW;
use POE::Filter::Line;
use POE::Filter::Reference;
use POE::Loop::Select;
use POE::Pipe::TwoWay;
use POE::Resource::Aliases;
use POE::Resource::Events;
use POE::Resource::Extrefs;
use POE::Resource::FileHandles;
use POE::Resource::Sessions;
use POE::Resource::SIDs;
use POE::Resource::Signals;
use POE::Session;
use POE::Wheel;
use POE::Wheel::ReadWrite;
use POE::Wheel::Run;
use POE::Wheel::SocketFactory;
use POE::Wheel::FollowTail;
use Socket;
use Time::HiRes;
use WWW::ipinfo;

use if $^O eq 'MSWin32', 'Win32::API';
use if $^O eq 'MSWin32', 'Plixer::EventLog';
use if $^O eq 'MSWin32', 'DBD::WMI';
use if $^O eq 'linux', 'Net::SSH::Expect';

$| = 1;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent = 1;

## DECLARE GLOBALS AND DEFAULTS ##

our ($syslogCount);
our (%Config, %file, %flowCache, %active);

my (%cfg, %thread, %delta);
my (@eventLogToGather, @goodList);
my (
	$config, $eventlog, $filename, $svc, $svcName, $syslog, $stream,
	$version, $testOnly, $verbose, $hostip, $originator, $CwF,
	$CwFTime, $sysmetrics, $psexec, $syspoll, $sourceip,
	$streamCollectors, $queueSysMetricGather, $queueSysMetricDevices,
	$shared_flowCache6, $honeynet, $syslogSend, $smPermTest, $ipinfo
);

$verbose			= 0;
$hostip				= &Plixer::Net::Packet::getAdapterInfo();
$originator			= $hostip->{'ip'};
$version			= &ipfixify::definitions::defVersionInfo();
@eventLogToGather	= ('1:SYSTEM','2:SECURITY','3:APPLICATION');

## DONE DECLARING GLOBALS AND DEFAULTS ##

unless (defined &ContinueRun) {
	*ContinueRun = sub {
		return 1
	};
	*RunningAsService = sub {return 0};
	&cliRun();
}

sub PerlSvc::Startup() {
	chdir(File::Spec->catdir((File::Spec->splitpath(&s_exe()))[0,1]) );
	ipfixifyStartup();
}

sub cliRun {
	PerlSvc::Interactive();
}

sub PerlSvc::Interactive() {
	chdir(File::Spec->catdir((File::Spec->splitpath(&s_exe()))[0,1]) );
	ipfixifyStartup();
}

if (! defined $PerlSvc::VERSION){
	PerlSvc::Interactive();
}

sub ipfixifyStartup {
	my ($eventlog, $fPath, $fFile);

	&ipfixify::help::mainHelp(version => $version) if (! $ARGV[0]);

  ## GET COMMAND LINE OPTIONS ##
	GetOptions(
		'config=s'		=> \$config,
		'debug+'		=> \$verbose,
		'file=s'		=> \$filename,
		'help|?'		=> sub {
							&ipfixify::help::mainHelp(
								version => $version
							)
						},
		'honeynet=s'	=> \$honeynet,
		'import=s'		=> sub {
							my (undef, $dbString) = @_;
							&ipfixify::util::scrutImport(
								version => $version,
								import	=> $dbString
							);
						},
		'name=s'		=> \$svcName,
		'autostart=s'	=> \$svc,
		'credentials=s'	=> sub {
			my (undef, $credentials) = @_;
			my $original = $credentials;

			if ( $^O eq 'MSWin32' && ! -e $credentials ) {
				$credentials = Win32::GetShortPathName( $credentials );
			}

			&ipfixify::util::scrutCfgCredentials(
				version		=> $version,
				config		=> $credentials,
				original	=> $original
			);
		},
		'sourceip=s'	=> \$sourceip,
		'sysmetrics+'	=> \$sysmetrics,
		'permtest=s'	=> \$smPermTest,
		'syspoll=s'		=> \$syspoll,
		'stream=s'		=> \$stream,
		'psexec=s'		=> \$psexec,
		'sendto=s'		=> \$streamCollectors,
		'syslog=s'		=> \$syslog,
		'test|t'		=> \$testOnly,
		'verbose+'		=> \$verbose,
		'version'		=> sub { print "\n$version\n"; exit(0); }
	);

	if ( $^O eq 'MSWin32' ) {
		### BUG 11854 - specific support for 8.3 and wildcards in filefollow
		my (@filepath);
		my ($wildcard);

		$config = Win32::GetShortPathName( $config );

		if ($filename =~ m/\*/) {
			@filepath = split (/\\\\|\\|\//, $filename);
			$wildcard = pop(@filepath);
			$filename = join ('\\', @filepath);
		}

		$filename = Win32::GetShortPathName( $filename );

		if ($wildcard) {
			$filename .= "/$wildcard";
		}

		$psexec = Win32::GetShortPathName( $psexec );
	}

  ## VERIFY WE HAVE EVERYTHING IN ORDER ##
	%cfg = &ipfixify::parse::cfgCheck(
		'autostart'	=> $svc,
		'svcName'	=> $svcName,
		'config'	=> $config,
		'filename'	=> $filename,
		'syslog'	=> $syslog,
		'stream'	=> $stream,
		'sendto'	=> $streamCollectors,
		'sysmetrics'=> $sysmetrics,
		'permtest'	=> $smPermTest,
		'version'	=> $version,
		'test'		=> $testOnly,
		'verbose'	=> $verbose,
		'originator'=> $originator,
		'sourceip'	=> $sourceip,
		'psexec'	=> $psexec,
		'syspoll'	=> $syspoll,
		'honeynet'	=> $honeynet,
	);

	# BUG 15625 (LINUX BUG 18969)
	if ($smPermTest && $cfg{'mode'} eq 'sysmetrics') {
		if ($sourceip) {
			$originator = $sourceip;
		}

		&ipfixify::util::testSysMetrics
		  (
		   cfg			=> \%cfg,
		   host			=> $smPermTest,
		   orginator	=> $originator,
		   eventlogs	=> \@eventLogToGather,
		   verbose		=> $verbose
		  );
		exit(0);
	}

	# BUG 15058
	if ($cfg{'usernamesOnly'}) {
		print "\n+ collecting username data from eventlogs only\n" if ($verbose);
		@eventLogToGather = ('2:SECURITY');
	}

  ## CREATE DATA AND OPTION TEMPLATES ##
	if ($cfg{'mode'} eq 'sysmetrics' || $syspoll) {
		my $tmpdir = './ipfixify.tmp';
		mkdir ($tmpdir, 0777);
		$ENV{'TMP'} = $tmpdir;
		$ENV{'TMPDIR'} = $tmpdir;
		$ENV{'TEMP'} = $tmpdir;

		if ($sourceip) {
			$originator = $sourceip;
		}

		if (! $syspoll) {
			require threads;
			threads->import();
			require Thread::Queue;
			Thread::Queue->import();

			my ($dh, $tmpdir);
			my (@queue);

			$queueSysMetricGather	= new Thread::Queue();
			$queueSysMetricDevices	= new Thread::Queue();
			$shared_flowCache6		= new Thread::Queue();

			opendir ($dh, $ENV{'TMPDIR'});
			@queue = readdir($dh);
			closedir $dh;

			foreach (@queue) {
				unlink "$ENV{'TMPDIR'}/$_" unless ($_ =~ m/^\./);
			}

			unlink "$ENV{'TMPDIR'}/sysmetrics.db"
			  if (-e "$ENV{'TMPDIR'}/sysmetrics.db");

			eval {
				$ipinfo	= get_ipinfo();

				open ($dh, '>', "$ENV{'TMPDIR'}/gps.txt");
				print $dh "$ipinfo->{loc}";
				close($dh);
			};

			foreach my $thr (1..$cfg{'pollthreads'}){
				my $thread = threads->create
				  ({
					'stack_size'	=> 64*4096,
					'context'		=> 'void'
				   },
				   \&pollSysMetricsHost,
				   $thr
				  );
				print "\n+ Started pollSysMetricsHost thread $thr\n" if ($verbose);
			}
		}

		foreach my $cache (1..8,20,26,27,28,113,114) {
			%{$flowCache{$cache}} = &ipfixify::definitions::tempSelect(
				flowCache => $cache
			);
		}
	} elsif ($cfg{'mode'} eq 'stream') {
		foreach my $cache (11,13,14,18) {
			%{$flowCache{$cache}} = &ipfixify::definitions::tempSelect(
				flowCache => $cache
			);
		}
	} elsif ($cfg{'mode'} eq 'honeynet') {
		%{$flowCache{'25'}} = &ipfixify::definitions::tempSelect(
			flowCache => 25
		);

		my ($ip, $port) = &ipfixify::util::getIpPort(
			check => $streamCollectors
		);

		$syslogSend = new Net::Syslog(
			SyslogPort => $port,
			SyslogHost => $ip
		);
	} else {
		$flowCache{'0'}{'columns'} = $cfg{'columns'};
	}

	if ($syspoll) {
	  ### THIS METHOD RELIES ON LAUNCHING THE SYSPOLL EXTERNALLY
	  ### INSTEAD OF THROUGH THREADS. THREADS ARE EVIL
		open (my $dh, '<', "$ENV{'TMPDIR'}/gps.txt");
		my $gps = <$dh>;
		close($dh);

		if ($cfg{'pingtimeout'}) {
			my ($computer, $threadID, $p, $port, $pass);
			($computer, $threadID) = split (/::/, $syspoll);

			$port = $^O eq 'MSWin32' ? '135' : '22';

			$p = Net::Ping->new();
			$p->bind($originator);
			$p->port_number($port,'tcp');
			$pass = $p->ping($computer, $cfg{'pingtimeout'});
			$p->close();

			exit(99) if (! $pass);
		}

		if ($^O eq 'MSWin32') {
			&pollSysMetricsWindowsEndpoint
			  (
			   syspoll		=> $syspoll,
			   gps			=> $gps || '0,0',
			   verbose		=> $verbose,
			   originator	=> $originator
			  );
		} elsif ($^O eq 'linux') {
			&pollSysMetricsLinuxEndpoint
			  (
			   syspoll		=> $syspoll,
			   gps			=> $gps || '0,0',
			   verbose		=> $verbose,
			   originator	=> $originator
			  );
		}

		exit(0);
	}

	if ($verbose) {
		print "\n+ collection timeout set to $cfg{'pollTimeOut'} second(s)\n" if ($cfg{'pollTimeOut'});
		print "\n+ platform $^O detected\n";
		print "\n+ tempdir is $ENV{'TMPDIR'}\n" if ($cfg{'mode'} eq 'sysmetrics');
	}

  ## OPEN SOCKET(S) TO SEND FLOWS ##
	foreach (@{$cfg{'collector'}}) {
		my ($ip, $port) = &ipfixify::util::getIpPort(
			check => $_
		);

		print "\n+ Opening sending socket for $ip:$port\n"
		  if ($verbose && ! $syspoll);

		$flowCache{'fdh'}{"${_}-SELF"} = &ipfixify::ipfix::setupFdh(
			ip		=> $ip,
			port	=> $port,
			spoof	=> $cfg{'sourceip'} || '',
		);
	}

  ## BEGIN ALL NON-SYSPOLL MODES ##
	while(&ContinueRun()) {
		POE::Session->create (
			inline_states => {
				_start => sub {
					$_[KERNEL]->alarm(heartbeatSvc => time());
					$_[KERNEL]->alarm(sendFlowCache => time() + 10);
					$_[KERNEL]->alarm(optionTpl => time());
					$_[KERNEL]->alarm(maintenance => time() + 600);

					print "\n+ Starting $cfg{'mode'} Mode\n\n" if ($verbose);

					if ($cfg{'mode'} eq 'filefollow' || $cfg{'mode'} eq 'honeynet') {
						$_[KERNEL]->alarm(filefollow => time());
					} elsif ($cfg{'mode'} eq 'stream') {
						$_[KERNEL]->alarm(streamMode => time());
					} elsif ($cfg{'mode'} eq 'syslog') {
						$_[KERNEL]->alarm(syslogLogMode => time());
					} elsif ($cfg{'mode'} eq 'sysmetrics') {
						$_[KERNEL]->alarm(sysMetricsMissedPolls => time());
						$_[KERNEL]->alarm(sysMetricsMode => time());
						$_[KERNEL]->alarm(sysMetricsQueueTransforms => time());
					}
				},
				filefollow => sub {
					my (@path);
					my ($pre, $post, $fh, $watchman, $wF, $wFTime);

					@path = split (/\\|\//, $filename);
					$fFile = pop(@path);
					$fPath =  join ('/', @path);

					if ($fFile =~ m/\*/) {
						($pre, $post) = split (/\*/, $fFile, 2);

						opendir (my $fh, $fPath);
						for ( grep (/^$pre\S+$post$/, readdir $fh ) ) {
							my $accessTime = (stat("$fPath/$_"))[9];

							if (! $file{$_} || ($file{$_} && $file{$_} < $accessTime)) {
								$file{$_} = $accessTime;
							}
						}
						closedir($fh);

						$wF = (sort { $file{$b} <=> $file{$a} } keys %file)[0];
						$wFTime = localtime($file{$wF});

						if ($CwF ne $wF) {
							$CwF = $wF;
							$CwFTime = $CwFTime;
							$watchman = "$fPath/$CwF";
						}
					} else {
						$watchman = "$fPath/$fFile";
					}

					if (-e $watchman) {
						my $func;

						if ($cfg{'mode'} eq 'honeynet') {
							$func = 'honey_line';
						} else {
							$func = 'got_line';
						}

						print "\n+ Watching $watchman\n\n" if ($verbose);
						$_[HEAP]->{wheel} = POE::Wheel::FollowTail->new(
							Filename   => $watchman,
							InputEvent => $func,
							ErrorEvent => 'got_error',
							SeekBack   => 0,
						);
					}

					$_[KERNEL]->delay(filefollow => 30);
				},
				got_error	=> sub {
					warn "$_[ARG0]\n"
				},
				got_line => sub {
					push (@{ $flowCache{'0'}{'flows'}{'SELF'} },
						&ipfixify::parse::fileLine(
							'line'			=> $_[ARG0],
							'cfg'			=> \%cfg,
							'cacheid'		=> '0',
							'verbose'		=> $verbose,
							'originator'	=> $originator,
							'flowCache'		=> \%flowCache
						)
					);
				},
				honey_line => sub {
					my ($flow, $alert) = &ipfixify::parse::honeynet(
						'flow'			=> $_[ARG0],
						'originator'	=> $originator
					);

					if ($flow) {
						push (@{ $flowCache{'25'}{'flows'}{'SELF'} },
							&ipfixify::parse::fileLine(
								'line'			=> $flow,
								'cfg'			=> \%cfg,
								'cacheid'		=> '25',
								'verbose'		=> $verbose,
								'originator'	=> $originator,
								'flowCache'		=> \%flowCache
							)
						);
						$syslogSend->send($alert);
					}
				},
				heartbeatSvc => sub {
					if (! ContinueRun()) { exit(0); }
					$_[KERNEL]->delay(heartbeatSvc => 5);
				},
				optionTpl => sub {
					$_[KERNEL]->delay(optionTpl => 180);
					if ($cfg{'mode'} eq 'syslog') {
						&ipfixify::ipfix::rfc3164optionTemplate(
							'flowCache'		=> \%flowCache,
							'verbose'		=> $verbose,
							'cfg'			=> \%cfg
						);
					}
					if ($cfg{'mode'} eq 'sysmetrics') {
						foreach (1..8,20,26,27,28) {
							&ipfixify::ipfix::rfc5610optionTemplate(
								'columns'		=> $flowCache{$_}{'columns'},
								'flowCache'		=> \%flowCache,
								'cacheid'		=> $_,
								'verbose'		=> $verbose,
								'cfg'			=> \%cfg
							);
						}

						&ipfixify::ipfix::sysmetricsOptionTemplates(
							'flowCache'		=> \%flowCache,
							'verbose'		=> $verbose,
							'cfg'			=> \%cfg
						);
					}
					if ($cfg{'mode'} eq 'filefollow') {
						&ipfixify::ipfix::rfc5610optionTemplate(
							'columns'		=> $flowCache{'0'}{'columns'},
							'flowCache'		=> \%flowCache,
							'verbose'		=> $verbose,
							'cfg'			=> \%cfg
						);
					}
					if ($cfg{'mode'} eq 'honeynet') {
						&ipfixify::ipfix::rfc5610optionTemplate(
							'columns'		=> $flowCache{'25'}{'columns'},
							'flowCache'		=> \%flowCache,
							'cacheid'		=> '25',
							'verbose'		=> $verbose,
							'cfg'			=> \%cfg
						);
					}
				},
				sendFlowCache => sub {
					$_[KERNEL]->delay(sendFlowCache => 1);

					&ipfixify::ipfix::sendFlows(
						'cfg'			=> \%cfg,
						'verbose'		=> $verbose,
						'originator'	=> $originator,
						'flowCache'		=> \%flowCache,
						'syspoll'		=> $syspoll
					);
				},
				streamMode => sub {
					my ($ip, $port) = &ipfixify::util::getIpPort(
						check => $stream
					);

					POE::Component::Server::Syslog->spawn(
						Type        => 'udp',
						BindAddress => $ip,
						BindPort    => $port,
						InputState  => \&streamRcv,
						MaxLen		=> 1024,
						ErrorState	=> \&syslogErr,
						SkipResolve	=> 1
					);
				},
				syslogLogMode => sub {
					my ($ip, $port) = &ipfixify::util::getIpPort(
						check => $syslog
					);

					POE::Component::Server::Syslog->spawn(
						Type        => 'udp',
						BindAddress => $ip,
						BindPort    => $port,
						InputState  => \&syslogRcv,
						ErrorState	=> \&syslogErr,
						MaxLen		=> 1024,
						SkipResolve	=> 1
					);
				},
				sysMetricsMissedPolls => sub {
					$_[KERNEL]->delay(sysMetricsMissedPolls => ($cfg{'testinterval'} * 60));
					undef(@goodList);

					foreach my $computer (@{$cfg{'members'}}) {
						$queueSysMetricDevices->enqueue($computer);
					}
				},
				sysMetricsMode => sub {
					$_[KERNEL]->delay(sysMetricsMode => 50);

					foreach my $computer (@goodList) {
						if (! $active{$computer}) {
							$queueSysMetricGather->enqueue($computer);
						}
					}
				},
				sysMetricsQueueTransforms => sub {
					while ($shared_flowCache6->pending()) {
						push (@{ $flowCache{'6'}{'flows'}{'SELF'} },
							&ipfixify::parse::fileLine(
								'line'			=> $shared_flowCache6->dequeue_nb(),
								'cfg'			=> \%cfg,
								'columns'		=> $flowCache{'6'}{'columns'},
								'colCount'		=> $flowCache{'6'}{'columnCount'},
								'cacheid'		=> '6',
								'verbose'		=> $verbose,
								'originator'	=> $originator,
								'flowCache'		=> \%flowCache,
								'delimiter'		=> $flowCache{'6'}{'delimiter'}
							)
						);
					}

					while ($queueSysMetricDevices->pending()) {
						push (@goodList, $queueSysMetricDevices->dequeue_nb());
					}
					$_[KERNEL]->delay(sysMetricsQueueTransforms => 1);
				},
				maintenance => sub {
					foreach (keys %{$flowCache{'cache'}{'hosts'}}) {
						if ($flowCache{'cache'}{'hosts'}{$_}{'expire'} < time()) {
							delete $flowCache{'cache'}{'hosts'}{$_};
						}
					}

					$_[KERNEL]->delay(maintenance => 600);
				}
			},
			args => [$filename],
		);
		$poe_kernel->run();
	}
}

exit(0);

##########################################################################

sub Install() {
	my ($mode, $errors, $niceName, $perm);

	$filename = '';
	$config = '';
	$mode = '';

	GetOptions(
		'name=s'		=> \$svcName,
		'config=s'		=> \$config,
		'file=s'		=> \$filename,
		'syslog=s'		=> \$syslog,
		'stream=s'		=> \$stream,
		'sendto=s'		=> \$streamCollectors,
		'sourceip=s'	=> \$sourceip,
		'sysmetrics+'	=> \$sysmetrics,
		'psexec=s'		=> \$psexec,
		'honeynet=s'	=> \$honeynet,
	);

	print "$version\n";

	&ipfixify::util::testPerms();

	if (! $svcName) {
		print "Error: --name parameter missing\n";
		$errors++;
	}

	if (! $config) {
		print "Error: --config parameter missing\n";
		$errors++;
	} elsif (! -e $config) {
		print "Error: can't find $config\n";
		$errors++;
	}

	if (! $filename && ! $syslog && ! $sysmetrics && ! $stream && ! $honeynet) {
		print "Error: --file, --syslog, --sysmetrics, --stream, or --honeynet parameter missing\n";
		$errors++;
	} elsif ((! -e $filename && $filename !~ m/\*/) && ! $syslog && ! $sysmetrics) {
		print "Error: can't find $filename\n";
		$errors++;
	}

	if ($errors) {
		print "\n\nInstalling as a Service\n\n".
			"--install [auto] --name=\"<svcname>\" [--config=<path/tocfg>]\n".
			"   [--file=<path/tofile> || --syslog IP:PORT || -sysmetrics\n".
			"    || -stream IP:PORT || -honeynet IP:PORT\n\n".
			"   these options will allow you to add IPFIXify as a service.\n".
			"   All 4 parameters are required.\n\n";

		exit(0);
	}

	$niceName = $svcName;

	if ($svcName =~ m/\ /) {
		$svcName =~ s/\ /\_/ig;
	}

	$perm++ if ($syslog);
	$perm++ if ($filename && ! $honeynet);
	$perm++ if ($sysmetrics);
	$perm++ if ($stream);
	$perm++ if ($honeynet);

	if ($perm > 1) {
		print "** Error: Only one mode can be enabled per instance.\n";
		exit(0);
	}

	if ($syslog) {
		$mode = "--syslog $syslog";
	} elsif ($stream) {
		$mode = "--stream $stream";

		if ($streamCollectors) {
			$mode .= " --sendto $streamCollectors";
		}
	} elsif ($filename && ! $honeynet) {
		$mode = "--file \"$filename\"";
	} elsif ($filename && $honeynet) {
		$mode = "--honeynet $honeynet --file \"$filename\"";
	} elsif ($sysmetrics) {
		my ($ini, $pscli);
		my (@members);

		$ini = new Config::IniFiles( -file => $config, -nomultiline => 1);

		@members = $ini->val('options', 'member');

		foreach (@members) {
			if ($_ ne $originator && $^O eq 'MSWin32') {
				$pscli = 1;
			}
		}

		if ($ini->val('options', 'netstatDetails') && $pscli) {
			if (! $psexec) {
				print "** Error: Path to PSexec.exe is required.\n";
				exit(0);
			} elsif (! -e $psexec) {
				print "** Error: Could not find psexec.exe at $psexec.\n";
				exit(0);
			}
			$mode = "--sysmetrics --psexec \"$psexec\"";
		} else {
			$mode = "--sysmetrics";
		}
	}

	if ($sourceip) {
		$mode .= " --sourceip $sourceip";
	}

	%Config = (
		ServiceName => $svcName,
		DisplayName => "IPFIXify: $niceName",
		Parameters  => "--config \"$config\" $mode",
		Description => "Plixer IPFIXifies Everything!"
	);
}

##########################################################################

sub pollSysMetricsHost {
	my (
		$thread_id, $fn, $computer, $verboseO, $debugO, $user,
		$machineID
	);

	$fn = 'ipfixify.exe';

	if ($^O eq 'MSWin32') {
		$user = undef;
		$fn .= '.exe' if ($fn !~ m/.exe/);
	} elsif ($^O eq 'linux') {
		$user = getpwuid($<);

		# Threads and Net::SSH::Expect, yes threads are evil
		# https://rt.cpan.org/Public/Bug/Display.html?id=39777
		close(STDIN);
		close(STDOUT);
		close(STDERR);
	}

	$verboseO = $verbose ? "--verbose" : '';
	$debugO = ($verbose > 1) ? "--debug" : '';

	$thread_id = shift;

	while (1) {
		my ($timer, $start, $debug, $services, $obj, $procTime, $flow);
		my (@psexec);

		$computer = $queueSysMetricGather->dequeue();

		$debug = '+ T'.sprintf ('%-4s', $thread_id). sprintf ('%-15s', $computer);

		$active{$computer} = time();

		$start = [ Time::HiRes::gettimeofday( ) ];
		print "$debug (StepTime / Over All) : Polling\n" if ($verbose > 1);

		if ($psexec) {
			@psexec = ('--psexec', $psexec);
		}

		$obj = Plixer::Process->new
		  (
		   exe_name	=> $fn,
		   exe_args	=> 
		   [
			"--syspoll",
			"${computer}::${thread_id}",
			"--config",
			$config,
			@psexec,
			$verboseO,
			$debugO
		   ],
		   startup_dir => '.',
		   username	=> $user
		  );

		$obj->run();

		while ($obj->is_alive()) {
			sleep 1;

			if ($procTime > $cfg{'pollTimeOut'}) {
				$obj->kill();
			} else {
				$procTime++;
			}
		}

		delete $active{$computer};

		## THIS IS A VERY IMPORTANT BLOCK BUT IT'S COMMENTED
		## OUT. RIGHT NOW WE LAUNCH SEPARATE IPFIXIFY.EXE TO POLL THE
		## INDIVIDUAL HOST. IF WE CAN UNCOMMENT THIS BLOCK, THEN WE
		## STOP THAT. HOWEVER, DOING SO HAS MASSIVE MEMORY LEAKS THAT
		## AREN'T IDENTIFABLE.
		#if ($^O eq 'MSWin32') {
		#	&pollSysMetricsWindowsEndpoint(
		#	    syspoll		=> "${computer}::${thread_id}",
		#		verbose		=> $verbose,
		#		originator	=> $originator
		#	);
		#} elsif ($^O eq 'linux') {
		#	&pollSysMetricsLinuxEndpoint(
		#		syspoll		=> "${computer}::${thread_id}",
		#		verbose		=> $verbose,
		#		originator	=> $originator
		#	);
		#}

      ## DETERMINE MACHINE ID ##
		$machineID = &ipfixify::sysmetrics::getMachineID
		  (
		   poller => 1,
		   computer => $computer
		  );

	  ## POLLING STATISTICS ##
		$flow = join
		  (
		   ':-:',
		   $machineID,
		   int(Time::HiRes::tv_interval($start) * 1000),
		   1
		  );

		$shared_flowCache6->enqueue($flow)
		  if (-e "$ENV{'TMPDIR'}/$computer.machineid");

	  ## DONE ##
		print "$debug (Total Time ".&formatTimer(Time::HiRes::tv_interval($start)).") : Done\n"
			if ($verbose);
	}
}

##########################################################################

sub pollSysMetricsLinuxEndpoint {
	my (%arg);
	my (@row);
	my (
		$ssh, $output, $timer, $start, $debug_system, $stamp, $local,
		$machineID
	);

	%arg = (@_);

	$stamp = time();

	($arg{'computer'}, $arg{'thread_id'}) = split (/::/, $arg{'syspoll'});

	$debug_system = '+ T'. sprintf ('%-4s', $arg{'thread_id'}).
		sprintf ('%-15s', $arg{'computer'});

	return 0 if (! $arg{'computer'});

	$start = [ Time::HiRes::gettimeofday( ) ];

	eval {
		if ($arg{'computer'} eq $arg{'originator'}) {
			$local = 1;
		} else {
			$local = 0;

			$ssh = Net::SSH::Expect->new (
				host 		=> $arg{'computer'},
				password	=> $cfg{'pwd'},
				user 		=> $cfg{'user'},
				raw_pty 	=> 1,
				no_terminal => 1,
				timeout 	=> $arg{'pingtimeout'},
			);

			$output = $ssh->login();
		}
	};

	if ($@) {
		print qq {$debug_system No Connection Made, skipping\n} if ($verbose);
		return 0;
	}

  ## DETERMINE MACHINE ID ##
	$machineID = &ipfixify::sysmetrics::getMachineID
	  (
	   'handle'	=> $ssh,
	   'local' => $local,
	   'computer' => $arg{'computer'}
	  );

  ## ENDPOINT IDENTITY ##
	{
		my (
			$caption, $version, $machineName, $systemType, $vendor,
			$flow, $lat, $long
		);

		$caption = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/cat /etc/issue',
		   local	=> $local
		  );

		$version = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/uname -r',
		   local	=> $local,
		  );

		$machineName = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/hostname',
		   local	=> $local,
		  );

		$systemType = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/uname -m',
		   local	=> $local,
		  );

		$vendor = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/cat /sys/devices/virtual/dmi/id/sys_vendor',
		   local	=> $local,
		  );

		### Latitude/Longitude ###
		($lat, $long) = split (/,/, $arg{gps});

		### Flow ###
		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : EndpointIndentity\n"
			if ($verbose > 1);

		$flow = join
		  (
		   ':-:',
		   $arg{'originator'},
		   $arg{'computer'},
		   $machineID,
		   $machineName,
		   $caption,
		   $version,
		   $vendor,
		   $systemType,
		   $lat,
		   $long
		  );

		push (@{ $flowCache{'114'}{'flows'}{'SPOOL'} }, $flow);
	}

  ## VITALS : CPU, MEMORY, PROCESSES ##
	if ($cfg{'vitals'}) {
		my ($cpu, $flow, $mem, $vmem, $proc);

		$cpu = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> "/bin/grep 'cpu ' /proc/stat | /bin/awk '{usage=(\$2+4)*100/(\$2+\$4+\$5)} END {print usage}'",
		   local	=> $local,
		  );

		$mem = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> "/usr/bin/free -b | grep 'Mem: ' | /bin/awk '{usage=\$4} END {print usage}'",
		   local	=> $local,
		  );

		$vmem = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> "/usr/bin/free -b | grep 'Swap: ' | /bin/awk '{usage=\$4} END {print usage}'",
		   local	=> $local,
		  );

		$proc = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/ps aux | wc -l',
		   local	=> $local,
		  );

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : EndpointVitals\n"
			if ($verbose > 1);

		$flow = join
		  (
		   ':-:',
		   $machineID,
		   int($cpu + .5),
		   int($mem),
		   int($vmem),
		   int($proc),
		   1
		  );

		push (@{ $flowCache{'4'}{'flows'}{'SPOOL'} }, $flow);
	} else {
		print "$debug_system vitals skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## STORAGE AVAILABLE ##
	if ($cfg{'storageAvailability'}) {
		my @partitions = &ipfixify::sysmetrics::linuxCommandGrabber
		  (
		   ssh 		=> $ssh,
		   command	=> '/bin/df',
		   local	=> $local,
		   multi	=> 1
		  );

		foreach (@partitions) {
			my ($avail, $flow, $part, $used, $usedPer);

			$_ =~ s/\s+/\|/ig;

			(undef, undef, $used, $avail, $usedPer, $part) = split (/\|/, $_);
			$avail *= 1024;

			next if (! $part || $part =~ m/mounted/i);

			$flow = join
			  (
			   ':-:',
			   $machineID,
			   $part,
			   $avail,
			   1
			  );

			push (@{ $flowCache{'5'}{'flows'}{'SPOOL'} }, $flow);
		}

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : FreeSpace\n"
			if ($verbose > 1);
	} else {
		print "$debug_system storageAvailability skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## PROCESSES RUNNING DETAILS ##
	if ($cfg{'processLists'}) {
		my (%processList);
		my ($cpu, $mem);

		print "$debug_system processListsCPU skipped, option disabled\n"
			if (($verbose > 1) && ! $cfg{'processListsCPU'});

		($timer, %processList) = &ipfixify::sysmetrics::linuxProcessGrabber(
			'ssh'		=> $ssh,
			'grabCpu'	=> $cfg{'processListsCPU'},
			'host'		=> $arg{'computer'},
			'originator'=> $arg{'originator'}
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : Processlist\n"
			if ($verbose > 1);

		foreach my $proc (keys %processList) {
			$mem = join
			  (
			   ':-:',
			   $machineID,
			   $processList{$proc}{'Caption'},
			   $processList{$proc}{'ParentProcessName'},
			   $processList{$proc}{'ProcessUserName'},
			   $processList{$proc}{'CommandLine'},
			   $processList{$proc}{'ParentProcessId'},
			   $processList{$proc}{'shaParentProcessId'},
			   $processList{$proc}{'ProcessId'},
			   $processList{$proc}{'shaProcessId'},
			   $processList{$proc}{'VirtualSize'},
			   $processList{$proc}{'WorkingSetSize'},
			   1
			  );

			push (@{ $flowCache{'8'}{'flows'}{'SPOOL'} }, $mem);

			if ($cfg{'processListsCPU'}) {
				$cpu = join
				  (
				   ':-:',
				   $machineID,
				   $processList{$proc}{'Caption'},
				   $processList{$proc}{'ParentProcessName'},
				   $processList{$proc}{'ProcessUserName'},
				   $processList{$proc}{'CommandLine'},
				   $processList{$proc}{'ParentProcessId'},
				   $processList{$proc}{'shaParentProcessId'},
				   $processList{$proc}{'ProcessId'},
				   $processList{$proc}{'shaProcessId'},
				   $processList{$proc}{'cpuUsage'},
				   1
				  );

				push (@{ $flowCache{'7'}{'flows'}{'SPOOL'} }, $cpu);
			}
		}
	} else {
		print "$debug_system processLists skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## NETSTAT DETAILS ##
	if ($cfg{'processLists'} && $cfg{'netstatDetails'}) {
		my (@netstatList);
		my ($timer);

		($timer, @netstatList) = &ipfixify::sysmetrics::netstatDetails(
			'ip'		=> $arg{'computer'},
			'user'		=> $arg{'user'},
			'password'	=> $arg{'pwd'},
			'originator'=> $originator,
			'ssh'		=> $ssh
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : netStatDetails\n"
			if ($verbose > 1);

		foreach my $record (@netstatList) {
			my ($proto, $srcIp, $srcPort, $dstIp, $dstPort, $state, $pid) = split (/\|/, $record);

			my $flow = join
			  (
			   ':-:',
			   $machineID,
			   $proto,
			   $srcIp,
			   $srcPort,
			   $dstIp,
			   $dstPort,
			   $state,
			   $pid,
			   1
			  );

			push (@{ $flowCache{'20'}{'flows'}{'SPOOL'} }, $flow);
		}
	} else {
		print "$debug_system netstatDetails skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## USERNAMES or EVENT LOGS ###
	if ($cfg{'usernamesOnly'} || $cfg{'eventlogs'}) {
		# not available on linux agents
	} else {
		print "$debug_system eventLogs skipped, not supported\n"
			if ($verbose > 1);
	}

  ## INTERFACE DETAILS AND STATISTICS ##
	if ($cfg{'ifStatistics'}) {
		my ($timer);
		my (%interfaceStats);

		($timer, %interfaceStats) = &ipfixify::sysmetrics::linuxInterfaceGrabber(
			'ssh'		=> $ssh,
			'host'		=> $arg{'computer'},
			'originator'=> $arg{'originator'}
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : ifStatistics\n"
		  if ($verbose > 1);

		foreach my $int (keys %interfaceStats) {
			my ($flow, $option);

			$flow = join
			  (
			   ':-:',
			   $machineID,
			   $interfaceStats{$int}{ifIndex},
			   $interfaceStats{$int}{tx_bytes},
			   $interfaceStats{$int}{rx_bytes},
			   $interfaceStats{$int}{tx_bytes},
			   $interfaceStats{$int}{rx_bytes},
			   1
			  );

			push (@{ $flowCache{'28'}{'flows'}{'SPOOL'} }, $flow);

			$option = join
			  (
			   ':-:',
			   $machineID,
			   $interfaceStats{$int}{ifIndex},
			   $int,
			   $interfaceStats{$int}{portspeed},
			);

			push (@{ $flowCache{'113'}{'flows'}{'SPOOL'} }, $option);
		}
	} else {
		print "$debug_system ifStatistics skipped, option disabled\n"
	}

  ## SEND FLOWS ##
	&ipfixify::ipfix::sendFlows(
		'cfg'			=> \%cfg,
		'flowCache'		=> \%flowCache,
		'verbose'		=> $verbose,
		'spool'			=> "$stamp-$arg{'computer'}",
		'originator'	=> $arg{'originator'},
		'syspoll'		=> $arg{'syspoll'}
	);

  ## DONE ##
	$ssh->close() if ($ssh);

	print "$debug_system (Total Time ".&formatTimer(Time::HiRes::tv_interval($start)).") : Done\n"
		if ($verbose > 1);

	return 0;
}

##########################################################################

sub pollSysMetricsWindowsEndpoint {
	my (%arg);
	my (@row);
	my ($dbh, $sth, $timer, $start, $debug_system, $stamp, $local, $machineID);

	%arg = (@_);

	$stamp = time();

	($arg{'computer'}, $arg{'thread_id'}) = split (/::/, $arg{'syspoll'});

	$debug_system = '+ T'. sprintf ('%-4s', $arg{'thread_id'}).
		sprintf ('%-15s', $arg{'computer'});

	return 0 if (! $arg{'computer'});

	$start = [ Time::HiRes::gettimeofday( ) ];

	eval {
		if ($arg{'computer'} eq $arg{'originator'}) {
			$dbh = DBI->connect('dbi:WMI:');
			$local = 1;
		} else {
			$dbh = DBI->connect("dbi:WMI:$arg{'computer'}");
			$local = 0;
		}
	};

	if ($@) {
		if ($cfg{'vitals'} || $cfg{'storageAvailability'} || $cfg{'processLists'} || $cfg{'ifStatistics'}) {
			print qq {$debug_system No Connection Made, skipping\n} if ($verbose);
			return 0;
		}
	}

	if ($cfg{'vitals'} || $cfg{'storageAvailability'} || $cfg{'processLists'} || $cfg{'ifStatistics'}) {
	  ## DETERMINE MACHINE ID ##
		$machineID = &ipfixify::sysmetrics::getMachineID
		  (
		   'handle'	=> $dbh,
		   'local' => $local,
		   'computer' => $arg{'computer'}
		  );

	  ## ENDPOINT IDENTITY ##
		{
			my (%caption, %name, %version, %maker, %type);
			my ($flow, $lat, $long);

			($timer, %caption) = &ipfixify::sysmetrics::wmiVitalsGrabber(
				'dbh'   	=> $dbh,
				'query'     => 'SELECT * FROM Win32_OperatingSystem',
				'value'     => 'Caption',
			);

			($timer, %version) = &ipfixify::sysmetrics::wmiVitalsGrabber(
				'dbh'   	=> $dbh,
				'query'     => 'SELECT * FROM Win32_OperatingSystem',
				'value'     => 'Version',
			);

			($timer, %name) = &ipfixify::sysmetrics::wmiVitalsGrabber(
				'dbh'   	=> $dbh,
				'query'     => 'SELECT * FROM Win32_ComputerSystem',
				'value'     => 'Name',
			);

			($timer, %type) = &ipfixify::sysmetrics::wmiVitalsGrabber(
				'dbh'   	=> $dbh,
				'query'     => 'SELECT * FROM Win32_ComputerSystem',
				'value'     => 'SystemType',
			);

			($timer, %maker) = &ipfixify::sysmetrics::wmiVitalsGrabber(
				'dbh'   	=> $dbh,
				'query'     => 'SELECT * FROM Win32_ComputerSystem',
				'value'     => 'Manufacturer',
			);

			print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : EndpointIndentity\n"
				if ($verbose > 1);

			### Latitude/Longitude ###
			($lat, $long) = split (/,/, $arg{gps});

			$flow = join
			  (
			   ':-:',
			   $arg{'originator'},
			   $arg{'computer'},
			   $machineID,
			   $name{Name},
			   $caption{Caption},
			   $version{Version},
			   $maker{Manufacturer},
			   $type{SystemType},
			   $lat,
			   $long
			  );

			push (@{ $flowCache{'114'}{'flows'}{'SPOOL'} }, $flow);
		}
	}

  ## VITALS : CPU, MEMORY, PROCESSES ##
	if ($cfg{'vitals'}) {
		my (%loadPercent, %freePhysMem, %freeVirMem, %numOfProc);
		my ($flow);

		($timer, %loadPercent) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'	  	=> $dbh,
			'query'     => 'SELECT * FROM Win32_Processor',
			'value'     => 'LoadPercentage',
			'math'      => 'avg',
			'factor'	=> 1
		);

		($timer, %freePhysMem) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'   	=> $dbh,
			'query'     => 'SELECT * FROM Win32_OperatingSystem',
			'value'     => 'FreePhysicalMemory',
		);

		($timer, %freeVirMem) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'		=> $dbh,
			'query'     => 'SELECT * FROM Win32_OperatingSystem',
			'value'     => 'FreeVirtualMemory',
		);

		($timer, %numOfProc) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'	  	=> $dbh,
			'query'     => 'SELECT * FROM Win32_OperatingSystem',
			'value'     => 'NumberOfProcesses',
		);
		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : EndpointVitals\n"
			if ($verbose > 1);

		$flow = join
		  (
		   ':-:',
		   $machineID,
		   $loadPercent{LoadPercentage},
		   $freePhysMem{FreePhysicalMemory} * 1024,
		   $freeVirMem{FreeVirtualMemory} * 1024,
		   $numOfProc{NumberOfProcesses},
		   1
		  );

		push (@{ $flowCache{'4'}{'flows'}{'SPOOL'} }, $flow);
	} else {
		print "$debug_system vitals skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## STORAGE AVAILABLE ##
	if ($cfg{'storageAvailability'}) {
		my (%freeHdd);

		($timer, %freeHdd) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'   	=> $dbh,
			'query'     => 'SELECT * FROM Win32_Volume WHERE (DriveType = 1 OR DriveType = 3)',
			'drivespace'=> 'DriveLetter,FreeSpace',
		);
		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : FreeSpace\n"
			if ($verbose > 1);

		foreach my $drive (keys %freeHdd) {
			my $flow = join
			  (
			   ':-:',
			   $machineID,
			   $drive,
			   $freeHdd{$drive},
			   1
			);

			push (@{ $flowCache{'5'}{'flows'}{'SPOOL'} }, $flow);
		}
	} else {
		print "$debug_system storageAvailability skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## PROCESSES RUNNING DETAILS ##
	if ($cfg{'processLists'}) {
		my (%processList, %processors);
		my ($cpu, $mem);

		($timer, %processors) = &ipfixify::sysmetrics::wmiVitalsGrabber(
			'dbh'   	=> $dbh,
			'query' 	=> 'SELECT * FROM Win32_ComputerSystem',
			'value'     => 'NumberOfLogicalProcessors',
		);

		($timer, %processList) = &ipfixify::sysmetrics::wmiProcessGrabber(
			'dbh'		=> $dbh,
			'cpuCount'  => $processors{'NumberOfLogicalProcessors'},
			'grabCpu'	=> $cfg{'processListsCPU'},
			'host'		=> $arg{'computer'},
			'originator'=> $arg{'originator'}
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : Processlist\n"
			if ($verbose > 1);

		print "$debug_system processListsCPU skipped, option disabled\n"
			if (($verbose > 1) && ! $cfg{'processListsCPU'});

		foreach my $proc (keys %processList) {
			next unless ($processList{$proc}{'Caption'});

			$mem = join
			  (
			   ':-:',
			   $machineID,
			   $processList{$proc}{'Caption'},
			   $processList{$proc}{'ParentProcessName'},
			   $processList{$proc}{'ProcessUserName'},
			   $processList{$proc}{'CommandLine'},
			   $processList{$proc}{'ParentProcessId'},
			   $processList{$proc}{'shaParentProcessId'},
			   $processList{$proc}{'ProcessId'},
			   $processList{$proc}{'shaProcessId'},
			   $processList{$proc}{'VirtualSize'},
			   $processList{$proc}{'WorkingSetSize'},
			   1
			  );

			push (@{ $flowCache{'8'}{'flows'}{'SPOOL'} }, $mem);

			if ($cfg{'processListsCPU'}) {
				$cpu = join
				  (
				   ':-:',
				   $machineID,
				   $processList{$proc}{'Caption'},
				   $processList{$proc}{'ParentProcessName'},
				   $processList{$proc}{'ProcessUserName'},
				   $processList{$proc}{'CommandLine'},
				   $processList{$proc}{'ParentProcessId'},
				   $processList{$proc}{'shaParentProcessId'},
				   $processList{$proc}{'ProcessId'},
				   $processList{$proc}{'shaProcessId'},
				   $processList{$proc}{'cpuUsage'},
				   1
				  );

				push (@{ $flowCache{'7'}{'flows'}{'SPOOL'} }, $cpu);
			}
		}
	} else {
		print "$debug_system processLists skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## NETSTAT DETAILS ##
	if ($cfg{'processLists'} && $cfg{'netstatDetails'}) {
		my (@netstatList);
		my ($timer);

		($timer, @netstatList) = &ipfixify::sysmetrics::netstatDetails(
			'ip'		=> $arg{'computer'},
			'user'		=> $arg{'user'},
			'password'	=> $arg{'pwd'},
			'originator'=> $originator,
			'psexec'	=> $psexec
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : netStatDetails\n"
			if ($verbose > 1);

		foreach my $record (@netstatList) {
			my ($proto, $srcIp, $srcPort, $dstIp, $dstPort, $state, $pid) = split (/\|/, $record);

			my $flow = join
			  (
			   ':-:',
			   $machineID,
			   $proto,
			   $srcIp,
			   $srcPort,
			   $dstIp,
			   $dstPort,
			   $state,
			   $pid,
			   1
			  );

			push (@{ $flowCache{'20'}{'flows'}{'SPOOL'} }, $flow);
		}
	} else {
		print "$debug_system netstatDetails skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## USERNAMES or EVENT LOGS ###
	if ($cfg{'usernamesOnly'} || $cfg{'eventlogs'}) {
		my ($err, $events) = &ipfixify::sysmetrics::eventLogConnect(
			cfg		 	=> \%cfg,
			machine		=> $arg{'computer'}
		);

		if (! $err) {
			foreach (@eventLogToGather) {
				my ($cacheid, $el) = split (/:/, $_);

				$timer = &ipfixify::sysmetrics::eventLogParse(
					flowcacheid => $cacheid,
					eventlog	=> $el,
					elh			=> $events,
					tid			=> $arg{'thread_id'},
					cfg		 	=> \%cfg,
					flowCache	=> \%flowCache,
					computer	=> $arg{'computer'},
					originator	=> $arg{'originator'},
					machineID	=> $machineID,
					verbose		=> $verbose
				);

				print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : EventLog ($el)\n"
					if ($verbose > 1);
			}
		} else {
			print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : $events [Error Connecting]\n"
			  if ($verbose > 1);
		}
	} else {
		print "$debug_system eventLogs skipped, option disabled\n"
			if ($verbose > 1);
	}

  ## INTERFACE DETAILS AND STATISTICS ##
	if ($cfg{'ifStatistics'}) {
		my ($timer);
		my (%interfaceStats);

		($timer, %interfaceStats) = &wmiInterfaceGrabber(
			'dbh'		=> $dbh,
			'host'		=> $arg{'computer'},
			'originator'=> $arg{'originator'}
		);

		print "$debug_system (".&formatTimer($timer)." / ".&formatTimer(Time::HiRes::tv_interval($start)).") : ifStatistics\n"
		  if ($verbose > 1);

		foreach my $int (keys %interfaceStats) {
			my ($flow, $option);

			$flow = join
			  (
			   ':-:',
			   $machineID,
			   $interfaceStats{$int}{ifIndex},
			   $interfaceStats{$int}{octets_tx},
			   $interfaceStats{$int}{octets_rx},
			   $interfaceStats{$int}{packets_tx},
			   $interfaceStats{$int}{packets_rx},
			   1
			);

			push (@{ $flowCache{'28'}{'flows'}{'SPOOL'} }, $flow);

			$option = join
			  (
			   ':-:',
			   $machineID,
			   $interfaceStats{$int}{ifIndex},
			   $int,
			   $interfaceStats{$int}{portspeed},
			);

			push (@{ $flowCache{'113'}{'flows'}{'SPOOL'} }, $option);
		}
	} else {
		print "$debug_system ifStatistics skipped, option disabled\n"
	}

  ## SEND FLOWS ##
	&ipfixify::ipfix::sendFlows(
		'cfg'			=> \%cfg,
		'flowCache'		=> \%flowCache,
		'verbose'		=> $verbose,
		'spool'			=> "$stamp-$arg{'computer'}",
		'originator'	=> $arg{'originator'},
		'syspoll'		=> $arg{'syspoll'}
	);

  ## DONE ##
	$dbh->disconnect() if ($dbh);

	print "$debug_system (Total Time ".&formatTimer(Time::HiRes::tv_interval($start)).") : Done\n"
		if ($verbose > 1);

	return 0;
}

##########################################################################

sub Remove() {
	my ($errors, $niceName);

	GetOptions('name=s' => \$svcName);

	print "$version\n";

	&ipfixify::util::testPerms();

	if (! $svcName) {
		print "Error: missing name parameter\n";
		$errors++;
	}

	if ($errors) {
		print "\n\nService Removal Instructions\n\n".
			"--remove --name=\"<svcname>\"\n\n".
			"   removes the service for this instance of IPFIXify.\n";

		exit(0);
	}

	$niceName = $svcName;

	if ($svcName =~ m/\ /) {
		$svcName =~ s/\ /\_/ig;
	}

	%Config = (
		ServiceName => $svcName,
	);
}

##########################################################################

sub s_exe {
	my $exePath = undef;

	if (defined &PerlApp::exe) {
		$exePath = PerlApp::exe();
	} elsif (defined &PerlSvc::exe) {
		$exePath = PerlSvc::exe();
	}
	return $exePath;
}

##########################################################################

sub syslogErr {
	print Dumper $_[ARG0] if ($verbose);
}

sub syslogRcv {
	#$syslogCount++;
	push (@{ $flowCache{'0'}{'flows'}{'SELF'} },
		&ipfixify::parse::fileLine(
			'line'			=> $_[ARG0],
			'cfg'			=> \%cfg,
			'cacheid'		=> '0',
			'verbose'		=> $verbose,
			'originator'	=> $originator,
			'flowCache'		=> \%flowCache
		)
	);
}

##########################################################################

sub streamRcv {
	#$syslogCount++;
	my ($id, $msg);
	my (@fieldCount);

	($id, $msg) = split (/:/, $_[ARG0]->{'msg'}, 2);
	$id =~ s/IPFIXIFY|\[|\]|:|\ //g;
	$msg =~ s/^\ //g;

	@fieldCount = split (/$flowCache{$id}{'delimiter'}/, $msg);

	if (! $flowCache{$id}{'delimiter'}) {
		print "* Flow Cache request of $id not found, dropping flow\n" if ($verbose);
		return;
	} elsif (@fieldCount ne $flowCache{$id}{'columnCount'}) {
		print "* Flow Cache $id - Flow Dropped field count is not ".
			$flowCache{$id}{'columnCount'}.", got ".
			@fieldCount."\n" if ($verbose);

		return;
	} else {
		## IF YOU WANT TO LOOK AT FLOWS IN REALTIME AND WANT TO MAKE CACHES
		## FOR THAT DATA, HERE IS WHERE IT WOULD GO. ID IS THE FLOW CACHE

		push (@{ $flowCache{$id}{'flows'}{'SELF'} },
			&ipfixify::parse::fileLine(
				'line'			=> $msg,
				'cfg'			=> \%cfg,
				'cacheid'		=> $id,
				'verbose'		=> $verbose,
				'originator'	=> $originator,
				'flowCache'		=> \%flowCache
			)
		);
	}
}

##########################################################################

sub formatTimer {
	my ($timer, $format);

	$timer = shift;
	$format = sprintf "%-8s", $timer;
	$format = substr $format, 0, 8;

	return $format;
}


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:4 ***
# perl-indent-level:4 ***
# tab-width: 4 ***
# indent-tabs-mode: t ***
# End: ***
#
# vim: ts=4 sw=4 noexpandtab
