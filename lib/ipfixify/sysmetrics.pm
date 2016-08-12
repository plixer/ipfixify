#!perl

package ipfixify::sysmetrics;

use strict;
use Capture::Tiny ':all';
use Data::Dumper;
use DBI;
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha256_hex);
use Exporter;
use ipfixify::parse;
use Time::HiRes;

our ($VERSION);
our (@ISA, @EXPORT);

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
	&createDb
	&eventLogConnect
	&eventLogGrab
	&eventLogLastID
	&eventLogParse
	&getMachineID,
	&linuxCommandGrabber
	&linuxInterfaceGrabber
	&linuxProcessGrabber
	&netstatDetails
	&pingTest
	&profiling
	&sampling
	&wmiInterfaceGrabber
	&wmiProcessGrabber
	&wmiVitalsGrabber
);

=pod

=head1 NAME

ipfixify::sysmetrics

=head1 SYNOPSIS

=over 2

	&ipfixify::sysmetrics::createDb();

	($err, $event) = &ipfixify::sysmetrics::eventLogConnect(
		cfg => \%cfg,
		machine => $ip
	);

	($lastrec, @records) = &ipfixify::sysmetrics::eventLogGrab(
		eventlog	=> 'Application|Security|System',
		elh			=> $eventLogHandle,
		tid			=> $arg{'tid'},
		eventfilter => [4634] || '',
		startrec	=> $recordNumber,
		verbose		=> 1 || 0
	);

	$z = &ipfixify::sysmetrics::eventLogLastID(
		flowcacheid		=> $arg{'flowcacheid'},
		computer		=> $arg{'computer'},
		action			=> [SET|GET],
		eventid			=> $y
	);

	$timer = &ipfixify::sysmetrics::eventLogParse(
		flowcacheid => $cacheid,
		lastX       => $lastX,
		eventlog	=> $el,
		elh			=> $events,
		flowCache	=> \%flowCache,
		computer	=> $arg{'computer'},
		originator	=> $arg{'originator'},
		machineID	=> $machineID,
		verbose		=> $verbose
	);

	$machineID = &ipfixify::sysmetrics::getMachineID(
		'handle'	=> [$ssh|$dbh],
		'local'		=> [0|1]
	);

	$output = &ipfixify::sysmetrics::linuxCommandGrabber
	  (
	   ssh		=> $ssh,
	   command	=> command,
	   local	=> [1|0],
	   chop		=> [1|0],
	   multi	=> [1|0]
	  );

	($timer, %results) = &ipfixify::sysmetrics::linuxInterfaceGrabber(
		'ssh'		=> $ssh,
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

	($timer, %results) = &ipfixify::sysmetrics::linuxProcessGrabber(
		'ssh'		=> $ssh,
		'grabCpu'	=> $cfg{'processListsCPU'},
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

	($timer, @results) = &ipfixify::sysmetrics::netstatDetails(
		'ip'		=> $arg{'ip'},
		'user'		=> $arg{'user'},
		'password'	=> $arg{'password'}
		'psexec'	=> $arg{'psexec'},
		'ssh'		=> $arg{'ssh'}
	);

	$pass = &ipfixify::sysmetrics::pingTest(
		computer		=> $computer,
		debug_system	=> "+ $shortTime ".sprintf('%-15s',$computer),
		verbose			=> $verbose,
		pingtimeout		=> $cfg{'pingtimeout'},
		originator		=> $originator,
		cfg				=> \%cfg
	);

	&ipfixify::sysmetrics::profiling(
		config  => $config,
		lastX   => $lastX,
		psexec  => $psexec,
		cfg		=> \%cfg
	);

	&ipfixify::sysmetrics::sampling(
	   cfg		=> \%cfg,
	   debug    => $debug,
	   member   => $sample,
	   record   => $sampleRecord
	);

	($timer, %results) = &ipfixify::sysmetrics::wmiInterfaceGrabber(
		'dbh'		=> $dbh,
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

	($timer, %results) = &ipfixify::sysmetrics::wmiProcessGrabber(
		'dbh'		=> $dbh,
		'cpuCount'  => $processors{'NumberOfLogicalProcessors'},
		'grabCpu'	=> $cfg{'processListsCPU'},
		'host'		=> $arg{'computer'},
		'originator'=> $arg{'originator'}
	);

	($time, %results) = &ipfixify::sysmetrics::wmiVitalsGrabber(
		'connect'  => $services,
		'query'    => 'SELECT Name, FreeSpace FROM Win32_LogicalDisk',
		'value'    => 'FreeSpace',
		'label'    => 'Name',
		'math'     => 'each',
		'sid'      => [1|0],
		'factor'   => '1'
	);

=back

=head1 DESCRIPTION

This module contains functions related to utility or functions for
system metrics mode.

The following functions are part of this module.

=cut

#####################################################################

=pod

=head2 createDb

The create DB function creates the database file and appropriate
tables for the operations of sysMetrics mode.

=over 2

	&ipfixify::sysmetrics::createDb();

=back

There are currently no parameters required for this function.

=cut

sub createDb {
	my (%arg);
	my ($dbh, $query);

	%arg = (@_);

	return if (-e "$ENV{'TMPDIR'}/sysmetrics.db");

	$dbh = DBI->connect
	  (
	   "dbi:SQLite:dbname=$ENV{'TMPDIR'}/sysmetrics.db",
	   "",
	   "",
	   { RaiseError => 1, AutoCommit => 1}
	  );

	$query = qq {
		CREATE TABLE IF NOT EXISTS `eventlogs` (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			computer,
			flowcacheid INTEGER,
			lastEvent INTEGER
		);
	};

	$dbh->do($query);

	$query = qq {
		CREATE TABLE IF NOT EXISTS `usereventlogs` (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			computer,
			flowcacheid INTEGER,
			lastEvent INTEGER
		);
	};

	$dbh->do($query);

	$dbh->disconnect() if ($dbh);

	return;
}

#####################################################################

=pod

=head2 eventLogConnect

this function connects to a system to read eventlog events.

=over 2

	($err, $event) = &ipfixify::sysmetrics::eventLogConnect(
		cfg => \%cfg,
		machine => $ip
	);

=back

The currently supported parameters are:

=over 2

=item * cfg

The current configuration hash with all settings from cfg file

=item * machine

The IP address of the machine to connect to. If left blank, then
localhost is assumed.

=back

Two parameters are returned. $err will be true (1) if an error
occurred. Therefore, the $event will contain the message. If $err is
false (0) then $event can be used to communicate with the
$arg{'machine'}

=cut

sub eventLogConnect {
	my (%arg);
	my ($events);

	%arg = (@_);

	eval {
		# use credentials in the end
		$events = Plixer::EventLog->new(
			$arg{'machine'},
			$arg{'cfg'}->{'user'},
			$arg{'cfg'}->{'pwd'},
			$arg{'verbose'}
		);
	};

	if ($@) {
		return (1, $@);
	} else {
		return (0, $events);
	}
}

#####################################################################

=pod

=head2 eventLogGrab

This grabs a list of eventlogs and returns them for processing.

=over 2

	($lastrec, @records) = &ipfixify::sysmetrics::eventlogGrab(
		eventlog	=> 'Application|Security|System',
		elh			=> $eventLogHandle,
		tid			=> $arg{'tid'},
		eventfilter => [4634] || '',
		startrec	=> $recordNumber,
		verbose		=> 1 || 0
	);

=back

The currently supported parameters are:

=over 2

=item * eventlog

specify which eventlog we will gather events

=item * elh

the eventlog handle to the machine where we will gather events

=item * tid

The thread ID for logging and capturing purposes

=item * eventfilter

when passed, events that match those event ids will be
gathered. otherwise all events will be gathered

=item * startrec

which record do we begin when gathering events

=item * verbose

when enabled, debug will be printed out to the screen

=back

Two parameters are returned. $lastrec is the last eventlog record
number collected to use for the next cycle. The @records will contain
an array of hashes that contain the records to process.

=cut

sub eventLogGrab {
	my (%arg);
	my ($json, $stdout, $stderr);
	my (@eventfilter, @records, @userIdentityEvents);

	%arg = (@_);

	@userIdentityEvents =
	  (
	   '4624',
	   '4634',
	   '4647',
	   '6272',
	   '6273',
	   '6274',
	   '6278',
	   '6279'
	  );

	if ($arg{'cfg'}->{'usernamesOnly'}) {
		@eventfilter = @userIdentityEvents;
	} else {
		@eventfilter = ();
	}

	($stdout, $stderr) = eval {
		capture {
			$arg{'elh'}->parse
			  (
			   eventlog => $arg{'eventlog'},
			   eventfilter => \@eventfilter,
			   startrec => $arg{'startrec'},
			  );
		};
	};

	if ($stdout =~ m/error: 5/) {
		print "[Error]: Invalid Login Credentials\n"
		  if ($arg{'verbose'});

		return ($arg{'startrec'}, @records);
	} elsif ($stderr) {
		print "$stderr\n" if ($arg{'verbose'});
		return ($arg{'startrec'}, @records);
	} elsif ($@) {
		print "[Error]: $@\n" if ($arg{'verbose'});
		return ($arg{'startrec'}, @records);
	}

	$json = JSON::XS->new->utf8;

	foreach (split (/\|\|/, $stdout)) {
		eval {
			my (@userMeta);

			$_ =~ s/\r|\n|\0|\t/:::/ig;

			foreach my $slice (split (/:::/, $_)) {
				$slice =~ s/^://;
				push (@userMeta, $slice) if ($slice);
			}

			$_ =~ s/:::/\ /ig;
			my $obj = $json->decode($_);
			$userMeta[0] = $obj->{'event_id'};
			$userMeta[1] = $obj->{'message'} =~ m/an account was successfully logged on/i ? '0' : '1';
			$obj->{'logname'} = uc($obj->{'logname'});

			foreach my $event (@userIdentityEvents) {
				push (@{$obj->{'user_meta'}}, @userMeta)
					if ($userMeta[0] eq $event);
			}

			#print Dumper $obj if ($arg{'verbose'} > 1);
			push (@records, $obj);
			$arg{'startrec'} = $arg{'startrec'} < $obj->{'record_id'} ? $obj->{'record_id'} : $arg{'startrec'};
		};

		if ($@) {
			open (my $err, ">>", "ipfixify_json.err");
			print $err "RAW: $_\n";
			print $err "ERROR: $@\n";
			close($err);
		}
	}

	return ($arg{'startrec'}, @records);
}

#####################################################################

=pod

=head2 eventLogLastID

this function manages the last eventlog event ID for polling multiple
system.

=over 2

	$z = &ipfixify::sysmetrics::eventLogLastID(
		flowcacheid		=> $arg{'flowcacheid'},
		computer		=> $arg{'computer'},
		action			=> [SET|SETUSER|GET|GETUSER],
		eventid			=> $y
	);

=back

The currently supported parameters are:

=over 2

=item * flowcacheid

which flowcache are we tracking an eventlog ID

=item * computer

the computer that we're tracking event log IDs

=item * action

an action of GET retreives the last ID. An action of SET will store
the last read eventlog ID for future polling.

=item * eventid

This is the eventid to store when the action is SET

=back

What is returned is the eventid to use as a starting point. New
entries will return UNDEF

=cut

sub eventLogLastID {
	my (%arg);
	my ($dbh, $eventid, $query, $ref, $sth, $table);

	%arg = (@_);

	$dbh = DBI->connect
	  (
	   "dbi:SQLite:dbname=$ENV{'TMPDIR'}/sysmetrics.db",
	   "",
	   "",
	   { RaiseError => 1, AutoCommit => 1}
	  );

	$table = $arg{action} =~ m/USER/ig ? 'usereventlogs' : 'eventlogs';

	if ($arg{'action'} =~ m/GET/) {
		$query = qq {
			SELECT lastEvent FROM $table
			WHERE
			computer = '$arg{'computer'}' AND
			flowcacheid = '$arg{'flowcacheid'}'
		};

		$sth = $dbh->prepare($query);
		$sth->execute();
		$ref = $sth->fetchrow_hashref();
		$sth->finish();

		if ($ref->{'lastEvent'}) {
			$eventid = $ref->{'lastEvent'};
		} else {
			$query = qq {
				INSERT INTO $table
				(computer, flowcacheid, lastEvent)
				VALUES
				('$arg{'computer'}', $arg{'flowcacheid'}, '0')
			};

			$dbh->do($query);

			$eventid = undef;
		}
	} elsif ($arg{'action'} =~ m/SET/) {
		$query = qq {
			UPDATE $table
			SET lastEvent = '$arg{'eventid'}'
			WHERE
			computer = '$arg{'computer'}' AND
			flowcacheid = '$arg{'flowcacheid'}'
		};

		$sth = $dbh->prepare($query);
		$sth->execute();
		$ref = $sth->fetchrow_hashref();
		$sth->finish();
		$eventid = $arg{'eventid'};
	}

	$dbh->disconnect() if ($dbh);
	return $eventid;
}

#####################################################################

=pod

=head2 eventLogParse

This function takes all the gathered eventlogs and parses them in ways
to suit IPFIX exports

=over 2

	$timer = &ipfixify::sysmetrics::eventLogParse(
		flowcacheid => $cacheid,
		lastX       => $lastX,
		eventlog	=> $el,
		elh			=> $events,
		tid			=> $arg{'thread_id'},
		flowCache	=> \%flowCache,
		computer	=> $arg{'computer'},
		originator	=> $arg{'originator'},
		machineID	=> $machineID,
		verbose		=> $verbose
	);

=back

The currently supported parameters are:

=over 2

=item * flowcacheid

the flow cache for the eventlog. 1 (System), 2 (Application), 3
(security)

=item * lastX

the number of eventlogs to go back and gather. This is used for
profile testing mostly.

=item * eventlog

Which EventLog are we grabbing? System, Application, Security, etc.

=item * elh

The eventlog handle used to connect to the eventlog

=item * tid

thread ID for log purposes

=item * flowcache

A reference to the flowcache so we can append to it data from
eventlogs and user identity

=item * computer

The IP address of the system we're gathering eventlogs

=item * originator

the IP address of our agent (the originator of the IPFIX data).

=item * machineID

the unique identifer for this machine

=item * verbose

if true, enables verbose mode

=back

The returned value is a high resolution time of how long it took to
parse the data.

=cut

sub eventLogParse {
	my (%arg);
	my (@eventfilter, @records);
	my ($stopwatch, $lastrec);

	%arg = (@_);

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];

	&ipfixify::sysmetrics::createDb();

	if ($arg{'lastX'}) {
		$lastrec = $arg{'elh'}->get_last_record_id($arg{'eventlog'});
		$lastrec = $lastrec - ($arg{'lastX'} - 1);
	} else {
		$lastrec = &ipfixify::sysmetrics::eventLogLastID
		  (
		   flowcacheid	=> $arg{'flowcacheid'},
		   computer		=> $arg{'computer'},
		   action		=> 'GET'
		  );

		if (not defined $lastrec) {
			$lastrec = $arg{'elh'}->get_last_record_id($arg{'eventlog'});

			$lastrec = &ipfixify::sysmetrics::eventLogLastID
			  (
			   flowcacheid	=> $arg{'flowcacheid'},
			   computer		=> $arg{'computer'},
			   action		=> 'SET',
			   eventid		=> $lastrec
			  );
		}
	}

	($lastrec, @records) = &ipfixify::sysmetrics::eventLogGrab
	  (
	   eventlog	=> $arg{'eventlog'},
	   elh		=> $arg{'elh'},
	   cfg		=> $arg{'cfg'},
	   tid		=> $arg{'tid'},
	   startrec	=> $lastrec,
	   verbose	=> $arg{'verbose'}
	  );

	foreach (@records) {
		my ($elFlow, $userFlow, $user, $record, $flow, $tmplUsed);

		print "+ Fetching Eventlog ($arg{'eventlog'}) ".
		  "Record $_->{'record_id'}\n"
			if ($arg{'verbose'} > 1);

		($user, $userFlow, $tmplUsed) = &ipfixify::parse::userNameFlow
		  (
		   'record'		=> $_->{user_meta},
		   'computer'	=> $arg{'computer'},
		   'originator'	=> $arg{'originator'},
		   'machineID'	=> $arg{'machineID'}
		  );

		push
		  (
		   @{ $arg{'flowCache'}->{$tmplUsed}{'flows'}{'SPOOL'} },
		   $userFlow
		  )	if ($userFlow);

		push
		  (
		   @{$arg{flowCache}->{$arg{flowcacheid}}{'flows'}{'SPOOL'}},
		   &ipfixify::parse::fileLine
		   (
			'line'			=> $_,
			'eventlog'		=> uc($arg{'eventlog'}),
			'cfg'			=> $arg{'cfg'},
			'computer'		=> $arg{'computer'},
			'originator'	=> $arg{'originator'},
			'machineID'		=> $arg{'machineID'},
			'verbose'		=> $arg{'verbose'},
		   )
		  ) if ($arg{'cfg'}->{'eventlogs'});

		$lastrec = $lastrec < $record->{'record_id'} ? $record->{'record_id'} : $lastrec;
	}

	if (! $arg{'lastX'}) {
		$lastrec = &ipfixify::sysmetrics::eventLogLastID
		  (
		   flowcacheid		=> $arg{'flowcacheid'},
		   computer		=> $arg{'computer'},
		   action			=> 'SET',
		   eventid			=> $lastrec
		  );

		print "+ Current placeholder set on EventLog ".
		  "($arg{'eventlog'}) Record $lastrec\n"
			if ($arg{'verbose'} > 1);
	}

	return Time::HiRes::tv_interval( $stopwatch );
}

#####################################################################

=pod

=head2 getMachineID

This function will generate a machine ID for the host polled

=over 2

	$machineID = &ipfixify::sysmetrics::getMachineID(
		'handle'	=> [$ssh|$dbh],
		'local'		=> [0|1]
	);

=back

The currently supported parameters are:

=over 2

=item * handle

The scalar that represents the ssh connection or wmi object

=item * local

If true, the data is from the local machine and not a remote
machine. this is important more for the linux platform than windows

=item * poller

If true, this mode retrieves the machineID from a file and is used by
the collection statistics flows

=back

The resulting machine ID should uniquely identify this name is
returned.

=cut

sub getMachineID {
	my (%arg);
	my ($uuid, $sid, $midf);

	%arg = (@_);

	$midf = "$ENV{TMPDIR}/$arg{'computer'}.machineid";

	if ($arg{'poller'}) {
		if (-e $midf) {
			open (my $mid, '<', $midf);
			$uuid = <$mid>;
			close($mid);
			return $uuid;
		} else {
			return;
		}
	} else {
		if ($^O eq 'MSWin32') {
			my (%sid, %uuid);

			(undef, %uuid) = &ipfixify::sysmetrics::wmiVitalsGrabber
			  (
			   'dbh'	=> $arg{'handle'},
			   'query'	=> 'SELECT * FROM Win32_ComputerSystemProduct',
			   'value'	=> 'UUID',
			  );

			(undef, %sid) = &ipfixify::sysmetrics::wmiVitalsGrabber
			  (
			   'dbh'	=> $arg{'handle'},
			   'query'	=> "SELECT * FROM Win32_UserAccount WHERE Name='Administrator'",
			   'value'	=> 'SID',
			   'sid'	=> 1
			  );

			$uuid = $uuid{UUID};
			$sid = $sid{sid};
		} else {
			$sid = &ipfixify::sysmetrics::linuxCommandGrabber
			  (
			   ssh		=> $arg{'handle'},
			   command	=> '/bin/cat ~/.ipfixify_machine_id',
			   local	=> $arg{'local'},
			   chop		=> 1
			  );


			if (! $sid) {
				$sid = &ipfixify::sysmetrics::linuxCommandGrabber
				  (
				   ssh		=> $arg{'handle'},
				   command	=> '/bin/cat /proc/sys/kernel/random/uuid > ~/.ipfixify_machine_id',
				   local	=> $arg{'local'},
				   chop		=> 1
				  );

				$sid = &ipfixify::sysmetrics::linuxCommandGrabber
				  (
				   ssh		=> $arg{'handle'},
				   command	=> '/bin/cat ~/.ipfixify_machine_id',
				   local	=> $arg{'local'},
				   chop		=> 1
				  );
			}
		}

		if (! -e $midf) {
			open (my $mid, '>', $midf);
			print $mid md5_hex("$uuid:$sid");
			close($mid);
		}
	}

	return md5_hex("$uuid:$sid");
}

#####################################################################

=pod

=head2 linuxCommandGrabber

This function will use ssh and execute linux commands.

=over 2

	$output = &ipfixify::sysmetrics::linuxCommandGrabber
	  (
	   ssh		=> $ssh,
	   command	=> command,
	   local	=> [1|0],
	   chop		=> [1|0],
	   multi	=> [1|0]
	  );

=back

The currently supported parameters are:

=over 2

=item * ssh

The scalar that represents the ssh connection. Will be blank for local
connections

=item * command

The command to execute

=item * local

If true, indicates the command should be executed locally.

=item * chop

If true, the last character of the output needs to be chopped. this is
likely due to the line feed or carriage return.

=item * multi

if true, the command will produce multiple lines of output that we
want.

=back

The returned value is the output of the command.

=cut

sub linuxCommandGrabber {
	my (%arg);
	my ($cmd);

	%arg = (@_);

	if ($arg{'local'}) {
		$cmd = `$arg{'command'}`;
	} else {
		$cmd = $arg{'ssh'}->exec($arg{'command'});
	}

	if ($arg{'multi'}) {
		my @partitions = split (/\n/, $cmd);
		shift(@partitions);
		return @partitions;
	} else {
		($cmd, undef) = split (/\n|\\/, $cmd);
		$cmd =~ s/\n|\r|\0|\t//ig;
		return $cmd;
	}
}

#####################################################################

=pod

=head2 linuxInterfaceGrabber

This function will use ssh and query interface information

=over 2

	($timer, %results) = &ipfixify::sysmetrics::linuxInterfaceGrabber(
		'ssh'		=> $ssh,
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

=back

The currently supported parameters are:

=over 2

=item * ssh

The scalar that represents the ssh connection

=item * host

the current machine host to help maintain the sha256 hash

=item * originator

the IP address of the system where the agent is running

=back

The returned %results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub linuxInterfaceGrabber {
	my (%arg, %value);
	my (@row);
	my ($cmd, $stopwatch);

	%arg = @_;

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];

	if ($arg{'originator'} eq $arg{'host'}) {
		$cmd = `/sbin/ip -o addr show | grep 'global'`;
	} elsif ($^O eq 'linux') {
		$cmd = $arg{'ssh'}->exec("/sbin/ip -o addr show | grep 'global'");
	} else {
		# this os isn't supported
		return (Time::HiRes::tv_interval( $stopwatch ), %value);
	}

	@row = split (/\n/, $cmd);

	foreach (@row) {
		my (@int);

		$_ =~ s/\s+/\|/ig;

		@int = split (/\|/, $_);

		foreach my $stat ('rx_bytes','tx_bytes','rx_packets','tx_packets') {
			if ($arg{'originator'} eq $arg{'host'}) {
				$value{$int[1]}{$stat} = int(`/bin/cat /sys/class/net/$int[1]/statistics/$stat`);
			} elsif ($^O eq 'linux') {
				$value{$int[1]}{$stat} = int($arg{'ssh'}->exec("/bin/cat /sys/class/net/$int[1]/statistics/$stat"));
			}
		}

		if ($arg{'originator'} eq $arg{'host'}) {
			$value{$int[1]}{ifIndex} = int(`/bin/cat /sys/class/net/$int[1]/ifindex`);
			$value{$int[1]}{macaddress} = `/bin/cat /sys/class/net/$int[1]/address`;
			$value{$int[1]}{portspeed} = int(`/bin/cat /sys/class/net/$int[1]/speed`) * 1000000;
		} elsif ($^O eq 'linux') {
			$value{$int[1]}{ifIndex} = int($arg{'ssh'}->exec("/bin/cat /sys/class/net/$int[1]/ifindex"));
			$value{$int[1]}{macaddress} = $arg{'ssh'}->exec("/bin/cat /sys/class/net/$int[1]/address");
			$value{$int[1]}{portspeed} = int($arg{'ssh'}->exec("/bin/cat /sys/class/net/$int[1]/speed")) * 1000000;
		}

		chop($value{$int[1]}{macaddress});
	}

	return (Time::HiRes::tv_interval( $stopwatch ), %value);
}

#####################################################################

=pod

=head2 linuxProcessGrabber

This function grabs running process information from a linux machine

=over 2

	($timer, %results) = &ipfixify::sysmetrics::linuxProcessGrabber(
		'ssh'		=> $ssh,
		'grabCpu'	=> $cfg{'processListsCPU'},
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

=back

The currently supported parameters are:

=over 2

=item * ssh

the handle to the ssh connection

=item * grabCpu

flag to indicate if we grab CPU per process.

=item * host

the current machine host to help maintain the sha256 hash

=item * originator

the IP address of the system where the agent is running

=back

The returned %results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub linuxProcessGrabber {
	my (%arg, %value, %sha);
	my (@row);
	my ($cmd, $stopwatch, $epoch);

	%arg = @_;

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];
	$epoch = time();

	if ($arg{'originator'} eq $arg{'host'}) {
		$cmd = `/bin/ps -e -o ppid,pid,c,rss,vsz,ruser,comm,args`;
	} elsif ($^O eq 'linux') {
		$cmd = $arg{'ssh'}->exec("/bin/ps -e -o ppid,pid,c,rss,vsz,ruser,comm,args");
	} else {
		# This OS isn't supported
		return;
	}

	@row = split (/\n/, $cmd);
	shift(@row);

	if ($arg{'originator'} eq $arg{'host'}) {
		foreach (@row) {
			my (@line, @procs);

			$_ =~ s/\0|\r|\n|\t/\ /ig;
			$_ =~ s/^\s+//;

			foreach my $match (1..7) {
				$_ =~ s/\s+/\|/;
			}

			my @line = split (/\|/, $_);
			$line[7] =~ s/\s+/\ /ig;

			if (-e "/proc/$line[1]/exe") {
				(undef, $line[8]) = split (/-\>\ /, `/bin/ls -l /proc/$line[1]/exe`);
				chop($line[8]);

				if ($sha{exe}{$line[8]}{expiry} < $epoch ) {
					my $sw = [ Time::HiRes::gettimeofday( ) ];
					open (my $file, "<:raw", $line[8]);

					$sha{exe}{$line[8]} = {
						host => $arg{'host'},
						exe => $line[8],
						sha256 => sha256_hex(<$file>),
						expiry => time() + 30,
						calctime => Time::HiRes::tv_interval( $sw )
					};

					close($file);

					$sha{pid}{$line[1]} = {
						host => $arg{'host'},
						exe => $line[8],
						name => $line[6],
						sha256 => $sha{exe}{$line[8]}{sha256},
					};
				}
			}
		}
	}

	foreach (@row) {
		my (
			$ppid, $pid, $cpu, $mem, $vmem, $user, $name, $command,
			$exepath, $match
		);
		my (@line);

		$_ =~ s/\0|\r|\n|\t/\ /ig;
		$_ =~ s/^\s+//;

		foreach $match (1..7) {
			$_ =~ s/\s+/\|/;
		}

		@line = split (/\|/, $_);
		$line[7] =~ s/\s+/\ /ig;

		($ppid, $pid, $cpu, $mem, $vmem, $user, $name, $command, $exepath) =
		  split (/\|/, $_);

		$value{$pid} = {
			Caption				=> $name,
			CommandLine			=> $command,
			ExecutablePath		=> $exepath,
			HandleCount			=> '0',
			ProcessUserName		=> $user || '',
			OtherOperationCount => '0',
			OtherTransferCount	=> '0',
			PageFileUsage		=> '0',
			ParentProcessId     => $ppid,
			ParentProcessName   => $sha{pid}{$ppid}{name} || '',
			PrivatePageCount    => '0',
			ProcessId           => $pid,
			ReadOperationCount  => '0',
			ReadTransferCount   => '0',
			ThreadCount         => '0',
			VirtualSize         => $vmem * 1024,
			WorkingSetSize      => $mem * 1024,
			WriteOperationCount	=> '0',
			WriteTransferCount  => '0',
			cpuUsage			=> $cpu,
			shaParentProcessId  => $sha{pid}{$ppid}{sha256} || '',
			shaProcessId		=> $sha{pid}{$pid}{sha256} || '',
		};
	}

	return (Time::HiRes::tv_interval( $stopwatch ), %value);
}

#####################################################################

=pod

=head2 netstatDetails

This function will use Psexec to remotely grab the netstat data.

=over 2

	($timer, @results) = &ipfixify::sysmetrics::netstatDetails(
		'ip'		=> $arg{'ip'},
		'user'		=> $arg{'user'},
		'password'	=> $arg{'password'}
		'psexec'	=> $arg{'psexec'},
		'ssh'		=> $arg{'ssh'}
	);

=back

The currently supported parameters are:

=over 2

=item * ip

The member to remotely connect to grab netstat

=item * user

The administrator user name that can connect remotely.

=item * password

The password for the administrator account.

=item * psexec

The path to psexec for remote execution on the windows platform

=item * ssh

The handle for SSH for remote execution on the linux platform

=back

The returned @results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub netstatDetails {
	my (%arg, %states);
	my ($cmd, $stopwatch, $user, $pwd);
	my (@conns);

	%arg = (@_);

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];

	%states =
	  (
	   'CLOSED' => '8',
	   'CLOSE_WAIT' => '6',
	   'CLOSING' => '9',
	   'ESTABLISHED' => '2',
	   'FIN_WAIT1' => '10',
	   'FIN_WAIT2' => '11',
	   'LAST_ACK' => '5',
	   'LISTEN' => '1',
	   'SYN_RECEIVED' => '4',
	   'SYN_RECV' => '4',
	   'SYN_SEND' => '3',
	   'SYN_SENT' => '3',
	   'TIME_WAIT' => '7',
	   'UNKNOWN' => '0',
	  );


	if ($arg{'originator'} eq $arg{'ip'}) {
		if ($^O eq 'MSWin32') {
			$cmd = `c:\\windows\\system32\\netstat.exe -aon 2\> nul`;
		} elsif ($^O eq 'linux') {
			$cmd = `/bin/netstat -atunp`;
		} else {
			# This OS isn't supported
			return;
		}
	} else {
		if ($^O eq 'MSWin32') {
			return if (! -e $arg{'psexec'});

			$user = $arg{'user'} ? "-u $arg{'user'}" : '';
			$pwd = $arg{'password'} ? "-p $arg{'password'}" : '';

			$cmd = join
			  (
			   ' ',
			   "\"$arg{'psexec'}\"",
			   "\\\\$arg{'ip'}",
			   $user,
			   $pwd,
			   "-n 20 -high",
			   '"c:\\windows\\system32\\netstat.exe" -aon',
			   "2\> nul"
			  );

			$cmd = `$cmd`;
		} elsif ($^O eq 'linux') {
			$cmd = $arg{'ssh'}->exec("/bin/netstat -atunp");
		} else {
			# This OS isn't supported
			return;
		}
	}

	foreach my $line (split /^/, $cmd) {
		my (
			$proto, $local, $foreign, $state, $pid, $srcIp, $srcPort,
			$dstIp, $dstPort, $prog
		);

		$line =~ s/\s+/\|/g;
		$line =~ s/:::/0.0.0.0:/ig;
		$line =~ s/\[::\]/0.0.0.0/ig;
		$line =~ s/\[::1\]/127.0.0.1/ig;
		$line =~ s/\*:\*/0.0.0.0:0/ig;
		$line =~ s/:\*/:0/ig;

		if ($^O eq 'MSWin32') {
			if ($line =~ m/^\|tcp/i) {
				(undef, $proto, $local, $foreign, $state, $pid) = split (/\|/, $line);
				$proto = '6';
			} elsif ($line =~ m/^\|udp/i) {
				(undef, $proto, $local, $foreign, $pid) = split (/\|/, $line);
				$proto = '17';
			}
		} elsif ($^O eq 'linux') {
			if ($line =~ m/^tcp/i) {
				(undef, undef, undef, $local, $foreign, $state, $pid) = split (/\|/, $line);
				($pid, $prog) = split (/\//, $pid);
				$proto = '6';
			} elsif ($line =~ m/^udp/i) {
				(undef, undef, undef, $local, $foreign, $pid) = split (/\|/, $line);
				($pid, $prog) = split (/\//, $pid);
				$proto = '17';
			}
		} else {
			next;
		}

		$state = $states{uc($state)} ? $states{uc($state)} : '0';

		($srcIp, $srcPort) = split (/:/, $local);
		($dstIp, $dstPort) = split (/:/, $foreign);

		if (! &ipfixify::parse::v_ip($srcIp)) {
			#Here is where we would test for IPv6 as well
			#for full support we would need another template
			#might as well do all of sysmetric at the same time
			next;
		}
		push @conns, "$proto|$srcIp|$srcPort|$dstIp|$dstPort|$state|$pid";
	}

	return (Time::HiRes::tv_interval( $stopwatch ), @conns);
}

#####################################################################

=pod

=head2 pingTest

This function pings system metrics hosts and will also do a connect
test.

=over 2

	$pass = &ipfixify::sysmetrics::pingTest(
		computer		=> $computer,
		debug_system	=> "+ $shortTime ".sprintf('%-15s',$computer),
		verbose			=> $verbose,
		pingtimeout		=> $cfg{'pingtimeout'},
		originator		=> $originator,
		cfg				=> \%cfg
	);

=back

The currently supported parameters are:

=over 2

=item * computer

The member to ping and/or connect test

=item * debug_system

The text used for CLI output if enabled

=item * verbose

The level of verbosity to output

=item * pingtimeout

the number of seconds set aside for ping testing

=item * cfg

A copy of the configuration file

=back

if ping suceeds, then 1 is returned. Otherwise, 0 is returned.

=cut

sub pingTest {
	my (%arg);
	my ($cmd, $dbh, $services);

	%arg = (@_);

	if (! $arg{'pingtimeout'}) {
		print "$arg{'debug_system'} DISABLED (SKIPPING)\n"
		  if ($arg{'verbose'});

		return 1;
	}

	if ($^O eq 'MSWin32') {
		eval {
			if ($arg{'computer'} eq $arg{'originator'}) {
				$dbh = DBI->connect('dbi:WMI:');
			} else {
				$dbh = DBI->connect("dbi:WMI:$arg{'computer'}");
			}
		};

		if ($@) {
			print "$arg{'debug_system'} FAILED\n" if ($arg{'verbose'});
			return 0;
		} else {
			print "$arg{'debug_system'} PASSED\n" if ($arg{'verbose'});
			return (1, $dbh);
		}
	} elsif ($^O eq 'linux') {
		if ($arg{'computer'} eq $arg{'originator'}) {
			print "$arg{'debug_system'} PASSED\n" if ($arg{'verbose'});
			return 1;
		} else {
			my ($output, $ssh);

			eval {
				$ssh = Net::SSH::Expect->new
				  (
				   host			=> $arg{'computer'},
				   password		=> $arg{'cfg'}->{'pwd'},
				   user			=> $arg{'cfg'}->{'user'},
				   raw_pty		=> 1,
				   timeout		=> $arg{'pingtimeout'},
				  );

				$output = $ssh->login();
			};

			$ssh->close() if ($ssh);

			if ($output =~ m/last login/i) {
				print "$arg{'debug_system'} PASSED\n"
				  if ($arg{'verbose'});

				return 1;
			} elsif ($output =~ m/permission denied/i) {
				print "$arg{debug_system} FAILED (Login Credentials)\n"
				  if ($arg{'verbose'});

				return 0;
			} else {
				print "$arg{'debug_system'} FAILED\n"
				  if ($arg{'verbose'});

				return 0;
			}
		}
	}

	print "$arg{'debug_system'} unsupported OS ERROR\n"
	  if ($arg{'verbose'});

	return 0;
}

#####################################################################

=pod

=head2 profiling

This function profiles members configured in the ipfixify.cfg file and gives
some overall statistics and performance information.

Error codes from Microsoft can be found at

https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx

=over 2

	&ipfixify::sysmetrics::profiling(
	   config   => $config,
       member   => $memberIP,
	   lastX    => $lastX,
	   psexec   => $psexec,
	   cfg		=> \%cfg
	);

=back

The currently supported parameters are:

=over 2

=item * config

the path and file name to the configuration file

=item * member

if this optional parameter is true, this will be the only IP profiled

=item * lastX

If present, profiling will go back X records for the newest record ID

=item * psexec

the path and file name to psexec on windows

=item * cfg

A copy of the configuration file

=back

The return output is a profile report.

=cut

sub profiling {
	my (%arg, %results, %errors);
	my ($data, $member, $lastX);
	my (@errors, @file, @members);

	%arg = (@_);

	if ($arg{'member'}) {
		push (@members, $arg{'member'});
	} else {
		@members = @{$arg{'cfg'}->{members}};
	}

	foreach (@members) {
		my ($psexec, $cmdline);

		print "+ profiling $_ ... ";

		if ($arg{psexec}) {
			$psexec = "--psexec $arg{psexec}";
		}

		if ($arg{lastX}) {
			$lastX = "--last $arg{'lastX'}";
		}

		$cmdline = join
		  (
		   ' ',
		   './ipfixify.exe',
		   "--config $arg{'config'}",
		   $psexec,
		   '--verbose',
		   '--debug',
		   $lastX,
		   '--syspoll',
		   $_
		  );

		push
		  (
		   @file,
		   "----------------------------------\n",
		   "$cmdline\n",
		   `$cmdline`
		  );

		print "Done!\n";
	}

	chomp(@file);

	foreach (@file) {
		$_ =~ s/\r|\n|\0//ig;

		if ($_ =~ m/syspoll/i) {
			my (undef, $device) = split (/--syspoll /, $_);
			($member, undef) = split (/::/, $device);
			$results{$member}{'events'}{'total'} = 0;
			$results{$member}{'errors'}{'status'} = 'OK';
		}

		if ($_ =~ m/following windows error/i) {
			my @line = split (/ /, $_);
			my $error = pop(@line);
			$error =~ s/\0|\r|\n|\.//ig;

			if ($error eq '5') {
				$error = '5 (Access Denied)';
			} elsif ($error eq '1722') {
				$error = '1722 (rpc server unavailable)';
			} elsif ($error eq '1753') {
				$error = '1753 (no more endpoints available '.
				  'from the endpoint mapper)';
			} else {
				$error = "$error (unknown)";
			}

			$results{$member}{errors}{code} = $error;

			push (@errors, $error) unless ($errors{$error});

			$errors{$error} = 1;

			$results{$member}{'errors'}{'status'} = 'ERROR';
		}

		if ($_ =~ m/Fetching Eventlog \(SECURITY\)/i) {
			$results{$member}{'events'}{'total'}++;
			my @line = split (/ /, $_);
			$results{$member}{'events'}{'start'} = $line[5]
			  if (! $results{$member}{'event'}{'start'});
		}

		if ($_ =~ m/: EventLog \(SECURITY\)/) {
			$_ =~ s/\s+/\ /ig;
			my @line = split (/ /, $_);
			$results{$member}{'events'}{'collect_time'} = $line[5];
			$results{$member}{'events'}{'collect_time'} =~ s/\)//ig;

			$results{$member}{'events'}{'per_second'} =
			  sprintf
				(
				 '%.2f',
				 $results{$member}{'events'}{'total'} /
				 $results{$member}{'events'}{'collect_time'}
				);
		}
	}

	foreach (sort {$results{$b}{events}{total} <=> $results{$a}{events}{total}} keys %results) {
		if ($arg{cfg}->{pollTimeOut} < $results{$_}{events}{collect_time}) {
			push
			  (
			   @errors,
			   "$_ took longer than pollTimeOut, ".
			   "increase pollTimeOut ($arg{cfg}->{pollTimeOut})"
			  );
		}

		if (! $results{$_}{events}{start}) {
			$results{$_}{errors}{status} = 'No Data';
			$results{$_}{'events'}{'start'} = '-';
			$results{$_}{events}{total} = '-';
			$results{$_}{events}{per_second} = '-';
			$results{$_}{events}{collect_time} = '-';
		}

		$data .=
		  sprintf('%-16s', $_).
		  sprintf('%-8s', $results{$_}{errors}{status}).
		  sprintf('%-7s', int($results{$_}{errors}{code})).
		  sprintf('%-12s', $results{$_}{'events'}{'start'}).
		  sprintf('%-10s', $results{$_}{events}{total}).
		  sprintf('%-8s', $results{$_}{events}{per_second}).
		  sprintf('%-16s', sec2string($results{$_}{events}{collect_time})).
		  "\n";

		if ($arg{lastX}) {
			my $total = $results{$_}{events}{total} || '0';
			push
			  (
			   @errors,
			   "$_ had $total user events (out of $arg{lastX}) ".
			   int($results{$_}{events}{total}/$arg{lastX} * 100). '%'
			  );
		}
	}

	if ($data) {
		print "\n".
		  sprintf('%-16s', 'Member').
		  sprintf('%-8s', 'Status').
		  sprintf('%-7s', 'Err #').
		  sprintf('%-12s', '1st Rec').
		  sprintf('%-10s', 'Events').
		  sprintf('%-8s', '/Sec').
		  sprintf('%-16s', 'Time').
		  "\n".
		  '-'x77 ."\n".
		  $data.
		  '-'x77 ."\n".
		  "\n";

		print "Legend: ". Dumper \@errors;
		print "\n";
	} else {
		print "\nNo Results, check configuration and run a permtest first";
		print " ... Abort!\n\n";
	}

	return;
}

sub sec2string {
	my $T = shift;

	my @out = reverse($T%60, ($T/=60) % 60, ($T/=60) % 24, ($T/=24) );
	my $out=sprintf "%03dd %02dh %02dm %02ds", @out;
	$out=~s/^000d |00h |00m //g;

	return $out;
}

#####################################################################

=pod

=head2 sampling

This function prints the output that IPFIXify expects to process
usernames. This data directly coorelates to the usernameflow parsing
function.

=over 2

	&ipfixify::sysmetrics::sampling(
	   cfg		=> \%cfg,
	   debug    => $debug,
	   member   => $sample,
	   record   => $sampleRecord
	);

=back

The currently supported parameters are:

=item * cfg

A copy of the configuration file

=item * debug

a flag whether debug mode is enabled

=item * member

the IP address to test

=item * record

the record number of retreive. Absense of this parameter means grab
last event.

=back

The return output is a sample report.

=cut

sub sampling {
	my (%arg);
	my ($eventLog, $json, $log, $mode, $rec, $stdout, $stderr);

	%arg = (@_);

	$json = JSON::XS->new->utf8;
	$mode = $arg{'debug'} ? '2' : '0';

	$eventLog = Plixer::EventLog->new
	  (
	   $arg{member},
	   $arg{cfg}->{user},
	   $arg{cfg}->{pwd},
	   $mode
	  );

	$log = 'SECURITY';
	$rec = $arg{record} ? $arg{record} : $eventLog->get_last_record_id($log);

	($stdout, $stderr) = eval {
		capture {
			$eventLog->parse
			  (
			   eventlog => $log,
			   startrec => $rec,
			   endrec => $rec,
			  );
		};
	};

	if ($@) { print "$@\n"; }

	if ($mode eq '2') {
		print "\n------------------------------\n";
		print "stdout\n\n$stdout\n";
		print "\n\stderr\n\n$stderr\n" if ($stderr);
		return;
	}

	foreach (split (/\|\|/, $stdout)) {
		eval {
			my (@userMeta);
			my $sliceNumber = '0';

			$_ =~ s/\r|\n|\0|\t/:::/ig;

			foreach my $slice (split (/:::/, $_)) {
				$slice =~ s/^://;
				if ($slice) {
					push (@userMeta, "$sliceNumber : $slice");
					$sliceNumber++;
				}
			}

			$_ =~ s/:::/\ /ig;

			my $obj = $json->decode($_);
			$userMeta[0] = "0 : $obj->{'event_id'}";
			$obj->{'logname'} = uc($obj->{'logname'});

			$userMeta[1] = $obj->{'message'} =~ m/an account was successfully logged on/i ? '1 : 0' : '1 : 1';

			push (@{$obj->{'user_meta'}}, @userMeta);
			print Dumper $obj;
		}
	};

	if ($@) {
		print "\nRAW: $_\n";
		print "\nERROR: $@\n";
	}

	return;
}

#####################################################################

=pod

=head2 wmiInterfaceGrabber

This function will use WMI and query interface information

=over 2

	($timer, %results) = &ipfixify::sysmetrics::wmiInterfaceGrabber(
		'dbh'		=> $dbh,
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

=back

The currently supported parameters are:

=over 2

=item * dbh

The scalar that represents the WMI connection

=item * host

the current machine host to help maintain the sha256 hash

=item * originator

the IP address of the system where the agent is running

=back

The returned %results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub wmiInterfaceGrabber {
	my (%arg, %value);
	my (@row);
	my ($cmd, $sth, $stopwatch);

	%arg = @_;

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];

	$sth = $arg{'dbh'}->prepare("SELECT Name, InterfaceIndex, MACAddress FROM Win32_NetworkAdapter WHERE PhysicalAdapter='True'");
	$sth->execute;

	while (@row = $sth->fetchrow) {
		$row[0] =~ s/\(/\[/ig;
		$row[0] =~ s/\)/\]/ig;
		$row[0] =~ s/\//\_/ig;

		my $ath = $arg{'dbh'}->prepare("SELECT BytesReceivedPersec, BytesSentPersec, PacketsReceivedPersec, PacketsSentPersec, CurrentBandwidth FROM Win32_PerfRawData_Tcpip_NetworkInterface WHERE Name='$row[0]'");
		$ath->execute;

		while (my @int = $ath->fetchrow) {
			$value{$row[0]} =
			  {
			   octets_rx	=> $int[0],
			   octets_tx	=> $int[1],
			   packets_rx	=> $int[2],
			   packets_tx	=> $int[3],
			   portspeed	=> $int[4],
			   ifIndex		=> $row[1],
			   macaddress	=> $row[2],
			  }
		  }
	}

	return (Time::HiRes::tv_interval( $stopwatch ), %value);
}

#####################################################################

=pod

=head2 wmiProcessGrabber

This function will use WMI and query running process data

=over 2

	($timer, %results) = &wmiProcessGrabber(
		'dbh'		=> $dbh,
		'cpuCount'  => $processors{'NumberOfLogicalProcessors'},
		'grabCpu'	=> $cfg{'processListsCPU'},
		'host'		=> $arg{'computer'}
		'originator'=> $arg{'originator'}
	);

=back

The currently supported parameters are:

=over 2

=item * dbh

The scalar that represents the WMI connection

=item * cpuCount

We need this in order to properly calculate CPU per process. Can get
it by calling wmiVitalGrabber for

SELECT NumberOfLogicalProcessors FROM Win32_Processor

=item * grabCpu

flag to indicate if we grab CPU per process.

=item * host

the current machine host to help maintain the sha256 hash

=item * originator

the IP address of the system where the agent is running

=back

The returned %results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub wmiProcessGrabber {
	my (%arg, %value, %sha);
	my (@row);
	my ($cmd, $sth, $stopwatch, $epoch);

	%arg = @_;

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];
	$epoch = time();

	$sth = $arg{'dbh'}->prepare('SELECT * FROM Win32_Process');

	if ($arg{'originator'} eq $arg{'host'}) {
		$sth->execute;

		while (@row = $sth->fetchrow) {
			next if ($row[0]->{'Name'} eq 'System Idle Process'|| ! $row[0]->{'Name'});

			if ($sha{$row[0]->{'ExecutablePath'}}{expiry} < $epoch ) {
				my $sw = [ Time::HiRes::gettimeofday( ) ];
				open (my $file, "<:raw", $row[0]->{'ExecutablePath'});

				$sha{exe}{$row[0]->{'ExecutablePath'}} =
				  {
				   host => $arg{'host'},
				   exe => $row[0]->{'ExecutablePath'},
				   sha256 => sha256_hex(<$file>),
				   expiry => time() + 30,
				   calctime => Time::HiRes::tv_interval( $sw )
				  };

				close($file);
			}

			$sha{pid}{$row[0]->{'ProcessId'}} =
			  {
			   host => $arg{'host'},
			   exe => $row[0]->{'ExecutablePath'},
			   name => $row[0]->{'Name'},
			   sha256 => $sha{exe}{$row[0]->{ExecutablePath}}{sha256},
			  };
		}
	}

	$sth->execute;

	while (@row = $sth->fetchrow) {
		my $pid;
		next if ($row[0]->{'Name'} eq 'System Idle Process'|| ! $row[0]->{'Name'});

		$pid = $row[0]->{'ProcessId'};

		$value{$pid} = {
			Caption				=> $row[0]->{'Name'},
			CommandLine			=> $row[0]->{'CommandLine'},
			ExecutablePath		=> $row[0]->{'ExecutablePath'},
			HandleCount			=> $row[0]->{'HandleCount'},
			ProcessUserName		=> '', # execute .method.getOwner()
			OtherOperationCount => $row[0]->{'OtherOperationCount'},
			OtherTransferCount	=> $row[0]->{'OtherTransferCount'},
			PageFileUsage		=> $row[0]->{'PageFileUsage'} * 1024,
			ParentProcessId     => $row[0]->{'ParentProcessId'},
			ParentProcessName   => $sha{pid}{$row[0]->{'ParentProcessId'}}{name} || '',
			PrivatePageCount    => $row[0]->{'PrivatePageCount'},
			ProcessId           => $pid,
			ReadOperationCount  => $row[0]->{'ReadOperationCount'},
			ReadTransferCount   => $row[0]->{'ReadTransferCount'},
			ThreadCount         => $row[0]->{'ThreadCount'},
			VirtualSize         => $row[0]->{'VirtualSize'},
			WorkingSetSize      => $row[0]->{'WorkingSetSize'},
			WriteOperationCount	=> $row[0]->{'WriteOperationCount'},
			WriteTransferCount  => $row[0]->{'WriteTransferCount'},
			cpuUsage			=> 0,
			shaParentProcessId  => $sha{pid}{$row[0]->{'ParentProcessId'}}{sha256} || '',
			shaProcessId		=> $sha{pid}{$pid}{sha256} || '',
		};
	}

	# CALCULATING PROCESS CPU
	# http://forums.cacti.net/viewtopic.php?f=12&t=33964
	# (divide by # of processors) http://msdn.microsoft.com/en-us/library/windows/desktop/aa394323(v=vs.85).aspx

	if ($arg{'grabCpu'} && $arg{'cpuCount'}) {
		$sth = $arg{'dbh'}->prepare('SELECT * FROM Win32_PerfRawData_PerfProc_Process');
		$sth->execute;

		while (@row = $sth->fetchrow) {
			next if (! $value{$row[0]->{'IDProcess'}}{'Caption'});
			$value{$row[0]->{'IDProcess'}}{'N1'} = $row[0]->{'PercentProcessorTime'};
			$value{$row[0]->{'IDProcess'}}{'D1'} = $row[0]->{'Timestamp_Sys100NS'};
		}

		sleep 1;

		$sth = $arg{'dbh'}->prepare('SELECT * FROM Win32_PerfRawData_PerfProc_Process');
		$sth->execute;

		while (@row = $sth->fetchrow) {
			my ($n, $d);
			next if (! $value{$row[0]->{'IDProcess'}}{'Caption'});

			$value{$row[0]->{'IDProcess'}}{'N2'} = $row[0]->{'PercentProcessorTime'};
			$value{$row[0]->{'IDProcess'}}{'D2'} = $row[0]->{'Timestamp_Sys100NS'};

			$n = $value{$row[0]->{'IDProcess'}}{'N2'} - $value{$row[0]->{'IDProcess'}}{'N1'};
			$d = $value{$row[0]->{'IDProcess'}}{'D2'} - $value{$row[0]->{'IDProcess'}}{'D1'};

			if ($d eq '0') {
				$value{$row[0]->{'IDProcess'}}{'cpuUsage'} = 0;
			} else {
				$value{$row[0]->{'IDProcess'}}{'cpuUsage'} = int(((($n / $d) * 100) / ($arg{'cpuCount'} + .5)));
			}

			if ($value{$row[0]->{'IDProcess'}}{'cpuUsage'} < 0) {
				$value{$row[0]->{'IDProcess'}}{'cpuUsage'} = 0;
			}
		}
	}

	return (Time::HiRes::tv_interval( $stopwatch ), %value);
}

#####################################################################

=pod

=head2 wmiVitalsGrabber

This function will use WMI and query for specific statistics

=over 2

	($timer, %results) = &ipfixify::sysmetrics::wmiVitalsGrabber(
		'connect'   => $services,
		'query'     => 'SELECT * FROM Win32_LogicalDisk',
		'value'     => 'FreeSpace',
		'label'     => 'Name',
		'math'      => 'each',
		'sid'       => [1|0],
		'factor'    => '1'
	);

=back

The currently supported parameters are:

=over 2

=item * connect

The scalar that represents the WMI connection

=item * query

The actual query to run against the WMI engine

=item * value

the column from the query that represents the data you're polling

=item * label

This optional column name represents the text to use for the value. If
not provided, then the value is the label

=item * math

This optional parameter controls how the measure your value. You can
either "sum" the values obtained, "avg" the values, or get "each" of
the values.

=item * sid

if true, the purpose of this WMI query is to get SID information to
generate a machine id.

=item * factor

this optional paratemer is a multiplier of the value. A decimal
notation can be used. (e.g. 1.024 for int to bytes)

=back

The returned %results will contain a hash of the values. The scalar
$timer will contain the number of milliseconds collect this data.

=cut

sub wmiVitalsGrabber {
	my (%arg, %value);
	my (@row);
	my ($oCount, $oTotal, $sth, $stopwatch);

	%arg = @_;

	$stopwatch = [ Time::HiRes::gettimeofday( ) ];

	$sth = $arg{'dbh'}->prepare($arg{'query'});
	$sth->execute;

	while (@row = $sth->fetchrow) {
		if ($arg{'drivespace'}) {
			my ($letter, $space) = split (/\,/, $arg{'drivespace'});
			$row[0]->{$letter} =~ s/\\//;
			$value{$row[0]->{$letter}} = $row[0]->{$space}
			  if ($row[0]->{$letter} =~ m/:/);
		} elsif ($arg{'sid'}) {
			$value{'sid'} .= $row[0]->{$arg{'value'}}.':';
		} else {
			$oCount++;

			if ($arg{'factor'}) {
				$oTotal += $row[0]->{$arg{'value'}};
			}
			$value{$arg{'value'}} = $row[0]->{$arg{'value'}}
			  if (defined $row[0]->{$arg{'value'}});
		}
	}

	if ($arg{'math'} eq 'avg' && $oCount) {
		$value{$arg{'value'}} = int(($oTotal / $oCount)+.5);
		$value{'objectCount'} = $oCount;
	} elsif ($arg{'math'} eq 'sum') {
		$value{$arg{'value'}} = $oTotal;
	}

	return (Time::HiRes::tv_interval( $stopwatch ), %value);
}

#####################################################################

=pod

=head1 BUGS AND CAVEATS

None at this time

=head1 COPYRIGHT AND LICENSE

This file is the property of Plixer International, Inc.

=head1 AUTHOR

Marc Bilodeau L<mailto:marc@plixer.com>

=cut

1;

__END__


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:4 ***
# perl-indent-level:4 ***
# tab-width: 4 ***
# indent-tabs-mode: t ***
# End: ***
#
# vim: ts=4 sw=4 noexpandtab
