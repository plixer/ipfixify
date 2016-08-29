#!perl

package ipfixify::util;

use strict;
use Config::IniFiles;
use Crypt::Blowfish;
use Data::Dumper;
use DBI;
use Digest::MD5 qw(md5_hex);
use Exporter;
use ipfixify::parse;
use Regexp::IPv6 qw($IPv6_re);
use Net::Ping;
use Term::ReadKey;
use Time::HiRes;

our ($VERSION);
our (@ISA, @EXPORT);
our (%deltas);

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
	&determineOriginator
	&findSourceIpAddressInMsg
	&formatShortTime
	&getIpPort
	&pwdmgr
	&scrutCfgCredentials
	&scrutImport
	&serviceMgr
	&testPerms
	&testSysMetrics
);

=pod

=head1 NAME

ipfixify::util

=head1 SYNOPSIS

=over 2

	$originator = &ipfixify::util::determineOriginator(
		data		=> \@data,
		cfg			=> $cfg,
		columns		=> $arg{'columns'},
	);

	$ele = &ipfixify::util::elementCache(
		'raw'		=> $_,
		'flowCache'	=> $arg{'flowCache'},
		'return'	=> 'ele'
	);

	$shortTime =&ipfixify::util::formatShortTime();

	$sourceOfBlame = &ipfixify::util::findSourceIpAddressInMsg(
		msg			=> $arg{'line'}->{'msg'},
		original	=> $arg{'line'}->{'addr'}
	);

	($ip, $port) =&ipfixify::util::getIpPort(
		check => $stream
	);

	($cfg{'user'}, $cfg{'pwd'}) = &ipfixify::util::pwdmgr(
		'credentials'	=> $cfg{'credentials'},
		'direction'		=> 'decode'
	);

	&ipfixify::util::scrutCfgCredentials(
		version => $version,
		config	=> $credentials
	);

	&ipfixify::util::scrutImport(
		version => $version,
		import	=> $dbString
	);

	&ipfixify::util::serviceMgr(
		'autostart'	=> $arg{'autostart'},
		'svcName'	=> $arg{'svcName'},
		'version'	=> $arg{'version'},
		'config'	=> $arg{'config'},
		'filename'	=> $arg{'filename'},
		'syslog'	=> $arg{'syslog'},
		'sysmetrics'=> $arg{'sysmetrics'},
		'psexec'	=> $arg{'psexec'},
		'sourceip'	=> $arg{'sourceip'},
		'honeynet'	=> $arg{'honeynet'}
	);

	&ipfixify::util::testPerms();

	&ipfixify::util::testSysMetrics(
		cfg => \%cfg,
		host => $smPermTest,
		orginator => $originator,
		eventlogs => \@eventLogToGather
	);

=back

=head1 DESCRIPTION

This module contains functions related to utility or CLI functions
within IPFIXify.

The following functions are part of this module.

=cut

#####################################################################

=pod

=head2 determineOriginator

Used to determine the address of the originator of the flows.

=over 2

	$originator = &ipfixify::util::determineOriginator(
		data		=> \@data,
		cfg			=> $cfg,
		columns		=> $arg{'columns'},
	);

=back

The currently supported parameters are:

=over 2

=item * data

An array of the line to parse

=item * cfg

the current cfg state

=item * columns

The list of columns in this template to match the data

=back

=cut

sub determineOriginator {
	my (%arg, %mesh);
	my (@columns, @data);
	my ($originator, $originatorName, $colCount);

	%arg = (@_);

	@data = @{$arg{'data'}};

	foreach(split (/\n/, $arg{'columns'})) {
		next if /^\s+$/;

		my $element = &ipfixify::util::elementCache(
			'raw'		=> $_,
			'flowCache'	=> $arg{'flowCache'}
		);
		push @columns, $element->{name};
	}

	pop(@columns);

	$colCount = @columns;

	if (! &ipfixify::parse::v_ip($arg{'cfg'}->{'originator'}) && $arg{'cfg'}->{'originator'}) {
		$originator = $arg{'cfg'}->{'originator'};
	} else {
		$originator = undef;
	}

	return ($originator, $colCount);
}

#####################################################################

=pod

=head2 elementCache

this function check and adds to the flowCache for elements

=over 2

	my $ele = &ipfixify::util::elementCache(
		'raw'		=> $_,
		'flowCache'	=> $arg{'flowCache'}
	);

=back

The currently supported parameters are:

=over 2

=item * raw

the raw template column string in FDI format.

=item * flowCache

the current flow cache as a reference where the element Cache is
stored

=back

=cut

sub elementCache {
	my (%arg);

	%arg =(@_);

	$arg{'raw'} =~ s/\s*|\n|\r|\0//g;

	if (! scalar keys %{$arg{'flowCache'}->{'cache'}{'elements'}{'raw'}{$arg{'raw'}}}) {
		my ($element, $ele);

		$element = FDI::InformationElement->for_spec($arg{'raw'});
		$ele = join( '.', @{$element}{qw{enterpriseId elementId}} );
		$ele =~ s/IANA.//;

		if (! defined $ele || ! defined $element->{'elementId'} ||
			! defined $element->{'dataType'} || ! defined $element->{'dataTypeSemantics'} ||
			! defined $element->{'enterpriseId'} || ! defined $element->{'length'} ||
			! defined $element->{'name'}
		) {
			die "\n** ERROR PARSING TEMPLATE LINE $arg{'raw'}\n";
		}

		$element->{'enterpriseId'} = $element->{'enterpriseId'} eq 'IANA' ? '0' : $element->{'enterpriseId'};

		$arg{'flowCache'}->{'cache'}{'elements'}{'raw'}{$arg{'raw'}} =
		  {
		   'ele'				=> $ele,
		   'elementId'			=> $element->{'elementId'},
		   'dataType'			=> $element->{'dataType'},
		   'dataTypeSemantics'	=> $element->{'dataTypeSemantics'},
		   'enterpriseId'		=> $element->{'enterpriseId'},
		   'length'			    => $element->{'length'},
		   'name'				=> $element->{'name'}
		  };
	}

	return $arg{flowCache}->{cache}{elements}{raw}{$arg{'raw'}};
}

#####################################################################

=pod

=head2 findSourceIpAddressInMsg

This function scrutinizes a message to determine who to point the
finger of blame and store it in the source field.

=over 2

	my $sourceOfBlame = &ipfixify::util::findSourceIpAddressInMsg(
		msg			=> $arg{'line'}->{'msg'},
		original	=> $arg{'line'}->{'addr'}
	);

=back

The currently supported parameters are:

=over 2

=item * msg

the message string to look high and low for a finger of blame.

=item * original

the original unspoiled address before trying to determine another

=back

=cut

sub findSourceIpAddressInMsg {
	my (%arg);
	my (@columns, @data);
	my ($fingerOfBlame);

	%arg = (@_);

	$fingerOfBlame = $arg{'original'};

	if ($arg{'msg'} =~ /^$IPv6_re$/) {
		#$fingerOfBlame = $1;
		$fingerOfBlame = $arg{'original'};
	} elsif($arg{'msg'} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/){
		my @ip = split (/\./, $1);
		#print __LINE__ .": $1 (@ip)\n";
		$fingerOfBlame = $ip[3] eq '0' ? undef : $1;
	}

	if (! &ipfixify::parse::v_ip($fingerOfBlame)) {
		$fingerOfBlame = $arg{'original'};
	}

	#print "finger of blame: $fingerOfBlame\n\n";

	return $fingerOfBlame;
}

#####################################################################

=pod

=head2 formatShortTime

This function returns a shorthand of localtime for logging/debug
purposes

=over 2

	$shortTime =&ipfixify::util::formatShortTime();

=back

There are currently no required parameters. the returned values is
short handed time stamp.

=cut

sub formatShortTime {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	my @abbr = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

	$hour = "0".$hour if (length($hour) == 1);
	$min = "0".$min if (length($min) == 1);
	$sec = "0".$sec if (length($sec) == 1);

	return "[$abbr[$mon] $mday $hour:$min:$sec]";
}

#####################################################################

=pod

=head2 getIpPort

This function parses out a string and determines what sender IP and
Port a sending or receiving socket should use.

=over 2

	($ip, $port) =&ipfixify::util::getIpPort(
		check => $stream
	);

=back

The currently supported parameters are:

=over 2

=item * check

the string to look for sender address and port

=back

the returned values are an IP and Port.

=cut

sub getIpPort {
	my (%arg);
	my ($ip, $port);

	%arg = (@_);

	($ip, $port) = split (/:/, $arg{'check'});

	return ($ip, $port);
}

#####################################################################

=pod

=head2 pwdmgr

This function encodes and decodes passwords.

=over 2

	($cfg{'user'}, $cfg{'pwd'}) = &ipfixify::util::pwdmgr(
		'credentials'	=> $cfg{'credentials'},
		'direction'		=> 'decode'
	);

=back

The currently supported parameters are:

=over 2

=item * credentials

This is the credentials text from the cfg file.

=item * direction

There are two options here. 'decode' and 'encode'

=back

=cut

sub pwdmgr {
	my (%arg);
	my ($key, $pwd, $user, $offset, $cipher, $credentials);

	%arg = (@_);

	if ($arg{'direction'} eq 'decode') {
		$key = pack("H16", "23123879217398271398712983721");
		$cipher = new Crypt::Blowfish $key;

		for ($offset = 0; $offset < length($arg{'credentials'}); $offset+=16) {
			my $linechunk = substr($arg{'credentials'}, $offset, 16);
			if (length($linechunk)<1) { last; }
			$credentials .= $cipher->decrypt(pack("H16", $linechunk));
			if (length($linechunk)<15) { last; }
		}

		($user, $pwd) = split (/:/, $credentials, 2);
		$pwd =~ s/\n|\r|\0|\t//;

		while ($pwd =~ m/\ $/) {
			chop $pwd;
		}

		chop $pwd if ($pwd =~ m/\:$/);

		return ($user, $pwd);
	} else {
		$key = pack("H16", "23123879217398271398712983721");  # min. 8 bytes
		$cipher = new Crypt::Blowfish $key;

		for($offset = 0; $offset < length($arg{'credentials'}); $offset+=8) {
			my $linechunk = substr($arg{'credentials'}, $offset, 8);
			$credentials .= unpack("H16", $cipher->encrypt(pack("A8", $linechunk)));
			if (length($linechunk)<7) { last; }
		}

		return $credentials
	}
}

#####################################################################

=pod

=head2 scrutCfgCredentials

This function manages credentials in a cfg file.

=over 2

	&ipfixify::util::scrutCfgCredentials(
		version => $version,
		config	=> $credentials
	);

=back

The currently supported parameters are:

=over 2

=item * version

Just a pretty way to tell users they have the wonderfully glorous IPFIXify

=item * config

the path to the config file.

=back

=cut

sub scrutCfgCredentials {
	my (%arg);
	my ($credentials, $ini, $pwd, $password, $username);

	%arg = (@_);

	print $arg{'version'};

	if (! -e $arg{'config'}) {
		print "\n* ERROR: $arg{'original'} not found!\n";
		exit(0);
	}

	require Term::ReadKey;
	Term::ReadKey->import ('ReadMode');

	while (! $pwd) {
		my ($verify);

		$username = $password = $verify = '';

		print "\nHit <Enter> to abort\n\nlocal or domain ".
		  "administrator user name\n(e.g. Domain\\Username ".
			"or Username): ";
		chomp ($username = <STDIN>);

		$username =~ s/\n|\r|\0//;

		if (! $username) { exit(0); }

		print "\nPassword: ";

		ReadMode(2);
		chomp ($password = <STDIN>);
		ReadMode(0);

		$password =~ s/\n|\r|\0|\t//;

		print "\nVerify Password: ";

		ReadMode(2);
		chomp ($verify = <STDIN>);
		ReadMode(0);

		$verify =~ s/\n|\r|\0|\t//;

		if (! $password) {
			print "\n\n* ERROR: Password is blank\n";
		} elsif ($password eq $verify) {
			$pwd = 1;
		} else {
			print "\n\n* ERROR: Password mismatch\n";
		}
	}

	$credentials = &ipfixify::util::pwdmgr
	  (
	   'credentials'	=> "$username:$password",
	   'direction'		=> 'encode'
	  );

	$ini = new Config::IniFiles
	  (
	   -file => $arg{'config'},
	   -nomultiline => 1
	  );

	if ($ini->setval('options', 'credentials', $credentials)) {
		$ini->WriteConfig($arg{'config'});
		print "\n\nDone!\n";
	} else {
		print "\n\n* ERROR: Couldn't set new credential. ".
		  "Check permissions!\n";
	}

	exit(0);
}

#####################################################################

=pod

=head2 scrutImport

This allows users to import SQL based information into the database of
Scrutinizer.

=over 2

	&ipfixify::util::scrutImport(
		version => $version,
		import	=> $dbString
	);

=back

The currently supported parameters are:

=over 2

=item * version

The current version information for IPFIXify

=item * import

The IP address:port of the Scrutinizer server.

=back

=cut

sub scrutImport {
	my (%arg);
	my (
		$confirm, $db, $dbh, $error, $dberr, $port, $pwd,
		$storedProcedure, $sth
	   );

	%arg = (@_);

	($db, $port) = split (/:/, $arg{'import'});

	if (! $db) {
		$error .= "The database IP is missing (ip:port)\n";
	} elsif (! &ipfixify::parse::v_ip($db)) {
		$error .= "The collector defined as '$db' is invalid\n";
	}

	if (! $port) {
		$error .= "The database port is missing (ip:port)\n";
	} elsif ($port =~ m/\D/ || $port > 65535) {
		$error .= "The database port defined as '$port' is invalid\n";
	}

	if (! -e './ipfixify.sql') {
		$error .= "Can't find ipfixify.sql definitions\n";
	}

	if ($error) {
		print "$arg{'version'}\n** ERROR **\n\n$error\n";
		exit(0);
	}

	print "$arg{'version'}\n** NOTE **\n\n".
		"Users can use the import function to add any necessary ".
		"definitions\nto Scrutinizer to report on the data sent ".
		"with a particular IPFIXIfy add-on.\n\nSince you are adding ".
		"to or modifying information in Scrutinizer, it is\n".
		"recommended that you do a complete backup before ".
		"continuing.\n\n";

	print "Do you have a backup and are ready to continue? (y/N) ";

	$confirm = <>;

	if ($confirm !~ m/^y/i) {
		print "\nExiting...\n";
		exit(0);
	}

	print "\n+ Attempting to connect to Scrutinizer at $arg{import}\n";

	require Term::ReadKey;
	Term::ReadKey->import ('ReadMode');

	while (! $pwd) {
		my ($mysqlPass, $dberr);

		$mysqlPass = '';

		print "\nWhat is your scrutinizer admin password: ";
		ReadMode(2);
		chomp ($mysqlPass = <STDIN>);
		ReadMode(0);

		$mysqlPass =~ s/\n|\r|\0//;

		$dbh = DBI->connect
		  (
		   "DBI:mysql:database=;host=$db;port=$port",
		   "scrutremote",
		   "$mysqlPass",
		   {
			PrintError => 0,
			RaiseError => 0
		   }
		);

		if (DBI->err) {
			print "\n\nERROR: The password entered does not appear ".
			  "to be correct. Please consult\nthe Scrutinizer ".
				"documentation or contact technical support for ".
				  "assistance.\n";
		} else {
			my (
				$currentVersion, $installedVersion, $file,
				$statements, $sth, $spin
			   );
			my (@results, @sql, @statements, @ver);

			@results = $dbh->selectrow_array("SELECT count(*), currentVal FROM plixer.serverprefs WHERE langKey = 'installedVersion'");
			($currentVersion, $installedVersion) = @results[ 0, 1 ];

			if ( defined $installedVersion ) {
				@ver = split( /\./, $installedVersion );
			}

			$spin = (
				(
					( @ver == 4 ) || # major.minor.patch.spin
					( @ver == 2 )    # alphabeta.spin
				)
				? $ver[-1]
				: 0
			);

			if ($spin < 22654) {
				print "\n\n\n** ERROR: This version of Scrutinizer ".
				  "($installedVersion) is not compatible with\n".
					"IPFIXify. Please upgrade Scrutinizer ".
					"to the latest version.\n";
				exit(0);
			}

			print "\n\n+ Importing definitions ...\n";

			open ($file, '<', './ipfixify.sql');
			@sql = <$file>; chomp(@sql);
			close($file);
			$statements = "@sql";

			@statements = split (/;/, $statements);

			if ($statements[0] =~ m/LANGCHECK/) {
				my (@results);
				my ($langkey, $test);

				(undef, $langkey) = split (/\|/, $statements[0]);
				$langkey =~ s/\;//ig;

				@results = $dbh->selectrow_array("SELECT id FROM languages.custom where id = '$langkey'");
				$test = $results[0];

				if ($test) {
					print "\n** Definitions Exist, nothing to do\n";
					unlink './ipfixify.sql' if (-e './ipfixify.sql');
					exit(0);
				} else {
					foreach (@statements) {
						eval {
							my $sth = $dbh->prepare($_);
							$sth->execute();
						};

						if ($@ || DBI->err) {
							print "\n** Error Executing **\n".
							  "Executing [$_]\n";
							$dberr++;
						}
					}
					$pwd = 1 unless ($dberr);
				}
			} else {
				print "\n** Error: No Langcheck directive found ".
				  "on first line\n";
				$dberr++;
			}
		}
	}

	unlink './ipfixify.sql' if (-e './ipfixify.sql');

	print "\nDone! Please restart your Scrutinizer Collector ".
	  "before you send\n      IPFIX traffic from this plugin.\n";

	exit(0);

	return;
}

#####################################################################

=pod

=head2 serviceMgr

This allows users to install IPFIXify as a service or Daemon.

=over 2

	&ipfixify::util::serviceMgr(
		'autostart'	=> $arg{'autostart'},
		'svcName'	=> $arg{'svcName'},
		'version'	=> $arg{'version'},
		'config'	=> $arg{'config'},
		'filename'	=> $arg{'filename'},
		'syslog'	=> $arg{'syslog'},
		'sysmetrics'=> $arg{'sysmetrics'},
		'psexec'	=> $arg{'psexec'},
		'sourceip'	=> $arg{'sourceip'},
		'honeynet'	=> $arg{'honeynet'}
	);

=back

The currently supported parameters are:

=over 2

=item * autostart

This tells us if we're adding or removing the service

=item * svcName

The name of the service

=item * version

The current version information.

=item * config

The current path and file name of the configuration file

=item * filename

The filename to follow

=item * syslog

Syslog listener settings

=item * sysmetrics

Server Metrics Mode

=item * psexec

Path to the PSEXEC.exe utility for system metrics mode.

=item * sourceip

Primarily used to change the interface IP that IPFIXify will report
as. The IP must exist on the system itself.

=item * honeynet

Honeynet mode

=back

=cut

sub serviceMgr {
	my (%arg);

	%arg = (@_);

	print "$arg{'version'}\n".
		"autostart    = $arg{'autostart'}\n".
		"Service Name = $arg{'svcName'}\n".
		"config       = $arg{'config'}\n".
		"filename     = $arg{'filename'}\n".
		"syslog       = $arg{'syslog'}\n".
		"sourceIp     = $arg{'sourceip'}\n".
		"psexec       = $arg{'psexec'}\n".
		"honeynet	  = $arg{'honeynet'}\n".
		"sysmetrics	  = $arg{'sysmetrics'}\n\n";

	if ($arg{'svcName'} =~ m/\ /) {
		$arg{'svcName'} =~ s/\ /\_/ig;
		print "+ Service Name has been converted to ".
		  "'$arg{'svcName'}'\n\n";
	}

	if ($^O =~ m/Win32/) {
		## WE RELY ON PERLSVC TO MANAGE SERVICES ##
	} else {
		my ($output);

		if ($arg{'autostart'} =~ /^y/i) {
			if (! -e "/etc/init.d/$arg{'svcName'}" ) {
				my ($mode, $pidDef, $pwd, $svc);

				$pwd = `pwd`;
				chop($pwd);

				if (! -e "$pwd/ipfixify.exe") {
					print "Error: can't locate ipfixify.exe in $pwd\n";
					exit(0);
				}

				if (! -e "$pwd/$arg{'config'}") {
					print "Error: can't locate $arg{config} in $pwd\n";
					exit(0);
				}

				if ($arg{'syslog'}) {
					$pidDef = "pid.syslog_$arg{'syslog'}";
				} elsif ($arg{'stream'}) {
					$pidDef = "pid.stream_$arg{'stream'}";
				} elsif ($arg{'filename'} && ! $arg{'honeynet'}) {
					$pidDef = "pid.$arg{'filename'}";
				} elsif ($arg{'honeynet'}) {
					$pidDef = "pid.honeynet_$arg{'honeynet'}";
				}

				$pidDef =~ s/\\|\/|\.|\:|\*/\_/g;

				if ($arg{'filename'} =~ m/\*/) {
					$arg{'filename'} =~ s/\*/\\\*/ig;
				}

				if ($arg{'syslog'}) {
					$mode = "--syslog $arg{'syslog'}";
				} elsif ($arg{'stream'}) {
					$mode = "--stream $arg{'stream'}";
				} elsif ($arg{'filename'} && ! $arg{'honeynet'}) {
					$mode = "--file \"$arg{'filename'}\"";
				} elsif ($arg{'honeynet'}) {
					$mode = "--honeynet $arg{'honeynet'} --file \"$arg{'filename'}";
				} elsif ($arg{'sysmetrics'}) {
					$mode = "--sysmetrics";
				}

				if ($arg{'sourceip'}) {
					$mode .= " --sourceip $arg{'sourceip'}";
				}

				open( $svc, '>', "/etc/init.d/$arg{'svcName'}" );
				print $svc "#! /bin/sh\n";
				print $svc "### BEGIN INIT INFO\n";
				print $svc "# Provides: $arg{'svcName'}\n";
				print $svc "# Default-Start: 2 3 4 5\n";
				print $svc "# Default-Stop: 0 1 6\n";
				print $svc "# Description: IPFIXify (TM) $arg{'config'} / $arg{'filename'}\n";
				print $svc "### END INIT INFO\n\n";
				print $svc "case \"\$1\" in\n";
				print $svc "    start)\n";
				print $svc "        echo -n \"Starting $arg{'svcName'}\"\n";
				print $svc "		cd $pwd\n";
				print $svc "        ./ipfixify.exe --config $arg{'config'} $mode >&- 2>&- &\n";
				print $svc "        echo \".\"\n";
				print $svc "        ;;\n";
				print $svc "    stop)\n";
				print $svc "        echo -n \"Stopping $arg{'svcName'}\"\n";
				print $svc "        /bin/kill -9 `/bin/cat $pwd/$pidDef`\n";
				print $svc "        echo \".\"\n";
				print $svc "        ;;\n";
				print $svc "    *)\n";
				print $svc "        echo \"Usage: /sbin/service $arg{'svcName'} {start|stop}\"\n";
				print $svc "        exit 1\n";
				print $svc "esac\n\n";
				print $svc "exit 0\n";
				close($svc);

				$output = `/bin/chown root:root /etc/init.d/$arg{'svcName'}`;
				$output = `/bin/chmod 0555 /etc/init.d/$arg{'svcName'}`;
				$output = `/sbin/chkconfig --add $arg{'svcName'}`;
				$output = `/sbin/chkconfig --level 2345 $arg{'svcName'} on`;

				print "Service Installed, but not started. To start, run:\n\n".
					"   service $arg{'svcName'} start\n\n";
			} else {
				print "* Service $arg{'svcName'} exists! If you want to remove this service run:\n\n".
					"ipfixify.exe --autostart=$arg{'autostart'} --name=$arg{'svcName'} --config=$arg{'config'} --file=$arg{'filename'}\n\n";
			}
		} else {
			if (! -e "/etc/init.d/$arg{'svcName'}" ) {
				print "* The service $arg{'svcName'} is not installed.\n\n";
			} else {
				$output = `/sbin/chkconfig --add $arg{'svcName'}`;
				$output = `/sbin/chkconfig --level 2345 $arg{'svcName'} on`;
				$output = `unlink /etc/init.d/$arg{'svcName'}`;

				print "* The service $arg{'svcName'} has been removed\n\n";
			}
		}
	}

	print "Done!\n";

	return;
}

#####################################################################

=pod

=head2 testPerms

This function verifies the prompt has administrative privileges to
perform system actions

=over 2

	&ipfixify::util::testPerms();

=back

There are currently no parameters supported.

=cut

sub testPerms {
	my (%arg);

	%arg = (@_);

	eval {
		open(my $file,'>>',"$ENV{'WINDIR'}/ipfixify.pid") || die 'err';
		close($file) if $file;
	};

	if ($@) {
		print "\n*ERROR* This action requires elevate permissions.".
		  " Please " . "execute using\n        a command prompt ".
			"running as " . "Administrator\n\n";
		exit(0);
	} else {
		unlink "$ENV{'WINDIR'}/ipfixify.pid"
		  if -e "$ENV{'WINDIR'}/ipfixify.pid";
	}

	return;
}

#####################################################################

=pod

=head2 testSysMetrics

This function tests to make sure all sysmetrics requirements are met

=over 2

	&ipfixify::util::testSysMetrics(
		cfg => \%cfg,
		host => $smPermTest,
		orginator => $originator,
		eventlogs => \@eventLogToGather,
		verbose => $verbose
	);

=back

There are currently no parameters supported.

=cut

sub testSysMetrics {
	my (%arg, %cfg);
	my (@row);
	my (
		$dbh, $errors, $sth, $pass, $pwd, $services, $eventRec,
		$warnings, $wmi, $ping, $p, $port
	);

	%arg = (@_);

	%cfg = %{$arg{'cfg'}};

  ### CONFIGURATION DUMP ###
	print "-"x75 ."\nCURRENT CONFIGURATION\n". "-"x75 ."\n";
	$pwd = $cfg{'pwd'};
	$cfg{'pwd'} = 'xxxxxxxxxxxxxxxxx';
	print Dumper \%cfg;
	$cfg{'pwd'} = $pwd;

  ### CONNECTIVITY TEST ###
	print "\n". "-"x75 ."\nCONNECTIVITY TEST\n". "-"x75 ."\n";

	$port = $^O eq 'MSWin32' ? '135' : '22';

	$p = Net::Ping->new();
	$p->bind($arg{'originator'});
	$p->port_number($port,'tcp');
	$pass = $p->ping($arg{'host'}, $cfg{'pingtimeout'});
	$p->close();

	if (! $pass) {
		if ($^O eq 'MSWin32') {
			print "\nThis user cannot access $arg{'host'}.\n".
			  "reference https://technet.microsoft.com/en-us/library/cc771551.aspx\n".
				"account needs \"Enable Account\" and ".
				  "\"Remote Enable\" WMI permissions.\n".
				  "Additional permissions required .. FAILED\n";
		} elsif ($^O eq 'linux') {
			print "\nThis user cannot access $arg{'host'} via SSH.\n".
			  "verify that the current credentials used are ".
				"correct for connectivity\n".
				  "Connectivity Test .. FAILED\n";
		}
		$errors++;
		return;
	} else {
		print "\nReaching out to $arg{'host'} .. PASSED\n";
	}

  ### STATISTIC POLL TEST ###
	print "\n". "-"x75 ."\nSTATISTIC POLL TEST\n". "-"x75 ."\n";

	if ($^O eq 'MSWin32') {
		($pass, $dbh) = &ipfixify::sysmetrics::pingTest
		  (
		   computer		=> $arg{'host'},
		   debug_system	=> '+ T0'.sprintf ('%-4s', ''). sprintf ('%-15s', $arg{'host'}),
		   verbose		=> 'permtest',
		   pingtimeout	=> $cfg{'pingtimeout'},
		   originator	=> $arg{'originator'},
		   cfg			=> \%cfg
		  );

		if (! $pass) {
			print "\nThis user cannot access $arg{'host'}.\n".
			  "reference https://technet.microsoft.com/en-us/library/cc771551.aspx\n".
				"account needs \"Enable Account\" and ".
				  "\"Remote Enable\" WMI permissions.\n".
					"Additional permissions required .. FAILED\n";

			$errors++;
		}

		eval {
			$sth = $dbh->prepare('SELECT * FROM Win32_Processor');
			$sth->execute;

			while (@row = $sth->fetchrow) {
				$wmi++;
			}
		};

		if (! $wmi || $@) {
			print "\nThis user cannot get statistics from the ".
			  "host via WMI.\nReference ".
			  "https://technet.microsoft.com/en-us/library/cc771551.aspx\n".
				"account needs \"Enable Account\" and ".
				  "\"Remote Enable\" WMI permissions.\n\n".
					"Additional permissions required .. FAILED\n";

			$errors++;
		} else {
			print "\nPASSED\n";
		}
	} elsif ($^O eq 'linux') {
		my ($cmd, $local, $output, $ssh, $test);

		eval {
			if ($arg{'host'} eq $arg{'originator'}) {
				$local = 1;
			} else {
				$local = 0;
				require Net::SSH::Expect;
				Net::SSH::Expect->import();

				$ssh = Net::SSH::Expect->new
				  (
				   host 	=> $arg{'host'},
				   password	=> $cfg{'pwd'},
				   user 	=> $cfg{'user'},
				   raw_pty 	=> 1,
				   timeout 	=> $arg{'pingtimeout'},
				  );

				$output = $ssh->login();
			}
		};

		if ($@) {
			print qq {SSH connect to $arg{'host'} .. FAILED\n};
			$errors++;
		}

		$cmd = "/bin/grep 'cpu ' /proc/stat | /bin/awk '{usage=(\$2+4)*100/(\$2+\$4+\$5)} END {print usage}'";

		if ($local) {
			$test = `$cmd`;
		} else {
			$test = $ssh->exec($cmd);
		}

		if (! $test) {
			print "\nFAILED\n";
			$errors++;
		} else {
			print "\nPASSED\n";
		}
	}

	# WINDOWS PLATFORM ONLY - EVENTLOG READ TEST
	if ($^O eq 'MSWin32') {
		print "\n". "-"x75 ."\nEVENTLOG READ TEST\n". "-"x75 ."\n\n";

		foreach (@{$arg{'eventlogs'}}) {
			my (%recType);
			my (@records);
			my (
				$cacheid, $el, $events, $LastRec, $err, $secEvent,
				$currentRecs
			);

			($cacheid, $el) = split (/:/, $_);

			($err, $events) = &ipfixify::sysmetrics::eventLogConnect
			  (
			   cfg => \%cfg,
			   machine => $arg{'host'},
			   verbose => $arg{'verbose'}
			  );

			if ($err) {
				print "($arg{'host'}) $el : \@ $@\n";
				$errors++;
			}

			$LastRec = $events->get_last_record_id($el) - 100;

			if ($LastRec > 0) {
				print "($arg{'host'}) $el : ".
				  "(last record num $LastRec)\n";

				(undef, @records) = &ipfixify::sysmetrics::eventLogGrab
				  (
				   eventlog => $el,
				   elh => $events,
				   startrec => $LastRec,
				   verbose => $arg{'verbose'}
				  );

				foreach my $x (@records) {
					my %record = %$x;

					print Dumper \%record if ($arg{'verbose'} > 1);

					$eventRec++;
					$currentRecs++;

					if ($record{'event_id'} eq '4624') {
						$recType{'win2008_2012'}{'event_4624'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '4634') {
						$recType{'win2008_2012'}{'event_4634'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '4647') {
						$recType{'win2008_2012'}{'event_4647'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '6372') {
						$recType{'win2008_2012'}{'event_6272'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '6373') {
						$recType{'win2008_2012'}{'event_6273'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '6378') {
						$recType{'win2008_2012'}{'event_6278'}++;
						$secEvent++;
					} elsif ($record{'event_id'} eq '6379') {
						$recType{'win2008_2012'}{'event_6279'}++;
						$secEvent++;
					}
				}

				if ($el eq 'SECURITY') {
					if ($secEvent) {
						print "$el : " . Dumper \%recType;
					} else {
						print "$el : No authentication events, ".
						  "username info will not be\n".
						  "   available until these events are ".
						  "generated. Reference\n".
						  "   \"Step 2: Creating and verifying an ".
						  "advanced audit policy\" in\n".
						  "   https://technet.microsoft.com/en-us/library/dd408940(v=ws.10).aspx\n".
						  "   to enable Logon/Logoff auditing.\n\n".
						  "   Additional permissions required .. ".
						  "FAILED\n\n";

						$warnings++;
					}
				}

				if (! $currentRecs) {
					print "$el : 0 record(s) scanned\n".
					  "   This user needs to be added to the ".
						"\"Builtin\\Event Log Readers\" group\n".
						  "   for the domain controller(s).\n\n".
							"   Additional permissions required ".
							  ".. FAILED\n\n";

					$errors++;
				} else {
					print "$el : $currentRecs record(s) scanned .. ".
					  "PASSED\n\n";
				}
			}
		}

		if (! $eventRec) {
			print "No EventLogs Read!\n".
			  "This user needs to be added to the ".
				"\"Builtin\\Event Log Readers\" group\n".
				  "for the domain controller(s).\n\n".
					"Additional permissions required .. FAILED\n";

			$errors++;
		}
	}

  ### FILE SYSTEM WRITE TEST ###
	print "\n". "-"x75 ."\nFILE WRITE TEST\n". "-"x75 ."\n";

	eval {
		open (TEST, ">ipfixify.test");
		print TEST "This file was created to test write ".
		  "permissions. it can be safely removed.\n";

		close(TEST);
	};

	if (! -e "ipfixify.test" || $@) {
		print "\n$@\n" if ($@);
		print "\nFile write test failed, Cannot write to ".
		  "current directory!\n".
			"additional permissions required .. FAILED\n";

		$errors++;
	} else {
		print "\nPASSED\n";
		unlink "ipfixify.test";
	}

  ### RESULTS ###
	print "\n". "-"x75 ."\nTEST RESULTS\n". "-"x75 ."\n";

	$warnings = $warnings ? $warnings : '0';
	$errors = $errors ? $errors : '0';

	print "\nWarnings: $warnings\n";
	print "Errors  : $errors\n\n";

	if (! $warnings && ! $errors) {
		print "Results : $arg{'host'} ... PASSED!\n";
	} elsif ($warnings && ! $errors) {
		print "Results : $arg{'host'} ... PASSED, with warnings!\n";
	} else {
		print "Results : $arg{'host'} ... FAILED!\n";
	}

	print "\n". "-"x75 ."\nCOMPLETE\n\n";

	return;
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
