#!perl

package ipfixify::help;

use strict;
use Exporter;

our ($VERSION);
our (@ISA, @EXPORT);

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
	&mainHelp
);

=pod

=head1 NAME

ipfixify::help

=head1 SYNOPSIS

=over 2

	&ipfixify::help::mainHelp(
		version => $version
	);

=back

=head1 DESCRIPTION

This module contains functions related to help and documentation.

The following functions are part of this module.

=cut

#####################################################################

=pod

=head2 main

The current main help instructions which is --help

=over 2

	&ipfixify::help::mainHelp(
		version => $version
	);

=back

The currently supported parameters are:

=over 2

=item * version

The current version header.

=back

=cut

sub mainHelp {
	my (%arg);
	my ($svcInstructions);

	%arg = (@_);

	if ($^O eq 'MSWin32') {
		$svcInstructions =
			"--install [auto] --name=\"<svcname>\" [--config=<path/cfg>]\n".
			"  [--file=<path/tofile> || --syslog IP:PORT || -sysmetrics\n".
			"   || -stream IP:PORT || -honeynet IP:PORT ]\n\n".
			"  these options will allow you to add IPFIXify as a service.\n".
			"  All 4 parameters are required.\n\n";
			"--remove --name=\"<svcname>\"\n\n".
			"  removes the service for this instance of IPFIXify.";
	} else {
		$svcInstructions =
			"--autostart=[y|n] --name=\"<svcname>\" --config=<path/cfg> \n".
			"  [--file=<path/file> || --syslog IP:PORT || ".
			"--stream IP:PORT\n".
			"    || --honeynet IP:PORT ]\n\n".
			"  these options will allow you to add or remove IPFIXify as ".
			"a service.\n".
			"   All 4 parameters are required.";
	}

	print qq {
$arg{'version'}
---------------------------------------------------------------------
Converted machine data into IPFIX flows to send to an IPFIX Collector
---------------------------------------------------------------------

For Wiki and source code, visit https://github.com/plixer/ipfixify

*** Command Line Options available ***

$svcInstructions

***********
* OPTIONS *
***********

--config=<path/to/cfg>

  this parameter specifies the location of the configuration file. If
  not specified, then ipfixify looks for ipfixify.cfg in the current
  directory.

--credentials=<path/to/cfg>

  If using System Metrics for multiple hosts, this command allows you
  to embed an encrypted username and password capable of accessing a
  remote system. The permtest option can be used to test permissions
  (see below)

--debug

  outputs a lot of information on the processes of IPFIXify. Very
  useful if making your own plugins to see how data is being converted
  to IPFIX flows.

--import <COLLECTOR_IP_ADDR>:<DB_PORT>

  imports reports and other required information to use the desired
  plugin.  helpful when sharing your plugin with other users.

--permtest

  Ex: ./ipfixify.exe --config ./ipfixify-sysmetrics.cfg --sysmetrics
    --psexec ./Psexec.exe --permtest 10.1.5.1

  Used for sysmetrics mode. It allows you to test the permissions
  needed for sysmetrics to gather data from the specified host
  (i.e. 10.1.5.1)

--test | --t

  tests the configuration file for errors. No flows will be sent with
  this option.

--verbose

  outputs additional information while IPFIXify is running.

*********
* MODES *
*********

--file=<path/to/file_to_track>

  Ex: ./ipfixify.exe --file /var/log/message --config ./filefollow.cfg

    specifies a text file to track for changes. Requires the --config
    parameter.

--honeynet <FLOWCOLLECTOR_IP_ADDR>:<UDP_PORT>

  Ex: ./ipfixify.exe --honeynet 192.168.2.28:2002 --sendto \
    192.168.2.28:514 --file /home/honeynet/connect.log &

    starts honeynet logging mode. Reads the honeynet logs and streams
    alerts and flows to a IPFIX Collector.

--syslog <LOCAL_IP_ADDR>:<UDP_PORT>

  Ex: ./ipfixify.exe --syslog 192.168.2.28:514 --config ./syslog.cfg

    makes IPFIXify a Syslog Listener. Currently only UDP is supported.

--sysmetrics [--psexec <path/to/psexec.exe>]

  Ex: ./ipfixify.exe --config ./ipfixify-sysmetrics.cfg --sysmetrics
    --psexec ./PsExec.exe

  Use sysmetrics mode. Requires the --config option. --psexec is only
  required if the netstatsdetails option in the config file is
  enabled.  currently windows only.

---------------------------------------------------------------------
};

	exit(0);
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
# cperl-indent-level:2 ***
# perl-indent-level:2 ***
# tab-width: 2 ***
# indent-tabs-mode: t ***
# End: ***
#
# vim: ts=2 sw=2 noexpandtab
