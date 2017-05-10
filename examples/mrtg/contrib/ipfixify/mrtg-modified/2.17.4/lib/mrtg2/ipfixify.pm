#!perl

package ipfixify;

use strict;

our ($VERSION);
our (@ISA, @EXPORT);

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
    &logDetails
);

=pod

=head1 NAME

ipfixify

=head1 SYNOPSIS

=over 2

    &ipfixify::logDetails(
        'rcfg'		=> \%rcfg,
        'cfgfile'	=> $cfgfile,
        'router'	=> $router,
        'inVal'		=> $cuin->{d}{$router},
        'outVal'	=> $cuout->{d}{$router},
        'mrtgTime'	=> $time,
		'streamIp'	=> $ip,
		'streamPort'=> $port		
    );

=back

=head1 DESCRIPTION

IPFIXify for MRTG will take the results of your SNMP poll, format the
data into IPFIX and send it to an IPFIX Collector such as Scrutinizer. For
more information, visit www.IPFIXify.com

The following parameters are passed from MRTG

=over 2

=item * rcfg

A compete awarness of the current mrtg.cfg

=item * cfgfile

the name of the mrtg configuration file (e.g. mrtg.cfg)

=item * router

the current device being polled (i.e. what's in the [ ] in your cfgfile)

=item * inVal

the result of the IN MIB/script output

=item * outVal

the result of the IN MIB/script output

=item * mrtgTime

the timestamp mrtg is using when these values were obtained

=item * streamIp

What IP Address are we sending all the polled SNMP results

=item * streamPort

What UDP Port are we sending all the polled SNMP Results

=back

The results of this are a nicely formatted log file that IPFIXify will use
to prepare the data for IPFIX export.

=cut

sub logDetails {
	my (%arg);
    my ($cfg, $cString, $inMib, $outMib, $hostTarget);
    my ($cPort, $cTimeout, $cRetries, $cBackoff, $cVersion, $groups);
    my ($cInf, $mibInf, $pollInf, $fh, $ipfixLogger);

	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	$year += 1900;
	$mon++;
	$mday = '0'.$mday if (length($mday) == 1);
    
	%arg = (@_);
    $cfg = $arg{'rcfg'};
    
    $inMib = '';
	$groups = $cfg->{groups}->{$arg{router}} ? $cfg->{groups}->{$arg{router}} : '-';
    
    ($mibInf, $pollInf, $cInf) = split (/:/, $cfg->{targorig}->{$arg{router}}, 3);
    ($inMib, $outMib) = split (/\&/, $mibInf);
    if (! $outMib) { $outMib = $inMib };
    
    $inMib = '1.3.6.1.2.1.2.2.1.10.'.$inMib
        if ($inMib =~ /^\d+$/);
    
    $outMib = '1.3.6.1.2.1.2.2.1.16.'.$outMib
        if ($outMib =~ /^\d+$/ && defined $outMib);
    
    
    ($cString, $hostTarget) =
        split (/\@/, $pollInf);
    ($cPort, $cTimeout, $cRetries, $cBackoff, $cVersion, undef) =
        split (/\:/, $cInf);

    $cPort = '161' if (! $cPort);
    $cTimeout = '2' if (! $cTimeout);
    $cRetries = '5' if (! $cRetries);
    $cBackoff = '1' if (! $cBackoff);
    $cVersion = '1' if (! $cVersion);

    $ipfixLogger = join (':-:',
        $arg{'cfgfile'},
        $hostTarget,
        $arg{'router'},
        $cfg->{title}->{$arg{router}},
        $inMib,
        $arg{'inVal'},
        $outMib,
        $arg{'outVal'},
        $cString,
        $cPort,
        $cTimeout,
        $cRetries,
        $cBackoff,
        $cVersion,
        $arg{'mrtgTime'},
		$groups
    );

	eval {
		require Net::Syslog;
		Net::Syslog->import();
	};
	
	if ($@) {
		print "$@\n";
		warn "\n\nIPFIXify option used, but Net::Syslog is missing\n".
			"See contrib/ipfixify/README-IPFIXIFY for details.\n\n\n";
	} else {
		use Net::Syslog;
		
		my $syslog = new Net::Syslog(
			Name       => 'IPFIXIFY',
			Pid        => 10,
			Facility   => 'local0',
			Priority   => 1,
			SyslogPort => $arg{'streamPort'},
			SyslogHost => $arg{'streamIp'},
		);
		$syslog->send($ipfixLogger);
	}
	
    return 0;
}

=pod

=head1 BUGS AND CAVEATS

None at this time

=head1 COPYRIGHT AND LICENSE

This file was provided by Plixer. It can be modified and
distributed under the same terms and conditions as MRTG

=head1 AUTHOR

Marc Bilodeau L<mailto:marc@plixer.com>

=cut

__END__


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:2 ***
# perl-indent-level:2 ***
# indent-tabs-mode: nil ***
# End: ***
#
# vim: ts=2 sw=2 expandtab
