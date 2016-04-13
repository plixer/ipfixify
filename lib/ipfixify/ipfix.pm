#!perl

package ipfixify::ipfix;

use strict;
use Exporter;
use Data::Dumper;
use FDI;
use FDI::InformationModel;
use FDI::Template;
use FDD::IPFIX;

our ($VERSION);
our (@ISA, @EXPORT);

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
    &getFDIHandle
    &rfc3164optionTemplate
    &rfc5610optionTemplate
    &sendFlows
    &sendOptionTemplate
    &setupFdh
    &sysmetricsOptionTemplates
);

=pod

=head1 NAME

ipfixify::ipfix

=head1 SYNOPSIS

=over 2

    &ipfixify::ipfix::rfc3164optionTemplate(
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

    &ipfixify::ipfix::rfc5610optionTemplate(
        'columns'		=> $flowCache{$_}{'columns'},
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

    &ipfixify::ipfix::sendFlows(
        'cfg'			=> \%cfg,
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'spool'			=> 'SPOOL_FILE_NAME',
        'originator'	=> $originator,
        'flowCache'		=> \%flowCache,
        'syspoll'		=> $syspoll
    );

    &ipfixify::ipfix::sendOptionTemplate(
        'flowCache'		=> \%flowCache,
        'enums'			=> \%enums,
        'cacheid'		=> $cacheid,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

    $connection = &ipfixify::ipfix::setupFdh(
        ip		=> $sendAddr,
        port	=> $sendPort,
    );

    &ipfixify::ipfix::sysmetricsOptionTemplates(
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

=back

=head1 DESCRIPTION

This module has functions related to the IPFIX protocol.

The following functions are part of this module.

=cut

#####################################################################

sub getFDIHandle {
    my $fdi_args = shift;
    $fdi_args //= {};

    die "FDI args must be a HASH ref"
      unless ( ref $fdi_args eq 'HASH' );

    my $fdh = FDI->connect_cached( "FDI:IPFIX:", $fdi_args );

    if ( !$fdh ) {
        Carp::croak("FDI create failed");
        return;
    }

    return $fdh;
}

#####################################################################

=pod

=head2 rfc3164optionTemplate

This function forms the IPFIX option template for rfc 3164
information.

=over 2

    &ipfixify::ipfix::rfc3164optionTemplate(
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

=back

The currently supported parameters are:

=over 2

=item * flowCache

the current state of the flowCache

=item * verbose

puts this function in verbose mode

=item * cfg

the current global configuration settings

=back

=cut

sub rfc3164optionTemplate {
    my (%arg, %enums);

    %arg = (@_);

  ### SEND FACILITY OPTION TEMPLATE ###

    %enums =
      (
       '0' => 'kern',
       '1' => 'user',
       '2' => 'mail',
       '3' => 'daemon',
       '4' => 'auth',
       '5' => 'syslog',
       '6' => 'lpr',
       '7' => 'news',
       '8' => 'uucp',
       '9' => 'cron',
       '10' => 'authpriv',
       '11' => 'ftp',
       '12' => 'ntp',
       '13' => 'logaudit',
       '14' => 'logalert',
       '15' => 'clock',
       '16' => 'local0',
       '17' => 'local1',
       '18' => 'local2',
       '19' => 'local3',
       '20' => 'local4',
       '21' => 'local5',
       '22' => 'local6',
       '23' => 'local7'
      );

    &ipfixify::ipfix::sendOptionTemplate
      (
       'flowCache'	=> $arg{'flowCache'},
       'enums'		=> \%enums,
       'cacheid'	=> 108,
       'verbose'	=> $arg{'verbose'},
       'cfg'		=> $arg{'cfg'}
      );

    ### SEND SEVERITY OPTION TEMPLATE ###

    %enums =
      (
       '0' => 'Emergency: system is unusable',
       '1' => 'Alert: action must be taken immediately',
       '2' => 'Critical: critical conditions',
       '3' => 'Error: error conditions',
       '4' => 'Warning: warning conditions',
       '5' => 'Notice: normal but significant condition',
       '6' => 'Informational: informational messages',
       '7' => 'Debug: debug-level messages'
      );

    &ipfixify::ipfix::sendOptionTemplate
      (
       'flowCache'	=> $arg{'flowCache'},
       'enums'		=> \%enums,
       'cacheid'	=> 109,
       'verbose'	=> $arg{'verbose'},
       'cfg'		=> $arg{'cfg'}
      );

    return 0;
}

#####################################################################

=pod

=head2 rfc5610optionTemplate

This function forms the IPFIX option template based on the
configuration column settings for rfc5610 support.

=over 2

    &ipfixify::ipfix::rfc5610optionTemplate(
        'columns'		=> $flowCache{$_}{'columns'},
        'flowCache'		=> \%flowCache,
        'cacheid'		=> $_,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

=back

The currently supported parameters are:

=over 2

=item * columns

The list of columns from the configuration file.
(could be extracted from flowCache)

=item * flowCache

the current flowCache

=item * cacheid

the cache Identifier for label purposes

=item * verbose

puts this function in verbose mode

=item * cfg

the current global cfg settings

=back

=cut

sub rfc5610optionTemplate {
    my (%arg, %dataType, %semantics, %template);
    my (@rfc5610);
    my ($pktCount);

    %arg = (@_);

    print "+ Assembling options template\n\n"
      if ($arg{'verbose'} > 1);

    %template = &ipfixify::definitions::tempSelect
      (
       flowCache => '107'
      );

    %dataType = &ipfixify::definitions::defDataType();
    %semantics = &ipfixify::definitions::defSemantics();

    foreach(split (/\n/, $arg{'columns'})) {
        next if /^\s*$/;

        my $element = &ipfixify::util::elementCache
          (
           'raw'		=> $_,
           'flowCache'	=> $arg{'flowCache'}
          );

        push
          (
           @rfc5610,
           $element->{'enterpriseId'},
           $element->{'elementId'},
           $dataType{lc($element->{'dataType'})},
           '',
           $element->{'name'},
           '0',
           '0',
           $semantics{lc($element->{'dataTypeSemantics'})},
           '0'
          );

        if ($arg{'verbose'} > 1) {
            print "  - option template data flow\n\n".
                "    0_303 : $element->{'elementId'}\n".
                "    0_339 : $element->{'dataType'} (".
                  $dataType{lc($element->{'dataType'})}.
                    ")\n".
                "    0_340 : ''\n".
                "    0_341 : $element->{'name'}\n".
                "    0_342 : 0\n".
                "    0_343 : 0\n".
                "    0_344 : $element->{'dataTypeSemantics'} (".
                  $semantics{lc($element->{'dataTypeSemantics'})}.
                    ")\n".
                "    0_345 : 0\n".
                "    0_346 : $element->{'enterpriseId'}\n\n";
        }
    }

    foreach my $collector (@{$arg{'cfg'}->{'collector'}}) {
        if (! $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}) {
            my ($sendAddr, $sendPort, $spoof);

            ($sendAddr, $sendPort) = &ipfixify::util::getIpPort
              (
               check => $collector
              );

            $arg{'flowCache'}->{'fdh'}{"$collector-SELF"} =
              &ipfixify::ipfix::setupFdh
                (
                 ip		=> $sendAddr,
                 port	=> $sendPort,
                );
        } else {
            $arg{'flowCache'}->{'fth'}{"$collector-SELF"} =
                $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}->prepare(
                    $template{'columns'}
                );

            $arg{'flowCache'}->{'fth'}{"$collector-SELF"}->addFlow(\@rfc5610);
            my $packetsSent = $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}->send();
            $pktCount += $packetsSent;
        }
    }

    if ($arg{'verbose'}) {
        my $shortTime = &ipfixify::util::formatShortTime();
        my $label = $arg{'cacheid'} ? "-C$arg{'cacheid'}" : "";

        print "* $shortTime Option Template ".
          "[$template{'id'}$label] - Sent ".
                $pktCount * @{$arg{'cfg'}->{'collector'}}.
                  " packet(s)\n";
    }

    return 0;
}

#####################################################################

=pod

=head2 sendFlows

This function sends the flows that are in the flow cache(s).

=over 2

    &ipfixify::ipfix::sendFlows(
        'cfg'			=> \%cfg,
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'spool'			=> 'SPOOL_FILE_NAME'
        'originator'	=> $originator,
        'flowCache'		=> \%flowCache,
        'syspoll'		=> $syspoll
    );

=back

The currently supported parameters are:

=over 2

=item * cfg

the current known cfg state

=item * flowCache

a reference to all things flows

=item * verbose

puts this function in verbose mode

=item * spool

if true, this will be the name of the spool file for the data.

=back

=cut

sub sendFlows {
    my (%arg);
    my ($pktCount);

    %arg = (@_);

    if ($arg{'cfg'}->{'mode'} eq 'sysmetrics') {
        #print "Spooling (Start)\n";
        my (@queue);
        my ($dh, $file, $line);

        opendir ($dh, $ENV{'TMPDIR'});
        @queue = sort {$a cmp $b} grep { /\.close/ } readdir($dh);
        closedir $dh;

        foreach $file (@queue) {
            my ($epoch, $computer, $fCache, $spool);
            my (@spool);

            ($epoch, $computer, $fCache) = split (/-/, $file);
            $fCache =~ s/\.close//;

            open($spool, '<', "$ENV{'TMPDIR'}/$file");
            @spool = <$spool>; chomp(@spool);
            close ($spool);

            foreach $line (@spool) {
                push
                  (
                   @{$arg{'flowCache'}->{$fCache}{'flows'}{'SELF'}},
                   &ipfixify::parse::fileLine
                   (
                    'line'		=> $line,
                    'cfg'		=> $arg{'cfg'},
                    'cacheid'	=> $fCache,
                    'verbose'	=> $arg{'verbose'},
                    'originator'=> $arg{'originator'},
                    'flowCache'	=> $arg{'flowCache'},
                    'syspoll'	=> $arg{'syspoll'}
                   )
                  );
            }
            unlink "$ENV{'TMPDIR'}/$file"
              if (-e "$ENV{'TMPDIR'}/$file");
        }
        #print "Spooling (End)\n";
    }

    foreach my $fCache (0..150) {
        next unless (scalar keys %{$arg{flowCache}->{$fCache}{flows}});

        my %copyCache = %{$arg{'flowCache'}->{$fCache}{'flows'}};
        %{$arg{'flowCache'}->{$fCache}{'flows'}} = undef;

        if ($arg{'spool'}) {
            next if (! $copyCache{'SPOOL'});

            my ($filename, $records, $spool);

            $filename = "$ENV{'TMPDIR'}/$arg{'spool'}-$fCache";

            open($spool, '>',"${filename}.open");

            foreach (@{$copyCache{'SPOOL'}}) {
                print $spool "$_\n";
                $records++;
            }

            close($spool);

            print "- wrote $records records to spool ${filename}\n"
              if ($arg{'verbose'} > 1);

            rename("${filename}.open", "${filename}.close");
        } else {
            foreach (keys %copyCache) {
                next if (! $copyCache{$_});

                my ($cachePacketCount);

                foreach my $collector (@{$arg{'cfg'}->{'collector'}}) {
                    if (! $arg{'flowCache'}->{'fdh'}{"$collector-$_"}) {
                        my ($sendAddr, $sendPort, $spoof);

                        ($sendAddr, $sendPort) =
                          &ipfixify::util::getIpPort
                            (
                             check => $collector
                            );

                        $arg{'flowCache'}->{'fdh'}{"$collector-$_"} =
                          &ipfixify::ipfix::setupFdh
                            (
                             ip		=> $sendAddr,
                             port	=> $sendPort,
                            );
                    } else {
                        my $packetsSent;

                        $arg{'flowCache'}->{'fth'}{"$collector-$_"} =
                            $arg{'flowCache'}->{'fdh'}{"$collector-$_"}->prepare($arg{'flowCache'}->{$fCache}{'columns'});

                        eval {
                            $arg{flowCache}->{fth}{"$collector-$_"}->addFlow( \@{$copyCache{$_}});
                        };

                        if ($@) {
                            open(my $fh, '>', "$ENV{'TMPDIR'}/ipfixify-addflow.dump" );    # ACF DEBUG
                            print $fh $@, "\n";
                            print $fh $fCache, "\n";
                            print $fh $arg{flowCache}->{$fCache}{columns}, "\n";
                            print $fh "$collector-$_", Dumper( \@{ $copyCache{$_} } ), "\n";
                            close $fh;

                            #die "$collector-$_: $@\n$arg{flowCache}->{$fCache}{columns}";
                        }

                        eval {
                            $packetsSent = $arg{'flowCache'}->{'fdh'}{"$collector-$_"}->send();
                        };

                        if ($@) {
                            open( my $fh, '>', "$ENV{'TMPDIR'}/ipfixify-send.dump" );
                            print $fh $@, "\n";
                            print $fh $fCache, "\n";
                            print $fh $arg{flowCache}->{$fCache}{columns}, "\n";
                            print $fh "$collector-$_", Dumper( \@{ $copyCache{$_} } ), "\n";
                            close $fh;
                        }

                        $pktCount += $packetsSent;
                        $cachePacketCount += $packetsSent;
                    }
                }

                if ($arg{'verbose'}) {
                    my $shortTime = &ipfixify::util::formatShortTime();
                    my $fCacheLabel = sprintf("%03d", $fCache);
                    my $label = $arg{flowCache}->{$fCache}{id} ? $arg{flowCache}->{$fCache}{id} : 'custom';

                    print "+ $shortTime Flow Cache ".
                      sprintf ('%-4s', $fCacheLabel).
                        '['.
                          sprintf ('%-12s', $label).
                            "] - Sent ".
                              $cachePacketCount * @{$arg{'cfg'}->{'collector'}}.
                                " packet(s)\n"
                                  if ($cachePacketCount);
                }
            }
        }
    }

    if ($arg{'verbose'}) {
        my $shortTime = &ipfixify::util::formatShortTime();

        print "* $shortTime Flow Data - Sent ".
          $pktCount * @{$arg{'cfg'}->{'collector'}}.
            " packet(s)\n"
              if ($pktCount);
    }

    return undef;
}

#####################################################################

=pod

=head2 sendOptionTemplate

This function sends IPFIX option templates.

=over 2

    &ipfixify::ipfix::sendOptionTemplate(
        'flowCache'		=> \%flowCache,
        'enums'			=> \%enums,
        'cacheid'		=> $cacheid,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

=back

The currently supported parameters are:

=over 2

=item * flowCache

the current state of the flowCache

=item * enums

The name value pairs that will be exported as part of the option template

=item * cacheid

the internal cache id of the option template (see definitions.pm)

=item * verbose

puts this function in verbose mode

=item * cfg

the current global configuration settings

=back

=cut

sub sendOptionTemplate {
    my (%arg, %template);
    my (@flows);
    my ($pktCount);

    %arg = (@_);

    %template = &ipfixify::definitions::tempSelect(
        flowCache => $arg{'cacheid'}
    );

    print "+ Sending $template{id} options template\n\n"
      if ($arg{'verbose'} > 1);

    foreach (keys(%{$arg{'enums'}})){
        push (@flows, $_, $arg{'enums'}->{$_});

        if ($arg{'verbose'} > 1) {
            print "  - option template data flow\n\n".
                "    $_ -> $arg{'enums'}->{$_}\n\n";
        }
    }

  ### SEND OPTION TEMPLATE ###
    foreach my $collector (@{$arg{'cfg'}->{'collector'}}) {
        if (! $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}) {
            my ($sendAddr, $sendPort, $spoof);

            ($sendAddr, $sendPort) = &ipfixify::util::getIpPort(
                check => $collector
            );

            $arg{'flowCache'}->{'fdh'}{"$collector-SELF"} =
			  &ipfixify::ipfix::setupFdh
				(
				 ip		=> $sendAddr,
				 port	=> $sendPort,
				);
        } else {
            $arg{'flowCache'}->{'fth'}{"$collector-SELF"} =
                $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}->prepare(
                    $template{'columns'}
                );

            $arg{'flowCache'}->{'fth'}{"$collector-SELF"}->addFlow(\@flows);
            my $packetsSent = $arg{'flowCache'}->{'fdh'}{"$collector-SELF"}->send();
            $pktCount += $packetsSent;
        }
    }

    if ($arg{'verbose'}) {
        my $shortTime = &ipfixify::util::formatShortTime();

        print "* $shortTime Option Template ".
          "[$template{'id'}] - Sent ".
                $pktCount * @{$arg{'cfg'}->{'collector'}}.
                  " packet(s)\n";
    }

    return 0;
}

#####################################################################

=pod

=head2 setupFdh

This function establishes a socket for sending flows

=over 2

        $connection = &ipfixify::ipfix::setupFdh(
            ip		=> $sendAddr,
            port	=> $sendPort,
        );

=back

The currently supported parameters are:

=over 2

=item * ip

the sender IP will be used if spoof doesn't overwrite it

=item * port

the udp port to use when sending flows

=back

=cut

sub setupFdh {
    my (%arg);

    %arg = (@_);

    return getFDIHandle
	  (
	   {
		CollectorIp   => $arg{'ip'},
		CollectorPort => $arg{'port'},
		MTU           => 1400,
	   }
	  );
}

#####################################################################

=pod

=head2 sysmetricsOptionTemplates

This function forms the IPFIX option templates for system metrics

=over 2

    &ipfixify::ipfix::sysmetricsOptionTemplates(
        'flowCache'		=> \%flowCache,
        'verbose'		=> $verbose,
        'cfg'			=> \%cfg
    );

=back

The currently supported parameters are:

=over 2

=item * flowCache

the current state of the flowCache

=item * verbose

puts this function in verbose mode

=item * cfg

the current global configuration settings

=back

=cut

sub sysmetricsOptionTemplates {
    my (%arg, %enums);

    %arg = (@_);

  ### SEND LOGIN STATE OPTION TEMPLATE ###

    %enums =
      (
       '0' => 'Login',
       '1' => 'Logged In',
       '2' => 'Log off',
       '3' => 'Denied',
       '4' => 'Discarded',
      );

    &ipfixify::ipfix::sendOptionTemplate
	  (
	   'flowCache'	=> $arg{'flowCache'},
	   'enums'		=> \%enums,
	   'cacheid'	=> 110,
	   'verbose'	=> $arg{'verbose'},
	   'cfg'		=> $arg{'cfg'}
	  );

  ### SEND LOGIN TYPE OPTION TEMPLATE ###

    %enums =
      (
       2 => 'Local',
       3 => 'Network',
       4 => 'Batch',
       5 => 'Service',
       7 => 'Unlock',
       8 => 'NetworkCleartext',
       9 => 'NewCredentials',
       10 => 'RemoteInteractive',
       11 => 'CachedInteractive',
       200 => 'PEAP',
       201 => 'MS-CHAPv2',
       202 => 'EAP',
       203 => 'Unauthenticated',
       255 => 'Unknown',
    );

    &ipfixify::ipfix::sendOptionTemplate
	  (
	   'flowCache'	=> $arg{'flowCache'},
	   'enums'		=> \%enums,
	   'cacheid'	=> 111,
	   'verbose'	=> $arg{'verbose'},
	   'cfg'		=> $arg{'cfg'}
	  );

  ### SEND NETSTAT STATE OPTION TEMPLATE ###

    %enums =
      (
       '0' => 'UNKNOWN',
       '1' => 'LISTEN',
       '2' => 'ESTABLISHED',
       '3' => 'SYN_SENT',
       '4' => 'SYN_RECV',
       '5' => 'LAST_ACK',
       '6' => 'CLOSE_WAIT',
       '7' => 'TIME_WAIT',
       '8' => 'CLOSED',
       '9' => 'CLOSING',
       '10' => 'FIN_WAIT1',
       '11' => 'FIN_WAIT2'
      );

    &ipfixify::ipfix::sendOptionTemplate
	  (
	   'flowCache'	=> $arg{'flowCache'},
	   'enums'		=> \%enums,
	   'cacheid'	=> 112,
	   'verbose'	=> $arg{'verbose'},
	   'cfg'		=> $arg{'cfg'}
	  );

    return 0;
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
