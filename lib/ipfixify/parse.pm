#!perl

package ipfixify::parse;

use strict;
use Carp qw(carp);
use Config::IniFiles;
use Data::Dumper;
use Date::Parse;
use DateTime::Locale::en_US;
use DateTime::Format::Builder::Parser::Dispatch;
use DateTime::Format::Builder::Parser::generic;
use DateTime::Format::Builder::Parser::Quick;
use DateTime::Format::Builder::Parser::Regex;
use DateTime::Format::Builder::Parser::Strptime;
use DateTime::Format::ISO8601;
use Encode;
use Exporter;
use File::Pid;
use Socket qw(:DEFAULT AF_INET);
use Text::CSV_XS;
use Time::Local;

our ($VERSION);
our (@ISA, @EXPORT);

our ($syslogCount, $uptime, $show);

$uptime				= time();
$show				= 0;

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
    &fileLine
    &inet_a2b
    &inet_b2a
    &userNameFlow
    &v_ip
    &v_mac
);

BEGIN {
    my @imports = (qw(AF_INET6));
    my @socket6_imports;

    # This might be overkill, but I'm not certain that all these
    # imports were added to Socket at the same time.
    for my $export (@imports) {
        eval { Socket->import($export); };
        if ($@) {
            push @socket6_imports, $export;
        }
    }

    eval {
        # Test to see if the sub works.
        # Socket::inet_ntop() may exist, but die with:
        # Socket::inet_ntop not implemented on this architecture
        Socket::inet_ntop( AF_INET, "\0\0\0\0" ); # test
        Socket->import('inet_ntop'); # import if the test doesn't die
    };

    if ($@) {
        push @socket6_imports, 'inet_ntop';
    }

    eval {
        # Test to see if the sub works.
        # Socket::inet_pton() may exist, but die with:
        # Socket::inet_pton not implemented on this architecture
        Socket::inet_pton( AF_INET, '0.0.0.0' ); # test
        Socket->import('inet_pton'); # import if the test doesn't die
    };

    if ($@) {
        push @socket6_imports, 'inet_pton';
    }

    if (@socket6_imports) {
        eval { require Socket6 };
        die $@ if $@;
        Socket6->import(@socket6_imports);
    }
}

=pod

=head1 NAME

ipfixify::parse

=head1 SYNOPSIS

=over 2

    %cfg = &ipfixify::parse::cfgCheck(
        'autostart'	=> $svc,
        'svcName'	=> $svcName,
        'config'	=> $config,
        'filename'	=> $filename,
        'dataTypes'	=> \%dataType,
        'semantics'	=> \%semantics,
        'dataUnits'	=> \%dataUnits,
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

    @flow = &ipfixify::parse::fileLine(
        'line'			=> $_[ARG0],
        'cfg'			=> \%cfg,
        'cacheid'		=> #,
        'verbose'		=> $verbose,
        'originator'	=> $originator,
        'flowCache'		=> \%flowCache
    );

    my ($flow, $alert) = &ipfix::parse::honeynet(
        'flow'			=> $_[ARG0],
        'originator'	=> $originator
    );

    ($user, $userFlow, $tmplUsed) = &ipfixify::parse::userNameFlow(
        'record'		=> $record,
        'computer'		=> $arg{'computer'},
        'originator'	=> $arg{'originator'}
    );

    $ip = &ipfixify::parse::v_ip($ip);

    $mac = &ipfixify::parse::v_mac($mac);

=back

=head1 DESCRIPTION

This module contains functions related to parsing data to export as
IPFIX.

The following functions are part of this module.

=cut

#####################################################################

=pod

=head2 cfgCheck

This function takes a line and parses it up and sends it out as flows.

=over 2

    %cfg = &ipfixify::parse::cfgCheck(
        'autostart'	=> $svc,
        'svcName'	=> $svcName,
        'config'	=> $config,
        'filename'	=> $filename,
        'dataTypes'	=> \%dataType,
        'semantics'	=> \%semantics,
        'dataUnits'	=> \%dataUnits,
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

=back

The currently supported parameters are:

=over 2

=item * autostart

This dictates if ipfixify should autostart on system boot

=item * svcName

If its going to start as a service, what's the service name.

=item * config

the path and filename to the config file.

=item * filename

The filename to watch for changes

=item * dataTypes

A hash of supported dataTypes as outlined by RFC5610

=item * semantics

A has of supported semantics as outlined by RFC5610

=item * dataUnits

A has of supported dataUnits as outlined by RFC5610

=item * version

The current versioning details

=item * test

This tells IPFIXify to only test the configuration and exit.

=item * verbose

If true, IPFIXify will spit out more messages.

=item * syslog

If true, contains syslog mode details

=item * originator

the IP address to reference as the original source

=item * sendTo

Allows an IP address and port to send the IPFIXify data somewhere else
in stream mode.

=item * sourceIp

The source IP allows a users to send data from a different interface
(by IP) on the same system.

=item * psexec

For system metrics mode on windows, this is the path to psexec.exe

=item * syspoll

For system metrics mode on windows, this specifies which system to
poll

=item * honeynet

if true, this contains honeynet mode details

=item * stream

if true, this contains stream mode details

=back

=cut

sub cfgCheck {
    my (%arg, %cfg, %dupcheck, %dataType, %semantics);
    my (@columns, @collector, @members);
    my (
        $errList, $ini, $columnCount, $collectorCount, $pidfile,
        $pidDef, $filename, $perm, $columns, $columnCheck
    );

    %arg = (@_);
    %dataType = &ipfixify::definitions::defDataType;
    %semantics = &ipfixify::definitions::defSemantics;
    $filename = $arg{'filename'} ? $arg{'filename'} : '';

    if (! $arg{'test'} && ! $arg{'syspoll'}) {
        &ipfixify::help::mainHelp(version => $arg{'version'})
          if (! $filename && ! $arg{'syslog'} && ! $arg{'sysmetrics'} && ! $arg{'stream'} && ! $arg{'honeynet'});
    }

    if (! -e $arg{'config'} && ! $arg{'stream'} && ! $arg{'syspoll'} && ! $arg{'honeynet'}) {
        &ipfixify::help::mainHelp(version => $arg{'version'})
    }

    if ($arg{'sourceip'}) {
        if (! &ipfixify::parse::v_ip($arg{'sourceip'})) {
            $errList .= "\n\n* The source IP defined as ".
              "'$arg{'sourceip'}' is invalid\n";
        } else {
            $cfg{'sourceip'} = $arg{'sourceip'};
        }
    } else {
        $cfg{'sourceip'} = $arg{'originator'};
    }

    if ($arg{'autostart'}) {
        if ($arg{autostart} !~ /^y/i && $arg{autostart} !~ /^n/i) {
            &ipfixify::help::mainHelp(version => $arg{'version'});
        }
        if ($arg{autostart} =~ /^y/i && ! $arg{svcName}) {
            &ipfixify::help::mainHelp(version => $arg{'version'});
        }

        &ipfixify::util::serviceMgr
          (
           'autostart' => $arg{'autostart'},
           'svcName' => $arg{'svcName'},
           'version' => $arg{'version'},
           'config' => $arg{'config'},
           'filename' => $arg{'filename'},
           'syslog' => $arg{'syslog'},
           'honeynet' => $arg{'honeynet'},
           'sysmetrics' => $arg{'sysmetrics'},
           'psexec'	=> $arg{'psexec'},
           'sourceip' => $arg{'sourceip'}
          );

        exit(0);
    }

    if (! $arg{'stream'} && ! $arg{'honeynet'}) {
        print "\n$arg{'version'}\n\n+ Scrutinizing $arg{'config'}\n"
          if (($arg{'test'} || $arg{'verbose'}) && ! $arg{'syspoll'});

        $ini = new Config::IniFiles
          (
           -file => $arg{'config'},
           -nomultiline => 1
          );

        @collector = $ini->val('options', 'collector');
        $cfg{'collector'} = \@collector;

        @columns = $ini->val('options', 'column');
        $cfg{'columns'} = \@columns;

      ### NOW PROCESS OPTIONAL SETTING NOT ALWAYS THERE IN THE CFG ###
        if ($ini->val('options', 'delimiter')) {
            $cfg{'delimiter'} = $ini->val('options', 'delimiter');

            if ($cfg{'delimiter'} =~ m/space/i) {
                $cfg{'delimiter'} =~ s/space/\ /i;
            } elsif ($cfg{'delimiter'} =~ m/pipe/i) {
                $cfg{'delimiter'} =~ s/pipe/\\\|/i;
            } elsif ($cfg{'delimiter'} =~ m/tab/i) {
                $cfg{'delimiter'} = "\t";
            }
        }

        # BUG 14593
        if ($ini->val('options', 'usernamesOnly')) {
            $cfg{'usernamesOnly'} =
              $ini->val('options', 'usernamesOnly');
        }

        # BUG 15078
        if ($ini->val('options', 'pollTimeOut')) {
            if ($ini->val('options', 'pollTimeOut') =~ m/\D/) {
                print "\n\n** Error: pollTimeOut contains non-digits";
                exit(0);
            }
            $cfg{'pollTimeOut'} = $ini->val('options', 'pollTimeOut');
        } else {
            $cfg{'pollTimeOut'} = '300';
        }

        if ($ini->val('options', 'originator')) {
            $cfg{'originator'} = $ini->val('options', 'originator');
        }

        if ($ini->val('options', 'member')) {
            @members = $ini->val('options', 'member');

            if (@members > 1 && ! $ini->val('options', 'credentials')) {
                print "\n** ERROR: Members are defined, but there ".
                  "are no credentials.\n\n  Please define ".
                    "credentials by executing ".
                      "the following command:\n\n".
                        " ipfixify.exe --credentials=<PATH/TO/CFG>\n";
                exit(0);
            }

            if ($ini->val('options', 'credentials')) {
                @members = $ini->val('options', 'member');

                ($cfg{'user'}, $cfg{'pwd'}) = &ipfixify::util::pwdmgr
                  (
                   'credentials'=> $ini->val('options', 'credentials'),
                   'direction'  => 'decode'
                  );
            } else {
                push @members, qq {$arg{'originator'}};
            }
        } else {
            push @members, qq {$arg{'originator'}};
        }

        $cfg{'members'} = \@members;

        if ($ini->val('options', 'pingthreads')) {
            $cfg{'pingthreads'} = $ini->val('options', 'pingthreads');
        } else {
            $cfg{'pingthreads'} = 1;
        }

        if ($ini->val('options', 'pollthreads')) {
            $cfg{'pollthreads'} = $ini->val('options', 'pollthreads');
        } else {
            $cfg{'pollthreads'} = 2;
        }

        if (defined $ini->val('options', 'pingtimeout')) {
            $cfg{'pingtimeout'} = $ini->val('options', 'pingtimeout');
        } else {
            $cfg{'pingtimeout'} = 1;
        }

        if ($ini->val('options', 'testinterval')) {
            $cfg{'testinterval'} = $ini->val('options', 'testinterval') * 60;
        } else {
            $cfg{'testinterval'} = 60 * 60;
        }

        if ($ini->val('options', 'vitals')) {
            $cfg{'vitals'} = $ini->val('options', 'vitals');
        }

        if ($ini->val('options', 'eventlogs')) {
            $cfg{'eventlogs'} = $ini->val('options', 'eventlogs');
        }

        if ($ini->val('options', 'storageAvailability')) {
            $cfg{'storageAvailability'} = $ini->val('options', 'storageAvailability');
        }

        if ($ini->val('options', 'processLists')) {
            $cfg{'processLists'} = $ini->val('options', 'processLists');
        }

        if ($ini->val('options', 'processListsCPU')) {
            $cfg{'processListsCPU'} = $ini->val('options', 'processListsCPU');
        }

        if ($ini->val('options', 'netstatDetails')) {
            $cfg{'netstatDetails'} = $ini->val('options', 'netstatDetails');
        }

        if ($ini->val('options', 'ifStatistics')) {
            $cfg{'ifStatistics'} = $ini->val('options', 'ifStatistics');
        }
    } else {
        print "\n$arg{'version'}\n" if ($arg{'verbose'});
    }

  ### CARRY ON ###

    if (! $cfg{collector} && ! $arg{'stream'} && ! $arg{'syspoll'} && ! $arg{'honeynet'}) {
        print "\n** Error: No collectors in $arg{'config'}\n";
        exit(0);
    }

    $perm++ if ($arg{'syslog'});
    $perm++ if ($arg{'stream'});
    $perm++ if ($arg{'filename'} && ! $arg{'honeynet'});
    $perm++ if ($arg{'sysmetrics'});
    $perm++ if ($arg{'syspoll'});
    $perm++ if ($arg{'honeynet'});

    if ($perm > 1) {
        print "\n\n** Error: Only one mode can be enabled on ".
          "the command line.";
        exit(0);
    }

    if ($arg{'filename'}) {
        $cfg{'mode'} = 'filefollow';
        $pidDef = "pid.$filename";
    }

    if ($arg{'syslog'}) {
        my ($ip, $port, $error);

        $cfg{'mode'} = 'syslog';

        ($ip, $port) = &ipfixify::util::getIpPort
          (
           check => $arg{'syslog'}
          );

        if (! $ip) {
            $error .= "\n- The syslog listener IP is missing (ip:port)";
        } elsif (! v_ip($ip)) {
            $error .= "\n- The syslog listener defined as '$ip' is invalid";
        } elsif ($ip =~ m/^127\./) {
            $error .= "\n- The syslog listener IP cannot be a loopback address ($ip)";
        } elsif ($ip =~ m/^0\.0\.0\.0$/) {
            $error .= "\n- The syslog listener IP cannot be $ip";
        }

        if (! $port) {
            $error .= "\n- The syslog UDP port defined is missing (ip:port)";
        } elsif ($port =~ m/\D/ || $port > 65535) {
            $error .= "\n- The syslog UDP port defined as '$port' is invalid";
        }

        if ($error) {
            $errList .= "\n\n** Error defining syslog listener **\n$error";
        }

        $pidDef = "pid.syslog_$arg{'syslog'}";
    };

    if ($arg{'stream'}) {
        my ($error, $ip, $port);

        $cfg{'mode'} = 'stream';

        ($ip, $port) = &ipfixify::util::getIpPort
          (
           check => $arg{'stream'}
          );

        if ($arg{'sendto'}) {
            $arg{'sendto'} =~ s/\ //ig;
            my @list = split (/,/, $arg{'sendto'});

            foreach (@list) {
                my ($streamip, $streamport) =
                  &ipfixify::util::getIpPort
                    (
                     check => $_
                    );

                if (! $streamip) {
                    $error .= "\n- The send to IP is missing (ip:port)";
                } elsif (! &ipfixify::parse::v_ip($streamip)) {
                    $error .= "\n- The send to defined as '$streamip' is invalid";
                }

                if (! $streamport) {
                    $error .= "\n- The send to UDP port defined is missing (ip:port)";
                } elsif ($streamport =~ m/\D/ || $streamport > 65535) {
                    $error .= "\n- The send to UDP port defined as '$streamport' is invalid";
                }
                push (@collector, "$streamip:$streamport");
            }
        } else {
            push (@collector, "$ip:4739");
        }

        $cfg{'collector'} = \@collector;

        if (! $ip) {
            $error .= "\n- The stream listener IP is missing (ip:port)";
        } elsif (! &ipfixify::parse::v_ip($ip)) {
            $error .= "\n- The stream listener defined as '$ip' is invalid";
        } elsif ($ip =~ m/^127\./) {
            $error .= "\n- The stream listener IP cannot be a loopback address ($ip)";
        } elsif ($ip =~ m/^0\.0\.0\.0$/) {
            $error .= "\n- The stream listener IP cannot be $ip";
        }

        if (! $port) {
            $error .= "\n- The stream UDP port defined is missing (ip:port)";
        } elsif ($port =~ m/\D/ || $port > 65535) {
            $error .= "\n- The stream UDP port defined as '$port' is invalid";
        }

        if ($error) {
            $errList .= "\n\n** Error defining stream mode **\n$error";
        }

        $pidDef = "pid.stream_$arg{'stream'}";
    };

    if ($arg{'honeynet'}) {
        my ($error, $ip, $port);
        my (@collector);

        ($ip, $port) = &ipfixify::util::getIpPort
          (
           check => $arg{'honeynet'}
          );

        if (! $ip) {
            $error .= "\n- The collector IP is missing (ip:port)";
        } elsif (! &ipfixify::parse::v_ip($ip)) {
            $error .= "\n- The collector defined as '$ip' is invalid";
        } elsif ($ip =~ m/^127\./) {
            $error .= "\n- The collector IP cannot be a loopback address ($ip)";
        } elsif ($ip =~ m/^0\.0\.0\.0$/) {
            $error .= "\n- The collector IP cannot be $ip";
        }

        if (! $port) {
            $error .= "\n- The collector UDP port defined is missing (ip:port)";
        } elsif ($port =~ m/\D/ || $port > 65535) {
            $error .= "\n- The collector UDP port defined as '$port' is invalid";
        }

        if ($arg{'sendto'}) {
            my ($streamip, $streamport) = &ipfixify::util::getIpPort
              (
               check => $arg{'sendto'}
              );

            if (! $streamip) {
                $error .= "\n- The syslog server IP is missing (ip:port)";
            } elsif (! &ipfixify::parse::v_ip($streamip)) {
                $error .= "\n- The syslog server defined as '$streamip' is invalid";
            }

            if (! $streamport) {
                $error .= "\n- The syslog server UDP port defined is missing (ip:port)";
            } elsif ($streamport =~ m/\D/ || $streamport > 65535) {
                $error .= "\n- The syslog server UDP port defined as '$streamport' is invalid";
            }
        } else {
            $error .= "\n- The sendto syslog server is missing";
        }

        if ($error) {
            $errList .= "\n\n** Error defining honeynet mode **\n$error";
        }

        push (@collector, "$ip:$port");
        $cfg{'mode'} = 'honeynet';
        $cfg{'collector'} = \@collector;
        $pidDef = "pid.honeynet_$arg{'honeynet'}";
    }

    if ($arg{'sysmetrics'}) {
        my ($needPsExec);

        foreach (@members) {
            if ($_ ne $arg{'originator'} && $^O eq 'MSWin32' && $cfg{'netstatDetails'}) {
                $needPsExec = 1;
            }
        }

        if (! $arg{'psexec'} && $needPsExec) {
            $errList .= "\n\n* Path/to/PSexec.exe is required when collecting netstatDetails\n".
              "  from remote systems on the Windows Platform\n";
        } elsif (! -e $arg{'psexec'} && $needPsExec) {
            $errList .= "\n\n* Could not find psexec.exe at $arg{'psexec'}\n";
        } else {
            $cfg{'psexec'} = $arg{'psexec'};
            $cfg{'mode'} = 'sysmetrics';
            $pidDef = "pid.sysmetrics";
        }
    };

    foreach (@collector) {
        my ($ip, $port, $error);

        ($ip, $port) = &ipfixify::util::getIpPort
          (
           check => $_
          );

        $collectorCount++;

        if (! $ip) {
            $error .= "\n- The collector IP is missing (ip:port)";
        } elsif (! &ipfixify::parse::v_ip($ip)) {
            $error .= "\n- The collector defined as '$ip' is invalid";
        }

        if (! $port) {
            $error .= "\n- The port defined is missing (ip:port)";
        } elsif ($port =~ m/\D/ || $port > 65535) {
            $error .= "\n- The port defined as '$port' is invalid";
        }

        if ($dupcheck{"$ip:$port"} eq "$ip:$port") {
            $error .= "\n- Duplicate collector defined ($ip:$port)";
        } else {
            $dupcheck{"$ip:$port"} = "$ip:$port";
        }

        if ($error) {
            $errList .= "\n\n** Error in Collector #$collectorCount ".
              "Definitions **\n$error";
        }
    }

    foreach my $field (@columns) {
        my ($ele, $a2b);
        my (@line);

        $columnCheck++;

        if ($field =~ m/\",\"/) {
          ## OLD FORMAT
            $field =~ s/\"//g;
            @line = split (/\,/, $field);

            $ele = ($line[0] eq '0') ? $line[1] : "$line[0]/$line[1]";
            $a2b = ($line[5] =~ m/address/i) ? ' xform:a2b_na' : '';

            $columns .= lc("$line[3]($ele)").
              "<$line[5]>{$line[6]$a2b}\n";
        } else {
          ## NEW FORMAT
            $field =~ s/\"//g;
            $columns .= "$field\n";
        }
    }

    if ($cfg{'mode'} eq 'filefollow' && $cfg{'originator'}) {
        #if (is_ipv6($arg{'originator'})) {
        #	push @columns, q {IPv6Originator(13745/5060)<ipv6Address>{identifier xform:a2b}};
        #} else {
            $columns .= "ipv4originator(13745/5059)<ipv4Address>{identifier xform:a2b}\n";
        #}
    }

    foreach(split (/\n/, $columns)) {
        next if /^\s*$/;

        my ($lcDType, $lcSemantic, $lcUnits, $error, $element);

        $element = &ipfixify::util::elementCache
          (
           'raw'		=> $_,
           'flowCache'	=> $arg{'flowCache'}
          );

        $columnCount++;

        if ($arg{'verbose'} > 1) {
            print "\n+ Checking column definitions line ".
              "$columnCount\n\n".
              "- informationElementId          (0_303): $element->{'elementId'}\n".
              "- informationElementDataType    (0_339): $element->{'dataType'}\n".
              "- informationElementDescription (0_340): ''\n".
              "- informationElementName        (0_341): $element->{'name'}\n".
              "- informationElementRangeBegin  (0_342): ''\n".
              "- informationElementRangeEnd    (0_343): ''\n".
              "- informationElementSemantics   (0_344): $element->{'dataTypeSemantics'}\n".
              "- informationElementUnits       (0_345): ''\n".
              "- privateEnterpriseNumber       (0_346): $element->{'enterpriseId'}\n".
              "- length                               : $element->{'length'}\n";
        }

        $lcDType = lc($element->{'dataType'});
        $lcSemantic = lc($element->{'dataTypeSemantics'});

        if ($element->{'enterpriseId'} =~ m/\D/ || $element->{'enterpriseId'} < 0 || $element->{'enterpriseId'} > 4294967295) {
            $error .= "\n- The privateEnterpriseNumber defined as '$element->{'enterpriseId'}' is invalid";
        }
        if ($element->{'elementId'} =~ m/\D/ || $element->{'elementId'} < 0 || $element->{'elementId'} > 65535) {
            $error .= "\n- The informationElementId defined as '$element->{'elementId'}' is invalid";
        }
        if ($element->{'length'} =~ m/\D/ || $element->{'length'} > 65535) {
            $error .= "\n- The length defined as '$element->{'length'}' is invalid";
        }

        #if (! defined $dataType{$lcDType}) {
        #	$error .= "\n- The dataType defined as '$dataType{$lcDType}' is invalid";
        #}
        #if (! defined $semantics{$lcSemantic}) {
        #	$error .= "\n- The semantics defined as '$semantics{$lcSemantic}' is invalid";
        #}

        if ($error) {
            $errList .= "\n\n** Error in Column #$columnCount Definitions **\n$error";
        }

        if ($element->{'enterpriseId'} eq '13745' && $element->{'elementId'} eq '115') {
            $cfg{'mailinizer'} = $columnCheck;
        }
    }

    if ($errList) {
        print "$errList\n\nAbort!\n";
        exit(0);
    };

    $cfg{'columns'} = $columns;

    if ($cfg{'mode'} eq 'filefollow') {
        $cfg{'filefollowColumnCount'} = $columnCount;
    }


    if ($arg{'test'}) {
        print "\n[TEST CFG MODE] Looks good!\n\n";
        exit(0);
    }

    $pidDef =~ s/\\|\/|\.|\:/\_/g;

    unlink "$pidDef";

    $pidfile = File::Pid->new({
        file => $pidDef
    });

    $pidfile->write();

    return (%cfg);
}

#####################################################################

=pod

=head2 fileLine

This function takes a line and parses it up and sends it out as flows.

=over 2

    @flow = &ipfixify::parse::fileLine(
        'line'			=> $_[ARG0],
        'cfg'			=> \%cfg,
        'cacheid'		=> #,
        'verbose'		=> $verbose,
        'originator'	=> $originator,
        'flowCache'		=> \%flowCache
    );

=back

The currently supported parameters are:

=over 2

=item * line

A line of text to parse and send out as flows.

=item * cfg

The current configuration from the specified CFG file.

=item * cacheid

the flow cache we are processing at the time. Primarily used for
validating data

=item * verbose

puts this function in verbose mode

=item * originator

This should be the address that the originator column will use. If
there is no originator configured, then this data is discarded and not
included in the flow.

=item * flowCache

a reference to the existing flowCache for originators to reference
cached host names

=back

=cut

sub fileLine {
    my (%arg);
    my (@data, @work);
    my ($cfg, $flowDebug, $colCount, $delimiter, $columns);

    %arg = (@_);

    $cfg = $arg{'cfg'};
    $columns = $arg{'flowCache'}->{$arg{'cacheid'}}{'columns'};
    $colCount = $arg{'flowCache'}->{$arg{'cacheid'}}{'columnCount'};
    $delimiter = $arg{'flowCache'}->{$arg{'cacheid'}}{'delimiter'};

    if ($cfg->{'mode'} eq 'syslog') {
        $colCount = 10; # predetermined right now (bug 12997)
        $arg{'line'}->{$arg{'originator'}} = $arg{'line'}->{'addr'};

        $arg{'line'}->{'msg'} =~ tr/\r\n\0/ /;

        $arg{'line'}->{'addr'} =
          &ipfixify::util::findSourceIpAddressInMsg
            (
             msg		=> $arg{'line'}->{'msg'},
             original	=> $arg{'line'}->{'addr'}
            );

        if ($arg{'line'}->{'msg'} =~ m/spoofaddress/) {
            my ($a, $addr, $b) = split
              (
               /spoofaddress/,
               $arg{'line'}->{'msg'}
              );

            if($addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
                $arg{'line'}->{$arg{'originator'}} = $addr;
            }
            $arg{'line'}->{'msg'} = $a . $b;
        }

        $arg{'line'}->{'processName'} = '-';

        if ($arg{'line'}->{'msg'} =~ m/^(.*)(\[MD5\w+\])(.*)$/ ) {
            $arg{'line'}->{'msg'} = $1 . $3;
            $arg{'line'}->{'msg'} =~ s/^\ //;
        }

        if ($arg{'line'}->{'msg'} =~ m/^(.*)(\[\d+\])(.*)$/ ) {
            $arg{'line'}->{'processName'} = $1;
            $arg{'line'}->{'processId'} = $2;
            $arg{'line'}->{'processId'} =~ s/\[|\]//ig;
        }

        push
          (
           @work,
           [
            $arg{'line'}->{'msg'},
            scalar time(),
            $arg{'line'}->{'pri'},
            $arg{'line'}->{'addr'},
            $arg{'line'}->{'severity'},
            $arg{'line'}->{'facility'},
            $arg{'line'}->{'processName'},
            $arg{'line'}->{'processId'},
            '1', # Placeholder: ipfixifyMessageCount
            $arg{'line'}->{$arg{'originator'}}
           ]
          );
    } elsif ($arg{'eventlog'}) {
        my (
            $date, $time, $year, $mon, $mday, $hour, $min, $sec,
            $epoch, $flow
           );
        my (@hash_key);

        # Andrew's Magic Start
        @hash_key = (qw{message computer source});

        for ( @{ $arg{line} }{@hash_key} ) {
            # FIX UTF-8 *BEFORE* other substitutions
            ##########################################################
            # Always use Encode::LEAVE_SRC with Encode::decode and
            # Encode::enecode or you may not get the results you
            # expect.
            # https://rt.cpan.org/Public/Bug/Display.html?id=80131
            ##########################################################
            eval {
                decode
                  (
                   'UTF-8',
                   $_,
                   Encode::FB_CROAK | Encode::LEAVE_SRC
                  );
            };
            if ($@) {
                # The encode is needed to get the string back in the
                # format it started in.  Not doing the encode is like
                # the residents of Earth, "mostly harmless", but may
                # cause perl to warn about wide characters in print
                # later on when we write to the spool file.
                $_ = encode
                  (
                   'UTF-8',
                   decode
                   (
                    'cp1252', $_,
                    Encode::FB_QUIET | Encode::LEAVE_SRC
                   )
                  );
            }

            tr/\r\n\0/ /;
        }
        # Andrew's Magic End

        ($date, $time) = split /T/ => $arg{line}->{'time_created'};
        ($year, $mon, $mday) = split /-/ => $date;
        ($hour, $min, $sec) = split /:/ => $time;
        $arg{line}->{'time_created'} = timegm
          (
           int($sec),
           $min,
           $hour,
           $mday,
           $mon-1,
           $year-1900
          );

        return join
          (
           ':-:',
           $arg{machineID},
           $arg{eventlog},
           @{$arg{line}}{
                'time_created',
                'record_id',
                'event_id',
                'source',
                'message',
            },
           1,    # Placeholder: ipfixifyMessageCount
           1     # Placeholder: rollable
          );
    } elsif ($cfg->{'mode'} eq 'filefollow') {
        my ($originator, $count);

        if ($cfg->{'delimiter'} eq 'QUOTEDCSV') {
            $arg{'line'} =~ s/",/||/g;
            $arg{'line'} =~ tr/"//d;
            my @line = split (/\|\|/, $arg{'line'});

            if ($cfg->{'originator'}) {
                ($originator, $count) =
                  &ipfixify::util::determineOriginator
                    (
                     data    => \@line,
                     cfg     => $cfg,
                     columns => $columns,
                    );

                $line[$count] = $originator;
            }

            push (@work, [ @line ]);
        } elsif ($cfg->{'mailinizer'}) {
            my ($csv, $line, $status);
            my (@raw);

            return undef if ($arg{'line'} =~ m/^#/);
            # this prevents invalid flows
            # from sneaking in due to
            # MICROSOFTs new log details

            $colCount = $cfg->{'mailinizer'};
            $csv = Text::CSV_XS->new();
            $status  = $csv->parse($arg{'line'});
            $line = join (':-:', $csv->fields());
            @raw = split (/:-:/, $line);

            if ($cfg->{'originator'}) {
                ($originator, $count) =
                  &ipfixify::util::determineOriginator
                    (
                     data    => \@raw,
                     cfg     => $cfg,
                     columns => $columns,
                    );

                $raw[$count] = $originator;
            }

            # bug 18949 - pesky single quotes in email addresses
            $raw[15] =~ s/^'|'$//g;
            $raw[18] =~ s/\'\'/\'/g;
            $raw[15] =~ s/^'|'$//g;
            $raw[18] =~ s/\'\'/\'/g;

            # bug 17373 - send a flow per recipient instead of all in
            # one field
            if ($raw[11] =~ m/;/) {
                my (@recipients);
                @recipients = split (/;/, $raw[11]);

                foreach (@recipients) {
                    my @flow = @raw;
                    $flow[11] = $_;
                    $flow[11] =~ s/^'|'$//g;
                    $flow[11] =~ s/\'\'/\'/g;
                    push (@work, [@flow]);
                }
            } else {
                $raw[11] =~ s/^'|'$//g;
                $raw[11] =~ s/\'\'/\'/g;
                push (@work, [ @raw ]);
            }
        } else {
            my @line = split (/$cfg->{'delimiter'}/, $arg{'line'});

            if ($cfg->{'originator'}) {
                ($originator, $count) =
                  &ipfixify::util::determineOriginator
                    (
                     data   => \@line,
                     cfg	=> $cfg,
                     columns=> $columns,
                    );

                $line[$count] = $originator;
            }

            @work = [ @line ];
            $colCount = $cfg->{'filefollowColumnCount'};
        }
    } elsif ($cfg->{'mode'} eq 'sysmetrics' || $arg{'syspoll'}) {
        push @work, [ split (/:-:/, $arg{'line'}) ];
    } elsif ($cfg->{'mode'} eq 'stream') {
        my $delToUse = $delimiter ? $delimiter : $cfg->{'delimiter'};
        push @work, [ split (/$delToUse/, $arg{'line'}) ];
    } elsif ($cfg->{'mode'} eq 'honeynet') {
        push @work, [ split (/:-:/, $arg{'line'}) ];
    }

    foreach my $queued (@work) {
        my (@flow);
        my ($count);

        $count = 0;
        @flow = @{$queued};

        print "\n+ New data to process\n\n" if ($arg{'verbose'} > 1);

        foreach (split (/\n/, $columns)) {
            next if /^\s*$/;

            my ($label, $element, $ele);

            $element = &ipfixify::util::elementCache
              (
               'raw'		=> $_,
               'flowCache'	=> $arg{'flowCache'}
              );

            $ele = $element->{'ele'};

            $flow[$count] = "" if (! defined $flow[$count]);

            # pack mac address (bug 18445)
            if ($ele eq '56' || $ele eq '57' || $ele eq '80' || $ele eq '81') {
                $flow[$count] = pack( "H*", $flow[$count] );
            }

            # changing sFlow HeaderBin back to Binary for IPFIX export
            if ($ele eq '315') {
                $flow[$count] = pack ('H*', $flow[$count]);
            }

            # need this to force a value of one for
            # ipfixifyMessageCount if the column exists in the
            # template and that value is empty
            if ($ele eq '13745.5223' && ! $flow[$count]) {
                $flow[$count] = '1';
            }

            # for mailinizer support (bug 9120)
            if ($ele eq '13745.115' || $ele eq '13745.116' || $ele eq '13745.105' || $ele eq '13745.124') {
                $flow[$count] =~ s/^\s+// if ($ele eq '13745.115');
                $flow[$count] = lc($flow[$count]);
            }

            # for mailinizer support (bug 12008) this field isn't
            # matching what the docs say, but the others are
            if ($ele eq '13745.109') {
                $flow[$count] = '0' if ($flow[$count] =~ m/\D/ || ! $flow[$count]);
            }

            # What is probably proper is to split out into different
            # templates and turn mailinizer into a mode for IPv6
            if ($ele eq '13745.100' || $ele eq '13745.104' || $ele eq '13745.131') {
                # ::1 in v4 fields (bug 12008)
                $flow[$count] = '127.0.0.1'
                  if ($flow[$count] eq '::1');
                # IPv6 addresses and missing addresses turn to N/A
                # (bug 17373)
                $flow[$count] = '0.0.0.255' if (! $flow[$count] || $flow[$count] eq '' || $flow[$count] =~ m/:/);
            }

            # for mailinizer support (bug 11854)
            if ($ele eq '13745.106') {
                my %events =
                  (
                   BADMAIL		=> 2000,
                   DEFER		=> 2001,
                   DELIVER		=> 2002,
                   DSN			=> 2003,
                   EXPAND		=> 2004,
                   FAIL			=> 2005,
                   POISONMESSAGE=> 2006,
                   RECEIVE		=> 2007,
                   REDIRECT		=> 2008,
                   RESOLVE		=> 2009,
                   SEND			=> 2010,
                   SUBMIT		=> 2011,
                   TRANSFER		=> 2012
                );
                $flow[$count] = $events{$flow[$count]};
            }

            # for mailinizer support (bug 11854)
            if ($ele eq '13745.122') {
                my %sources =
                  (
                   ADMIN		=> 1,
                   AGENT		=> 2,
                   DSN			=> 3,
                   GATEWAY		=> 4,
                   PICKUP		=> 5,
                   ROUTING		=> 6,
                   SMTP         => 7,
                   STOREDRIVER	=> 8
                  );
                $flow[$count] = $sources{$flow[$count]};
            }

            # for mailinizer support (bug 11854)
            if ($ele eq '13745.117') {
                $flow[$count] = &ipfixify::parse::date_time_to_epoch(
                    'date' => $flow[$count]
                );
            }

            ## bug 12008, this corrects non-integers for integer
            ## fields moved to here due to bug 13081
            if ($element->{'dataType'} =~ /signed/ && $flow[$count] !~ /^-?\d+$/) {
                $flow[$count] = int($flow[$count]);
            }

            $label = sprintf '%11s', $ele;
            $flowDebug .= "\n  $label => $flow[$count]";
            print "  $label => $flow[$count]\n"
			  if ($arg{'verbose'} > 1);

            if (! defined $flow[$count]) {
                print "cache $arg{'cacheid'} field $count ".
				  "[$element->{'dataType'}]".
                    " is not defined and it should be\n"
					  if ($arg{'verbose'} > 1);

                if ($element->{'dataType'} =~ m/signed/i) {
                    $flow[$count] = '0';
                } else {
                    $flow[$count] = '';
                }
            }

            $count++;
        }

        if (@flow != $colCount) {
            print "MISMATCH [$arg{'cacheid'}]: ". 
			  scalar(@data).
				" [expected $colCount]\n" ;
            print Dumper \@flow;
            print Dumper $flowDebug;
        } else {
            print "\n" if ($arg{'verbose'} > 1);
            push (@data, @flow);
        }
    }

    return @data;
}

#####################################################################

=pod

=head2 date_time_to_epoch

the mailinizer function is used to convert a string data to epoch.

=over 2

    $epoch = &ipfixify::parse::date_time_to_epoch(
        date => $date
    );

=back

The currently supported parameters are:

=over 2

=item * date

a date string in ISO8601 format

=back

Returns the epoch from the stringed text.

=cut

sub date_time_to_epoch {
    my (%arg);
    my ($epoch);

    %arg = (@_);

    if ($arg{'date'} eq '-'){
        return 0;
    }

    eval {
        my $dt = DateTime::Format::ISO8601->parse_datetime
		  (
		   $arg{'date'}
		  );
        $epoch = $dt->epoch;
    };

    if($@){
        return 0;
    }

    return $epoch;
}

#####################################################################

=method inet_a2b

Convert a human readable (ascii) IP address (v4 or v6) to a packed
(binary) format.

=cut

sub inet_a2b {
    # TODO return vs return undef; This was return undef, but Perl
    # Critic complained.
    (carp "undefined address" && return $_[0]) unless defined $_[0];

    # Bug 10409 and Bug 11845 Socket::aton (which we used to rely on
    # here) does some odd things with empty strings.  As near as I can
    # tell it resolves them to the local IP.  Using inet_pton resolves
    # this issue.
    my $IP;

    eval {
        use bytes;
        $IP = inet_pton(AF_INET,$_[0]) || inet_pton(AF_INET6,$_[0]);
    };

    if ($@) {
        carp "inet_a2b : $_[0] ($@)";
    }
    return $IP;
}

#####################################################################

=method inet_b2a

Convert a packed (binary) IP address (v4 or v6) to a human readable
(ascii) format.

=cut

sub inet_b2a {
    # TODO return vs return undef; This was return undef, but Perl
    # Critic complained.
    (carp "undefined address" && return $_[0]) unless defined $_[0];
    (carp "bad address length" && return undef)
      if (length($_[0]) != 4);

    # for now, only IPv4 support until Scrutinizer has support for
    # IPv6 Username correlation. This below line would replace the
    # above line
      #if (length($_[0]) != 4 && length($_[0]) != 16);

    my $IP_ascii;
    eval {
        use bytes;
        $IP_ascii = inet_ntop(AF_INET,$_[0]);
        # when IPv6 support is added replace the above line with these
        # lines below commented out.
        #$IP_ascii = ( length($_[0]) == 4
        #             ? inet_ntop(AF_INET,$_[0])
        #             : inet_ntop(AF_INET6,$_[0]) );
    };
    if ($@) {
        carp "inet_b2a : $_[0] ($@)";
    }

    # IPv6 addresses can contain IPv4.
    $IP_ascii =~ s/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/$1/;

    return $IP_ascii;
}

#####################################################################

=pod

=head2 honeynet

This function takes a honeynet flow and parses it up and sends it out
as IPFIX.

=over 2

    my $flow = &ipfix::parse::honeynet(
        'flow'			=> $_[ARG0],
        'originator'	=> $originator
    );

=back

The currently supported parameters are:

=over 2

=item * flow

a honeynet log entry to parse

= item * originator

the originator of the flow (ip address)

=back

if a valid or non-excluded flow is processed, it's returned.

=cut

sub honeynet {
    my (%arg, %flow);
    my (@logEntry);
    my ($oneFlow, $exclusion, $flags);

    %arg =(@_);

    $exclusion = 0;

    %flow =
	  (
	   'sourceTransportPort'	=> '',
	   'connectionState'		=> '',
	   'sourceIPv4Address'		=> '',
	   'destinationTransportPort'=> '',
	   'comments'				=> '',
	   'protocolIdentifier'		=> '',
	   'destinationIPv4Address'	=> '',
	   'tcpControlBits'			=> '',
	   'flowStartMilliseconds'	=> '',
	   'octetDeltaCount'		=> '',
	   'octetDeltaCountrev'		=> ''
	  );

    if ($arg{'flow'} =~ m/\|/) {
        @logEntry = split (/\ /, $arg{'flow'}, 7);

        $flow{'flowStartMilliseconds'} = str2time($logEntry[0]).'0000000000000';
        $flow{'flowStartMilliseconds'} =~ s/\.//;
        $flow{'flowStartMilliseconds'} = substr($flow{'flowStartMilliseconds'}, 0, 13);

        (undef, $flow{protocolIdentifier}) = split(/\(/,$logEntry[1]);
        chop($flow{'protocolIdentifier'});

        $flow{'sourceIPv4Address'} = $logEntry[2];
        $flow{'sourceTransportPort'} = $logEntry[3];
        $flow{'destinationIPv4Address'} = $logEntry[4];
        $flow{'destinationTransportPort'} = $logEntry[5];
        $flow{'destinationTransportPort'} =~ s/://;
        $flow{'comments'} = $logEntry[6];
    } else {
        $arg{'flow'} =~ s/\://g;
        @logEntry = split (/\ /, $arg{'flow'});

        $flow{'flowStartMilliseconds'} = str2time($logEntry[0]).'0000000000000';
        $flow{'flowStartMilliseconds'} =~ s/\.//;
        $flow{'flowStartMilliseconds'} = substr($flow{'flowStartMilliseconds'}, 0, 13);

        (undef, $flow{'protocolIdentifier'}) = split (/\(/, $logEntry[1]);
        chop($flow{'protocolIdentifier'});

        if ($logEntry[2] eq 'E') {
            $flow{'connectionState'} = '2';
            $flow{'octetDeltaCountrev'} = $logEntry[7];
            $flow{'octetDeltaCount'} = $logEntry[8];
        } elsif ($logEntry[2] eq 'S') {
            $flow{'connectionState'} = '0';
        } elsif ($logEntry[2] eq '-') {
            $flow{'connectionState'} = '1';
        }

        if ($flow{'protocolIdentifier'} eq '1') {
            my ($type, $code, $padded, $fix);
            ($code, $type) = split (/\(/, $logEntry[5]);
            chop($type); chop($type);
            $padded = sprintf("%02d", $code);
            $fix = $type.$padded;

            $flow{'sourceIPv4Address'} = $logEntry[3];
            $flow{'sourceTransportPort'} = '0';
            $flow{'destinationIPv4Address'} = $logEntry[4];
            $flow{'destinationTransportPort'} = hex($fix);
            $flow{'octetDeltaCount'} = $logEntry[6];
        } else {
            $flow{'sourceIPv4Address'} = $logEntry[3];
            $flow{'sourceTransportPort'} = $logEntry[4];
            $flow{'destinationIPv4Address'} = $logEntry[5];
            $flow{'destinationTransportPort'} = $logEntry[6];

            if ($flow{'connectionState'} eq '1') {
                $flow{'octetDeltaCount'} = $logEntry[7];
                $flags = $logEntry[8];

                $flow{'tcpControlBits'} += 1 if ($flags =~ /F/);
                $flow{'tcpControlBits'} += 2 if ($flags =~ /S/);
                $flow{'tcpControlBits'} += 4 if ($flags =~ /R/);
                $flow{'tcpControlBits'} += 8 if ($flags =~ /P/);
                $flow{'tcpControlBits'} += 16 if ($flags =~ /A/);
                $flow{'tcpControlBits'} += 32 if ($flags =~ /U/);
                $flow{'tcpControlBits'} += 64 if ($flags =~ /E/);
                $flow{'tcpControlBits'} += 128 if ($flags =~ /C/);

                $flow{'comments'} = "@logEntry[9..$#logEntry]";
            } elsif ($flow{'connectionState'} eq '0') {
                $flow{'comments'} = "@logEntry[7..$#logEntry]";
            }
        }
    }

    $oneFlow = join
      (
       ':-:',
        $arg{'originator'},
        $arg{'originator'},
        $flow{'sourceTransportPort'},
        $flow{'connectionState'},
        $flow{'sourceIPv4Address'},
        $flow{'destinationTransportPort'},
        $flow{'comments'},
        $flow{'protocolIdentifier'},
        $flow{'destinationIPv4Address'},
        $flow{'tcpControlBits'},
        $flow{'flowStartMilliseconds'},
        $flow{'octetDeltaCount'},
        $flow{'octetDeltaCountrev'},
    );

  ### CHECK FOR EXCLUSIONS ###
    if ($flow{'destinationIPv4Address'} eq '255.255.255.255' && $flow{'destinationTransportPort'} eq '68' && $flow{'sourceTransportPort'} eq '67') {
        # EXCLUDE BOOTPC http://www.linklogger.com/UDP67_68.htm
        $exclusion = 1;
    }

  ### LET'S RETURN OUR PRECIOUS FLOW
    if ($exclusion) {
        return (undef, undef);
    } else {
        my $alert = "spoofaddress$flow{'sourceIPv4Address'}spoofaddress potential attack detected by honeynet appliance: $flow{'sourceIPv4Address'} -> [ $flow{'destinationTransportPort'} $logEntry[1] ] -> $flow{'destinationIPv4Address'}. $flow{'comments'}";
        return ($oneFlow, $alert);
    }
}

#####################################################################

=pod

=head2 userNameFlow

This function assembles a user name flow.

=over 2

    ($user, $userFlow, $tmplUsed) = &ipfixify::parse::userNameFlow(
        'record'		=> $record,
        'computer'		=> $arg{'computer'},
        'originator'	=> $arg{'originator'},
        'machineID'		=> $arg{'machineID'}
    );

=back

The currently supported parameters are:

=over 2

=item * record

the data to examine for userNameFlow

=item * computer

the computer this data came from

=item * originator

the IP Address of the agent

=item * machineID

a unique identifer for the endpoint system

=back

=cut

sub userNameFlow {
    my (%arg, %radius);
    my (
        $user, $srcAddr, $domain, $loginID, $loginType, $userFlow,
        $loginState, $flowIt
    );

    %arg = (@_);

    %radius =
      (
       'PEAP' => 200,
       'MS-CHAPv2' => 201,
       'EAP' => 202,
       'unauthenticated' => 203
      );

    if ($arg{'record'}->[0] eq '4624') {
        # For Log ins: Event ID 4624

        if ($arg{'record'}->[15] eq 'Security ID') {
            $user		= $arg{'record'}->[18];
            $domain		= $arg{'record'}->[20];
            $loginID	= $arg{'record'}->[22];
            $loginType	= $arg{'record'}->[11];
            $srcAddr	= $arg{'record'}->[34];
            $loginState = $arg{'record'}->[1];
        } else {
            $user		= $arg{'record'}->[16];
            $domain		= $arg{'record'}->[18];
            $loginID	= $arg{'record'}->[20];
            $loginType	= $arg{'record'}->[11];
            $srcAddr	= $arg{'record'}->[32];
            $loginState = $arg{'record'}->[1];
        }
    }

    if ($arg{'record'}->[0] eq '4634' || $arg{'record'}->[0] eq '4647') {
        # For Log offs: Windows 2008 has Event ID 4634 and 4647. Event
        # ID 4647 might help grab some of those log offs not recorded
        # as part of 4634 (reference bug 10984)

        $user		= $arg{'record'}->[5];
        $domain		= $arg{'record'}->[7];
        $loginID	= $arg{'record'}->[9];
        $loginType	= $arg{'record'}->[0] eq '4634' ? $arg{'record'}->[11] : '255';
        $srcAddr	= '0.0.0.255';
        $loginState = 2;
    }

    if ($arg{'record'}->[0] eq '6272') {
        # Bug 18445 (Radius)
        # Network Policy Server granted access to a user.

        $user		= $arg{'record'}->[5];
        $domain		= $arg{'record'}->[7];
        $loginID	= $arg{'record'}->[53];
        $loginType	= $radius{$arg{'record'}->[49]} || 255,
        $srcAddr	= $arg{'record'}->[22];
        $loginState = '0';
    }

    if ($arg{'record'}->[0] eq '6273') {
        # Bug 18445 (Radius)
        # Network Policy Server denied access to a user.

        $user		= $arg{'record'}->[6];
        $domain		= $arg{'record'}->[8];
        $loginID	= $arg{'record'}->[54];
        $loginType	= $radius{$arg{'record'}->[50]} || 255,
        $srcAddr	= $arg{'record'}->[23];
        $loginState = 3;
    }

    if ($arg{'record'}->[0] eq '6274') {
        # Bug 18445 (Radius)
        # Network Policy Server discarded the request for a user.

        $user		= $arg{'record'}->[6];
        $domain		= $arg{'record'}->[8];
        $loginID	= $arg{'record'}->[54];
        $loginType	= $radius{$arg{'record'}->[50]} || 255,
        $srcAddr	= $arg{'record'}->[23];
        $loginState = 4;
    }

    if ($arg{'record'}->[0] eq '6278') {
        # Bug 18445 (Radius)
        # Network Policy Server granted full access to a user
        # because the host met the defined health policy.

        $user		= $arg{'record'}->[5];
        $domain		= $arg{'record'}->[7];
        $loginID	= $arg{'record'}->[53];
        $loginType	= $radius{$arg{'record'}->[49]} || 255,
        $srcAddr	= $arg{'record'}->[22];
        $loginState = 1;
    }

    if ($user !~ m/\$/) {
        if (&ipfixify::parse::v_ip($srcAddr)) {
            $flowIt = 26;
        } elsif (&ipfixify::parse::v_mac($srcAddr)) {
            $srcAddr = join( '', split( /:|-/, $srcAddr ) );
            $flowIt = 27;
        }
    }

    if ($flowIt) {
        my ($username);

        if ($user && $domain) {
            $username = "$domain\\$user";
        } elsif ($user) {
            $username = $user;
        } elsif ($domain) {
            $username = $domain;
        } else {
            $username = '';
        }

        if ($loginID =~ m/\(/i) {
            (undef, $loginID) = split (/\,/, $loginID);
            $loginID =~ s/\)//i;
        }

        $userFlow = join
          (
           ':-:',
           $arg{'machineID'},
           encode('UTF-8', decode('UTF-8', lc($username), Encode::FB_DEFAULT|Encode::LEAVE_SRC)),
           $srcAddr,
           scalar time(),
           $loginState,
           $loginType,
           encode('UTF-8', decode('UTF-8', lc($loginID), Encode::FB_DEFAULT|Encode::LEAVE_SRC)),
           1
        );

        return ($username, $userFlow, $flowIt);
    }

    return undef;
}

#####################################################################

=pod

=head2 v_ip

Determines if the argument passed is an IP address

=over 2

    $ip = &ipfixify::parse::v_ip($ip);

=back

The currently supported parameters are:

=over 2

=item * $ip

The IP Address to test.

=back

Returns the IP if pass, nothing if failed.

=cut

sub v_ip {
    return undef unless $_[0];
    return (inet_b2a(inet_a2b($_[0]))//'') eq $_[0];
}

#####################################################################

=pod

=head2 v_mac

Determines if the argument passed is a MAC Address

=over 2

    $mac = &ipfixify::parse::v_mac($mac);

=back

The currently supported parameters are:

=over 2

=item * $mac

The MAC Address to test.

=back

Returns the MAC if pass, nothing if failed.

=cut

sub v_mac {
    return undef unless $_[0];

    if ($_[0] =~ /([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/) {
        return $_[0];
    } else {
        return undef;
    }
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
