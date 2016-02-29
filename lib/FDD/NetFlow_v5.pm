package FDD::NetFlow_v5;

use strict;
use warnings;
use version 0.77;          # get latest bug-fixes and API

use base ('FDI');


use Data::Dumper;
use Carp;
our @CARP_NOT = ('FDI');

use version (); our $VERSION = 'v0.0.4';

# Module implementation here
use Time::HiRes qw(gettimeofday tv_interval);

use FDI::InformationModel;
use FDI::Template;


use constant NETFLOW_V5_RAW_IP => '
		sourceIPv4Address(8)<ipv4Address>{identifier}
		destinationIPv4Address(12)<ipv4Address>{identifier}
		ipNextHopIPv4Address(15)<ipv4Address>{identifier}
		ingressInterface(10)<unsigned32>[2]{identifier}
		egressInterface(14)<unsigned32>[2]{identifier}
		packetDeltaCount(2)<unsigned64>[4]{deltaCounter}
		octetDeltaCount(1)<unsigned64>[4]{deltaCounter}
		flowStartSysUpTime(22)<unsigned32>
		flowEndSysUpTime(21)<unsigned32>
		sourceTransportPort(7)<unsigned16>{identifier}
		destinationTransportPort(11)<unsigned16>{identifier}
		paddingOctets(210)<octetArray>[1]{discard}
		tcpControlBits(6)<unsigned8>[1]{flags}
		protocolIdentifier(4)<unsigned8>{identifier}
		ipClassOfService(5)<unsigned8>{identifier}
		bgpSourceAsNumber(16)<unsigned32>[2]{identifier}
		bgpDestinationAsNumber(17)<unsigned32>[2]{identifier}
		sourceIPv4PrefixLength(9)<unsigned8>
		destinationIPv4PrefixLength(13)<unsigned8>
		paddingOctets(210)<octetArray>[2]{discard}
		';

use constant NETFLOW_V5_FMT_IP => '
		sourceIPv4Address(8)<ipv4Address>{identifier xform:a2b}
		destinationIPv4Address(12)<ipv4Address>{identifier xform:a2b}
		ipNextHopIPv4Address(15)<ipv4Address>{identifier xform:a2b}
		ingressInterface(10)<unsigned32>[2]{identifier}
		egressInterface(14)<unsigned32>[2]{identifier}
		packetDeltaCount(2)<unsigned64>[4]{deltaCounter}
		octetDeltaCount(1)<unsigned64>[4]{deltaCounter}
		flowStartSysUpTime(22)<unsigned32>
		flowEndSysUpTime(21)<unsigned32>
		sourceTransportPort(7)<unsigned16>{identifier}
		destinationTransportPort(11)<unsigned16>{identifier}
		paddingOctets(210)<octetArray>[1]{discard}
		tcpControlBits(6)<unsigned8>[1]{flags}
		protocolIdentifier(4)<unsigned8>{identifier}
		ipClassOfService(5)<unsigned8>{identifier}
		bgpSourceAsNumber(16)<unsigned32>[2]{identifier}
		bgpDestinationAsNumber(17)<unsigned32>[2]{identifier}
		sourceIPv4PrefixLength(9)<unsigned8>
		destinationIPv4PrefixLength(13)<unsigned8>
		paddingOctets(210)<octetArray>[2]{discard}
		';

=pod

=head2 driver

Initialize this driver

=cut

sub driver {
	my ( $class, $attr ) = @_;
	my $drh = bless {}, $class;

	my $fdh = $drh;

	my $header = FDI::Template->new();
	for my $spec_str (
		'version(-5/1)<unsigned16>{identifier}',
		'deltaFlowCount(-5/2)<unsigned16>{deltaCounter}',
		'exporterSysUpTime(-5/3)<unsigned32>{default}',
		'exportTimeSeconds(-5/4)<dateTimeSeconds>{quantity}',
		'exportTimeResidualNanoseconds(-5/5)<unsigned32>{quantity}',
		'flowSequenceNumber(-5/6)<unsigned32>{identifier}',
		'engineType(-5/7)<unsigned8>{identifier}',
		'engineIdentifier(-5/8)<unsigned8>{identifier}',
		'paddingOctets(210)<octetArray>[2]{discard}'
		) {
		#warn "addInformationElement (header): ", $spec_str, "\n";
		my $ie = FDI::InformationElement->for_spec($spec_str);

		#warn Dumper ($ie);

		$header->addInformationElement($ie);
	}

	$fdh->{header} = $header;

	#fdh->{flow_seq}     = 0;

	#fdh->{template}         = $template;
	#fdh->{v5_template_hash} = $template->getTemplateHash();
	#fdh->addTemplate($template);
	$fdh->{starttime} = [gettimeofday];

	#fdh->{flow_val_cnt} = $template->getElementCount;
	$fdh->{flow_seq} = 0;

	return $drh;
}

=pod

=head2 addFlow

TODO: Change this name
Push a complete flow to send later.
Override our super class to hide the template hash.

=cut

sub addFlow {
	my $drh = shift;
	my $fdh = $drh;
	$drh->SUPER::addFlow( $fdh->{v5_template_hash}, @_ );
}


# header offsets
use constant {
	version      => 0,
	flow_count   => 1,
	sysUpTime    => 2,
	timestamp    => 3,
	nanoseconds  => 4,
	flowSequence => 5,
	engineType   => 6,
	engineId     => 7,
	padding      => 8,
};

=pod

=head2 encodeData

put our data on the wire

=cut

sub encodeData {
	my ($drh, %arg) = @_;

	my $fdh = $drh;
	warn Dumper($fdh) unless $fdh->{header};
	my $headerLength = $fdh->{header}->getLength();

	#warn Dumper ($fdh->{header});
	#die "headerLength: $headerLength";

	for my $v5_template_hash ( keys %{ $fdh->{template_hashes} } ) {
		my $template = $fdh->{$v5_template_hash}{template};
		$fdh->{flow_val_cnt} = $template->getElementCount;

		#warn "flow_val_cnt: $fdh->{flow_val_cnt}\n";

		my $flowLength = $template->getLength();
		my @headerValues;
		@headerValues[ version, nanoseconds, engineType, engineId ]
			= ( 5, 0, 0, 0 );

		my $max_flows
			= int( ( $fdh->{max_pack_len} - $headerLength ) / $flowLength );

		my $data        = $template->{data};
	ENCODE_PKT:
		while ( my $flows = int( scalar @{$data} / $fdh->{flow_val_cnt} ) ) {
			if ( $flows >= $max_flows ) {
				$flows = $max_flows;
			} else {
				last ENCODE_PKT unless $fdh->{send_partial};
			}

			@headerValues[ flow_count, sysUpTime, timestamp, flowSequence ]
				= (
				$flows,
				($arg{uptime} // int( tv_interval( $fdh->{starttime} ) * 1000 )),
				($arg{now} // time()), $fdh->{flow_seq}
				);

			#warn Dumper(\@headerValues);
			$fdh->{header}->addFlow( \@headerValues );
			my $pdu = $fdh->{header}->encodeData(1);
			$pdu .= $template->encodeData($flows);

			push @{ $fdh->{pdus} }, $pdu;

	   #warn "encoded $flows flows ($fdh->{flow_seq}) : ", length($pdu), "\n";

			$fdh->{flow_seq} += $flows;    # increment next flow_seq
		}
	}
}


1;    # Magic true value required at end of module
__END__

=head1 NAME

FDD::NetFlow_v5 - [One line description of module's purpose here]


=head1 VERSION

This document describes FDD::NetFlow_v5 version 0.0.4


=head1 SYNOPSIS

    use FDD::NetFlow_v5;

=for author to fill in:
    Brief code example(s) here showing commonest usage(s).
    This section will be as far as many users bother reading
    so make it as educational and exeplary as possible.


=head1 DESCRIPTION

=for author to fill in:
    Write a full description of the module and its features here.
    Use subsections (=head2, =head3) as appropriate.


=head1 INTERFACE

=for author to fill in:
    Write a separate section listing the public components of the modules
    interface. These normally consist of either subroutines that may be
    exported, or methods that may be called on objects belonging to the
    classes provided by the module.


=head1 DIAGNOSTICS

=for author to fill in:
    List every single error and warning message that the module can
    generate (even the ones that will "never happen"), with a full
    explanation of each problem, one or more likely causes, and any
    suggested remedies.

=over

=item C<< Error message here, perhaps with %s placeholders >>

[Description of error here]

=item C<< Another error message here >>

[Description of error here]

[Et cetera, et cetera]

=back


=head1 CONFIGURATION AND ENVIRONMENT

=for author to fill in:
    A full explanation of any configuration system(s) used by the
    module, including the names and locations of any configuration
    files, and the meaning of any environment variables or properties
    that can be set. These descriptions must also include details of any
    configuration language used.

FDD::NetFlow_v5 requires no configuration files or environment variables.


=head1 DEPENDENCIES

=for author to fill in:
    A list of all the other modules that this module relies upon,
    including any restrictions on versions, and an indication whether
    the module is part of the standard Perl distribution, part of the
    module's distribution, or must be installed separately. ]

None.


=head1 INCOMPATIBILITIES

=for author to fill in:
    A list of any modules that this module cannot be used in conjunction
    with. This may be due to name conflicts in the interface, or
    competition for system or program resources, or due to internal
    limitations of Perl (for example, many modules that use source code
    filters are mutually incompatible).

None reported.


=head1 BUGS AND LIMITATIONS

=for author to fill in:
    A list of known problems with the module, together with some
    indication Whether they are likely to be fixed in an upcoming
    release. Also a list of restrictions on the features the module
    does provide: data types that cannot be handled, performance issues
    and the circumstances in which they may arise, practical
    limitations on the size of data sets, special cases that are not
    (yet) handled, etc.

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-net-flow-v5@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Andrew Feren  C<< <acferen@gmail.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2013, Andrew Feren C<< <acferen@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

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
