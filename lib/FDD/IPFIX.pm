package FDD::IPFIX;

use strict;
use warnings;

use base ('FDI');

use version 0.77;          # get latest bug-fixes and API

use Net::Flow;             # our backend for now

use Data::Dumper;
use Carp;
our @CARP_NOT = ('FDI');

use Digest::CRC qw(crc16);

use version (); our $VERSION = 'v0.0.4';

# Module implementation here
use Time::HiRes qw(gettimeofday tv_interval);

use FDI::InformationModel;
use FDI::Template;

use constant flow_ver => 10;

use constant DEBUG => $ENV{FDI_DEBUG};

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
		qw'
		version(-10/1)<unsigned16>{identifier}
		messageLength(-10/2)<unsigned16>{deltaCounter}
		exportTimeSeconds(-10/4)<dateTimeSeconds>{quantity}
		flowSequenceNumber(-10/6)<unsigned32>{identifier}
		observationDomainId(149)<unsigned32>{identifier}
		'
		) {
		#warn "addInformationElement (header): ", $spec_str, "\n";

		my $ie = FDI::InformationElement->for_spec($spec_str);

		$header->addInformationElement($ie);
	}

	$fdh->{header} = $header;

	#fdh->{flow_seq}     = 0;

	#fdh->{$template_hash}{data} = [flowdata]
	#fdh->{$template_hash}{template} = $template;
	#fdh->{$template_hash}{template_id} = next_template_id
	#fdh->{$template_hash}{flow_val_cnt} = <columns/row>

	# if set to an integer (>= 256) will increment for each new
	# template.  Hash ref stores calculated IDs to avoid collisions.
	$fdh->{next_template_id} = {};	# 256


	# state I need to maintain for my backend.
	$fdh->{_netflow} = {
		header => {
			VersionNum         => flow_ver,
			TemplateResendSecs => 300,

			ObservationDomainId => $attr->{ObservationDomainId} // 0,
		  SourceId            => $attr->{SourceId} // 0,
		  SequenceNum         => $attr->{SequenceNum} // 0,
		  SysUpTime           => $attr->{SysUpTime} // 0,
		  # UnixSecs not time() unless we plan to set it every time.
		  UnixSecs            => $attr->{UnixSecs} // 0,
		}
	};

	return $drh;
}

=pod

=head2 addTemplate

Add a template.

=cut

sub addTemplate {
	my ( $drh, $template ) = @_;
	$drh->SUPER::addTemplate( $template, @_ );

	my $fdh = $drh;

	my $template_hash = $template->getTemplateHash();

	return if ( exists $fdh->{$template_hash}{template_id} );

	my $template_id;
	if ( ref $fdh->{next_template_id} eq 'HASH' ) {

		# Attempt to create a template_id tied to the IEs in each template.
		#
		# If exporting using UDP with processes that may come and go it is
		# possible for two processes to get the same connection tuple and
		# assign the same template ID to different templates.  This should
		# still mostly work, but there are race conditions and possibly
		# lost packets that can cause problems in the collector.
		# See RFC7011 sections 8 and 10.3 for more details

		$template_id = crc16($template_hash);
		if ( $template_id < 256 ) {
			$template_id = 256;    # We have to pick something.
		}
		while ( exists $fdh->{next_template_id}{$template_id} ) {
			last if $fdh->{next_template_id}{$template_id} eq $template_hash;

			# increment until we don't collide in our process
			$template_id++;

			# I suppose there could be an infinite loop here, but if you
			# have that many templates you will almost certainly hit other
			# limitations first.
			if ($template_id > 0xFFFF) {
				$template_id = 256;
			}
		}
		$fdh->{next_template_id}{$template_id} = $template_hash;
		$fdh->{$template_hash}{template_id} = $template_id;
		#warn "$template_id => $fdh->{next_template_id}{$template_id}";

	} else {
		$template_id = $fdh->{$template_hash}{template_id}
			= $fdh->{next_template_id}++;
	}

	#
	# Now for some Net::Flow specific code
	#
	my $setId = 2;    # Default to data template


	my %nf_template = (
		SetId      => $setId,
		TemplateId => $template_id,
		Template   => [],
	);
	for my $element ( $template->getElements() ) {
		my $elementId = join( '.', @{$element}{qw{enterpriseId elementId}} );
		$elementId =~ s/^IANA\.//;

		if ( $element->{isScope} ) {
			$setId = 3;
			$nf_template{SetId} = $setId;
			$nf_template{ScopeCount}++;
		} else {
			$nf_template{FieldCount}++;
		}


		push @{ $nf_template{Template} },
			{
			Length => $element->{length},
			Id     => $elementId,
			};
	}
	$fdh->{_netflow}->{$template_hash}{template} = \%nf_template;
}


=pod

=head2 encodeData

put our data on the wire

=cut

sub encodeData {
	my ($drh, %arg) = @_;
	my $fdh = $drh;

	#warn "encoding IPFIX\n";

	my @flows;
	my @nf_templates;
	for my $template_hash ( keys %{ $fdh->{template_hashes} } ) {
		my $t_details = $fdh->{$template_hash};
		my $template  = $t_details->{template};
		my $dataref   = delete $template->{data};
		$template->{data} = [];

		push @nf_templates, $fdh->{_netflow}->{$template_hash}{template};

		while (@$dataref) {
			my %row = ( SetId => $t_details->{template_id} );
			for my $element ( $template->getElements() ) {
				my $val = shift @$dataref;
				my $elementId
					= join( '.', @{$element}{qw{enterpriseId elementId}} );
				$elementId =~ s/^IANA\.//;

				my $packstr = $element->getPackStr;

				if ( $element->{dataType} =~ /octetArray|string/ ) {
					$row{$elementId} = $val;
				} else {
					eval {
						local $SIG{__WARN__} = sub {
							Carp::carp( "val = $val\n" .Dumper($element) . ": $_[0]" );
							}
							if DEBUG;
						$row{$elementId} = pack( $packstr, $val );
					};
					if ($@) {

				  # Kludge for 64bit numbers on 32bit (mostly windows) systems
						if (   $@ =~ /Invalid type 'E'/
							&& $element->{dataType} eq 'unsigned64' ) {
							require Math::BigInt;
							my ( $i, $int1, $int2 );
							$i = new Math::BigInt($val);
							( $int1, $int2 ) = do {
								(   int( $i / 2**32 ) % 2**32,
									int( $i % 2**32 )
								);
							};
							local $SIG{__WARN__} = sub {
								Carp::carp( Dumper($element) . ": $_[0]" );
								}
								if DEBUG;
							$row{$elementId} = pack( 'N2', $int1, $int2 );
						} elsif ( $@ =~ /Invalid type 'e'/
							&& $element->{dataType} eq 'signed64' ) {
							require Math::BigInt;
							my ( $i, $int1, $int2 );
							$i = new Math::BigInt($val);
							( $int1, $int2 ) = do {
								if ( $i < 0 ) {
									$i = -1 - $i;
									(   ~( int( $i / 2**32 ) % 2**32 ),
										~int( $i % 2**32 )
									);
								} else {
									(   int( $i / 2**32 ) % 2**32,
										int( $i % 2**32 )
									);
								}
							};
							local $SIG{__WARN__} = sub {
								Carp::carp( Dumper($element) . ": $_[0]" );
								}
								if DEBUG;
							$row{$elementId} = pack( 'N2', $int1, $int2 );
						} else {
							warn $@;
						}
					}
				}
			}
			push @flows, \%row;
		}
	}

	my $header = $fdh->{_netflow}{header};
	$header->{UnixSecs} = $arg{now} // time();
	$header->{SysUpTime} = $arg{uptime} // ((time() - $^T) * 1000);

	#warn Dumper(\@flows);
	my $pdu_refs = [];
	my $ErrorsArrayRef;
	( $fdh->{_netflow}->{header}, $pdu_refs, $ErrorsArrayRef )
		= Net::Flow::encode( $fdh->{_netflow}->{header},
		\@nf_templates, \@flows, $fdh->{max_pack_len}, );

	for (@{$ErrorsArrayRef}) {
		next if !DEBUG && /NO FLOW DATA/;
		Carp::carp $_;
	}

	push @{ $fdh->{pdus} }, map {$$_} @$pdu_refs;
}


1;    # Magic true value required at end of module
__END__

=head1 NAME

FDD::IPFIX - [One line description of module's purpose here]


=head1 VERSION

This document describes FDD::IPFIX version 0.0.4


=head1 SYNOPSIS

    use FDD::IPFIX;

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

FDD::IPFIX requires no configuration files or environment variables.


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
C<bug-net-flow-ipfix@rt.cpan.org>, or through the web interface at
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
