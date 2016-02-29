package FDI::InformationModel;

use warnings;
use strict;
use version 0.77;          # get latest bug-fixes and API

use Data::Dumper;
use Carp;
our @CARP_NOT = ('FDI');

use version (); our $VERSION = 'v0.0.4';

# {pen => { ie => {<details>}}}
%FDI::InformationModel::ie_catalog = ();

# {name_pen => ie}}
%FDI::InformationModel::ie_names = ();

{

	package FDI::DS;       # DataSemantics

	%FDI::DS::aggregation = (
		default     => 1,
		group       => 2,
		min         => 3,
		max         => 4,
		avg         => 5,
		sum         => 6,
		or          => 7,
		and         => 8,
		min_na      => 9,
		max_na      => 10,
		avg_na      => 11,
		sum_na      => 12,
		truncate    => 13,
		default_na  => 14,
		group_na    => 15,
		or_na       => 16,
		and_na      => 17,
		truncate_na => 18,
	);

	%FDI::DS::units = (
		'none'          => 0x00,
		'bits'          => 0x01,
		'octets'        => 0x02,
		'packets'       => 0x03,
		'flows'         => 0x04,
		'seconds'       => 0x05,
		'milliseconds'  => 0x06,
		'microseconds'  => 0x07,
		'nanoseconds'   => 0x08,
		'4-octet words' => 0x09,
		'messages'      => 0x0A,
		'hops'          => 0x0B,
		'entries'       => 0x0C,
	);

	%FDI::DS::names = (
		default      => 0,
		quantity     => 1,
		totalCounter => 2,
		deltaCounter => 3,
		identifier   => 4,
		flags        => 5,
		list         => 6,
		discard      => -1,    # negative for my creation
	);
}

{

	package FDI::DT;           # DataTypes

	use constant variable_len => 0xFFFF;

	%FDI::DT::default_length = (
		junk                 => variable_len,    # non standard
		octetArray           => variable_len,
		unsigned8            => 1,
		unsigned16           => 2,
		unsigned24           => 3,               # non standard
		unsigned32           => 4,
		unsigned64           => 8,
		unsigned             => 8,
		signed8              => 1,
		signed16             => 2,
		signed32             => 4,
		signed64             => 8,
		signed               => 8,
		float32              => 4,
		float64              => 8,
		float                => 8,
		boolean              => 1,
		macAddress           => 6,
		string               => variable_len,
		dateTimeSeconds      => 4,
		dateTimeMilliseconds => 8,
		dateTimeMicroseconds => 8,
		dateTimeNanoseconds  => 8,
		ipv4Address          => 4,
		ipv6Address          => 16,
		basicList            => variable_len,
		subTemplateList      => variable_len,
		subTemplateMultiList => variable_len,
	);

	%FDI::DT::std_types = (
		octetArray           => 0,
		unsigned8            => 1,
		unsigned16           => 2,
		unsigned32           => 3,
		unsigned64           => 4,
		signed8              => 5,
		signed16             => 6,
		signed32             => 7,
		signed64             => 8,
		float32              => 9,
		float64              => 10,
		boolean              => 11,
		macAddress           => 12,
		string               => 13,
		dateTimeSeconds      => 14,
		dateTimeMilliseconds => 15,
		dateTimeMicroseconds => 16,
		dateTimeNanoseconds  => 17,
		ipv4Address          => 18,
		ipv6Address          => 19
	);

	my $have_quad;

	BEGIN {
		eval { $have_quad = pack( 'Q', 1 ); };
		if ($@) {
			$have_quad = 0;
		}
	}

	my ( $unsigned, $signed );
	my ($float);

	BEGIN {
		# 6.1.3.  float32
		#
		#    The float32 data type MUST be encoded as an IEEE single-precision
		#    32-bit floating point-type, as specified in [IEEE.754.1985].
		#
		# 6.1.4.  float64
		#
		#    The float64 data type MUST be encoded as an IEEE double-precision
		#    64-bit floating point-type, as specified in [IEEE.754.1985].

		# perl doesn't offer IEEE.754.1985 as an option.  However, the
		# reading I have done indicates that on any modern system perl's
		# "native format" should be IEEE.754.1985.  Not having an
		# alternative at the moment I am going to run with "native format"
		#
		# According to the pack documentation
		# "Forcing big- or little-endian byte-order on floating-point values
		# for data exchange can work only if all platforms use the same binary
		# representation such as IEEE floating-point. Even if all platforms
		# are using IEEE, there may still be subtle differences. Being able to
		# use > or < on floating-point values can be useful, but also
		# dangerous if you don't know exactly what you're doing. It is not a
		# general way to portably store floating-point values."
		#
		# We are going to pretend I "know exactly what [I am] doing" and
		# force big endian encoding.

		my ( $float32, $float64 );
		my ( $float32_len, $float64_len ) = ( 0, 0 );
		eval { $float32 = pack( 'f>', unpack( 'f>', "\0" x 8 ) ); };
		if ($@) {
			$float32 = undef;
		} else {
			$float32_len = length($float32);
		}

		eval { $float64 = pack( 'd>', unpack( 'd>', "\0" x 8 ) ); };
		if ($@) {
			$float64 = undef;
		} else {
			$float64_len = length($float64);
		}

		$float = [ 'a%d', (undef) x 8 ];
		$float->[4] = 'f>' if $float32_len == 4;

		# "Reduced sizing can also be used to reduce float64 to float32."
		# RFC 5101 Section 6.2
		$float->[8] = 'd>' if $float64_len == 8;

		if ($have_quad) {
			$unsigned
				= [ 'a%d', 'C', 'n', 'E3', 'N', 'E5', 'E6', 'E7', 'Q>' ];
			$signed
				= [ 'a%d', 'c', 'n!', 'e3', 'N!', 'e5', 'e6', 'e7', 'q>' ];
		} else {
			$unsigned
				= [ 'a%d', 'C', 'n', 'E3', 'N', 'E5', 'E6', 'xE6', 'x2E6' ];
			$signed
				= [ 'a%d', 'c', 'n!', 'e3', 'N!', 'e5', 'e6', 'xe6', 'x2e6' ];
		}
	}


	%FDI::DT::default_pack = (
		octetArray           => ['a%d'],
		unsigned8            => $unsigned,
		unsigned16           => $unsigned,
		unsigned32           => $unsigned,
		unsigned64           => $unsigned,
		unsigned             => $unsigned,
		signed8              => $signed,
		signed16             => $signed,
		signed32             => $signed,
		signed64             => $signed,
		signed               => $signed,
		float32              => $float,
		float64              => $float,
		float                => $float,
		boolean              => $unsigned,
		macAddress           => [ 'a%d', (undef) x 5, 'a6' ],
		string               => ['Z%d'],
		dateTimeSeconds      => $unsigned,
		dateTimeMilliseconds => [ 'a%d', (undef) x 7, 'a8' ],
		dateTimeMicroseconds => [ 'a%d', (undef) x 7, 'a8' ],
		dateTimeNanoseconds  => [ 'a%d', (undef) x 7, 'a8' ],
		ipv4Address          => [ 'a%d', (undef) x 3, 'a4' ],
		ipv6Address          => [ 'a%d', (undef) x 15, 'a16' ],
		basicList            => ['a%d'],
		subTemplateList      => ['a%d'],
		subTemplateMultiList => ['a%d'],
		junk                 => ['x%d'],
	);
}


{

	package FDI::InformationElement;

	use Data::Dumper;
	use Carp;

=pod

=head2 for_spec

TODO: is from_spec better?
create an Informationelement for a given spec.

=cut

	sub for_spec {
		my $class = shift;
		my $spec  = shift;

		my $ie_details = parse_spec($spec);

		# enterpriseId,
		# elementId,
		# name,
		# length,
		# dataTypeSemantics
		# dataType
		# isScope
		# pre_xform
		# post_xform
		#	};

		return bless $ie_details, $class;
	}

=pod

=head2 isVariableLen

is this IE currently variable length

=cut

	sub isVariableLen { return $_[0]->{length} == FDI::DT::variable_len }

=pod

=head2 getPackStr

If I want to put this on the wire what should I hand to pack?

=cut

	sub getPackStr {
		my $self = shift;

		my $packtypes = $FDI::DT::default_pack{ $self->{dataType} };
		Carp::croak "No pack information for $self->{dataType}"
			unless ref $packtypes eq 'ARRAY';

		my $packtype;
		my $packtype_idx = $self->{length};
		$packtype_idx = 0 if $packtype_idx > $#$packtypes;

		$packtype = $packtypes->[$packtype_idx];

		if ( $packtype =~ /%/ ) {
			if ( $self->isVariableLen ) {

				#warn "var len not fully implemented";
				return 'z/' . ( split( /%/, $packtype, 2 ) )[0];
			} else {
				return sprintf( $packtype, $self->{length} );
			}
		}

		return $packtype;
	}

=pod

=head2 getUnpackStr

If I want to pull this off the wire what should I hand to unpack?

=cut

	sub getUnpackStr {
		my $self = shift;
		return $self->getPackStr;
	}


=pod

=head2 getUniquenessHash

	 return the what makes this IE unique as a hashref

=cut

	sub getUniquenessHash {
		my $self = shift;
		my @uniqueKeys
			= qw{name enterpriseId elementId dataType_id dataTypeSemantics_id length};
		return [ @$self{@uniqueKeys} ];
	}

=pod

=head2 parse_spec

	 parse IE spec string.  See IE doctors for format.

=cut

	sub parse_spec {
		my $spec = shift;

		my $manufactured;

		$spec =~ s/^\s+//g;
		$spec =~ s/#.*//g;
		$spec =~ s/\s+$//g;

		my ( $name, $enterpriseId, $elementId, $type, $length, $details );

		#warn "--$spec--\n";
		unless (
			# TODO: The leading \s* is required, but I have no idea why.
			$spec
			=~ /\s*(?<name>[^<>()\[\]{}]+)?\s*(\(\s*(((?<pen>-?\d+)\s*\/)?\s*(?<ie>\d+))\s*\))?\s*(<\s*(?<type>[^<>]+)\s*>)?\s*(\[(?<len>\d+)\])?\s*(\{\s*(?<details>[^{}]+)\s*\})?/
			) {
			carp "Invalid spec: $spec (parse error)\n";
			return;
		}

		# mauke: gcola: fixed in 5.16
		# mauke: https://rt.perl.org/rt3/Public/Bug/Display.html?id=78266
		# dipsy: [ #78266: Memory leak with named regexp captures ]
		#
		# I left the names in the regexp since they only leak if you
		# reference them.  When we upgrade new perl with this fix we can
		# revert back to this code with the nice readable names.
		( $name, $enterpriseId, $elementId, $type, $length, $details )
			= ( $1, $5, $6, $8, $10, $+{details} );

		warn $spec unless defined $type;

		# Don't require $enterpriseId to be defined.
		unless ( defined $elementId ) {
			carp "Invalid spec (elementId required) : $spec\n";
			return;
		}

		# = ($+{name},$+{pen},$+{ie},$+{type},$+{len},$+{details});
		$enterpriseId //= 'IANA';
		if ( $elementId < 0x8000 && !$enterpriseId ) {
			carp "For Standard elements omit the 'PEN/' : $spec\n";
			$enterpriseId = 'IANA';
		}

		if (0) {
			no warnings 'uninitialized';
			warn
				"( $name, $enterpriseId, $elementId, $type, $length, $details )\n";
		}

		my $units;
		my $aggregation;
		my $semantics;
		my $isScope;
		my $pre_xform;
		my $post_xform;
		my $status;


		#warn "xxxxx : ", Dumper( \%+ );

		if ($details) {

			my @details = ( split( /\s+/, $details ) );
			if ($details) {
				@details = ($details) unless @details;
			}
			for my $detail (@details) {

				$manufactured = 1 if $detail eq 'manufactured';

				#warn "$detail\n";
				$semantics = $detail if ( exists $FDI::DS::names{$detail} );
				$aggregation = $detail
					if ( exists $FDI::DS::aggregation{$detail} );
				$isScope = 1 if ( 'scope' eq $detail );
				my ( $key, $val ) = split( /:/, $detail );
				if ($val) {
					if ( $key =~ /(^(?<direction>pre|post)_)?xform$/ ) {

						# named captures leak...
						#my $direction = $+{direction} // 'both';
						#my $xform = $+{xform};
						my $direction = $2 // 'both';
						my $xform = $val;

						$pre_xform = $xform
							if ( $direction =~ /^(pre|both)$/ );
						$post_xform = $xform
							if ( $direction =~ /^(post|both)$/ );
					} elsif ( $key eq 'agg' ) {
						$aggregation = $val
							if ( exists $FDI::DS::aggregation{$val} );
					} elsif ( $key eq 'units' ) {
						$units = $val if ( exists $FDI::DS::units{$val} );
					} elsif ( $key eq 'status' ) {
						$status = $val;
					}
				}
			}
		}

		$units = 'seconds'      if $type eq 'dateTimeSeconds';
		$units = 'milliseconds' if $type eq 'dateTimeMilliseconds';
		$units = 'microseconds' if $type eq 'dateTimeMicroseconds';
		$units = 'nanoseconds'  if $type eq 'dateTimeNanoseconds';

		$length = 8 if $type eq 'dateTimeMilliseconds';
		$length = 8 if $type eq 'dateTimeMicroseconds';
		$length = 8 if $type eq 'dateTimeNanoseconds';


	 #warn "( $name, $enterpriseId, $elementId, $type, $length, $details )\n";

		if (   'octetArray'           eq $type
			or 'boolean'              eq $type
			or 'macAddress'           eq $type
			or 'string'               eq $type
			or 'dateTimeSeconds'      eq $type
			or 'dateTimeMilliseconds' eq $type
			or 'dateTimeMicroseconds' eq $type
			or 'dateTimeNanoseconds'  eq $type
			## TODO : Put back for v12 (or not) ??
			#or 'ipv4Address'          eq $type
			#or 'ipv6Address'          eq $type
			) {
			$semantics //= 'default';
			$semantics = 'default' unless $semantics eq 'discard';
		}


		# TODO: Good idea to set a default if unspecified?
		$semantics   //= 'default';
		$aggregation //= 'default';
		$units       //= 'none';
		$status      //= 'current';

		$length = FDI::DT::variable_len if $length && $length eq 'v';

		my $ret = {
			dataType          => $type,
			dataTypeSemantics => $semantics,
			elementId         => $elementId,
			enterpriseId      => $enterpriseId,
			name              => $name,
			length            => $length,
			units             => $units,
			aggregation       => $aggregation,
			status            => $status,

		};
		$ret->{isScope}    = $isScope    if $isScope;
		$ret->{pre_xform}  = $pre_xform  if $pre_xform;
		$ret->{post_xform} = $post_xform if $post_xform;

		#warn "xxxxx : ", Dumper( $ret );

		my $ie_cat_details;

		# look up by name only to get ($enterpriseId && $elementId)
		if ( $name && !( defined $enterpriseId && defined $elementId ) ) {

		# $enterpriseId defaults to IANA.  Name lookups for other PENs need to
		# specify the pen in the spec  name(pen/) should work.
			my $ieid
				= $FDI::InformationModel::ie_names{"${name}_$enterpriseId"};
			$elementId //= $ieid;
			$ieid      //= $elementId;
			Carp::croak("name element ID mismatch in spec string: $spec")
				unless $elementId == $ieid;
		}

		# look up by ($enterpriseId && $elementId) is definative
		if ( defined $enterpriseId && defined $elementId ) {
			$ie_cat_details
				= $FDI::InformationModel::ie_catalog{$enterpriseId}
				{$elementId};
			unless ( defined $ie_cat_details ) {
				$ie_cat_details = $ret;
				$FDI::InformationModel::ie_catalog{$enterpriseId}{$elementId}
					= { %$ret, isScope => undef };

				$FDI::InformationModel::ie_names{"${name}_$enterpriseId"}
					= $elementId
					if $name;
			}

			# something failed to return useful information
			unless ( defined $ie_cat_details ) {
				Carp::croak("insufficient details in spec string: $spec");
			}
		}

		# TODO: validate that dataTypeSemantics match
		$ret->{dataTypeSemantics} //= $ie_cat_details->{dataTypeSemantics};

		# TODO: validate that dataTypes match
		$ret->{dataType} //= ( $ie_cat_details->{dataType} // 'octetArray' );
		$ret->{dataType} = 'junk' if $ret->{dataTypeSemantics} eq 'discard';

		$ret->{length} //= ( $ie_cat_details->{length}
				// $FDI::DT::default_length{$type} );

		if ( $ret->{length} > FDI::DT::variable_len ) {
			Carp::carp( "invalid length '$ret->{length}' defaulting to "
					. FDI::DT::variable_len );
			$ret->{length} = FDI::DT::variable_len;
		}
		unless ( $FDI::DT::default_length{ $ret->{dataType} } ) {
			Carp::carp(
				"invalid data type '$ret->{dataType}' defaulting to octetArray"
			);
			$ret->{dataType} = 'octetArray';
		}
		if ( $ret->{elementId} < 0 || $ret->{elementId} > 0xFFFF ) {
			Carp::croak("invalid elementId '$ret->{elementId}'")
				unless $manufactured;
		}

		unless ( $ret->{name} =~ /^\w*$/ ) {    # empty name OK.
			Carp::croak("invalid name '$ret->{name}'");
		}


		#warn Dumper($ret);
		return $ret;
	}

}


1;    # Magic true value required at end of module
__END__

=head1 NAME

FDI::InformationElement - [One line description of module's purpose here]


=head1 VERSION

This document describes FDI::InformationElement version 0.0.4


=head1 SYNOPSIS

    use FDI::InformationElement;

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

FDI::InformationElement requires no configuration files or environment variables.


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
C<bug-net-flow-informationelement@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Andrew Feren  C<< <andrewf@plixer.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2013, Andrew Feren C<< <andrewf@plixer.com> >>. All rights reserved.

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
