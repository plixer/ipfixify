package FDI::Template;

use warnings;
use strict;
use version 0.77;          # get latest bug-fixes and API

use Data::Dumper;
use Carp;
our @CARP_NOT = ('FDI');

use version (); our $VERSION = 'v0.0.4';

use Digest::MD5 qw(md5_hex);
use JSON qw (encode_json);

use constant VALIDATE_DATA => 1;

# Module implementation here

=pod

=head2 new

	 Create a new template

=cut

sub new {
	my ( $class, %args ) = @_;

	my $elements = [];
	my $self     = bless {

		# manufactured_elements => [],      # needed here?
		elements             => [],
		data                 => [],
		template_hash_id     => undef,
		template_description => undef,
		packlen              => undef,    # set later

	}, $class;

	if ( ref $args{elements} eq 'ARRAY' ) {
		$self->addInformationElement( @{ $args{elements} } );
	}

	return $self;
}


=pod

=head2 encodeData

	 Put this data in on the wire format

=cut

sub encodeData {
	my ( $self, $cur_flows ) = @_;

	my $packstr = $self->{packstr};
	if ( $cur_flows > 1 ) {
		$packstr = "($packstr)$cur_flows";

		#warn "$packstr\n"
	}

	my @data = splice( @{ $self->{data} }, 0,
		$cur_flows * $self->getElementCount );
	return unless @data;

	my $ret = pack( $packstr, @data ) or die "pack error: $packstr";
	return $ret;
}

=pod

=head2 validFlow

	 Is this flow valid for some value(s) of valid.  Currently does it
	 have the correct number of elements

=cut

sub validFlow {
	my ( $self, $data ) = ( shift, shift );
	croak "No elements in template" unless @{ $self->{elements} };

	# This could/should be WAY smarter
	return !( @$data % $self->{element_cnt} );
}

=pod

=head2 addFlow

	 Is this flow valid for some value(s) of valid.  Currently does it
	 have the correct number of elements

=cut

sub addFlow {
	my ( $self, $data ) = ( shift, shift );
	croak "No elements in template" unless @{ $self->{elements} };
	my $expected = $self->{element_cnt};
	my $received = @$data;
	if ( $received % $expected ) {

		#warn Dumper( $self->{elements} );
		croak "Wrong element count($received) in flow expecting $expected";
	}
	my $data_end = @{ $self->{data} };    # AKA $new_data_start
	push @{ $self->{data} }, @$data;

	if ( ref $self->{pre_xforms} ) {
		my $elem_cnt = $self->getElementCount;
	XFORM:
		for my $i ( 0 .. ( $elem_cnt - 1 ) ) {
			my $pre_xform = $self->{pre_xforms}[$i];
			next XFORM unless $pre_xform;

			my $dataType = $self->{elements}[$i]->{dataType};
			unless ( defined $dataType ) {
				warn "$i : ", Dumper( $self->{elements} );
				croak "no dataType";
			}

			for (
				my $offset = $i + $data_end;
				$offset < @{ $self->{data} };
				$offset += $elem_cnt
				) {

				my $in_offset = $offset - $data_end;

				my $section = 'none';
				if ( $pre_xform eq 'a2b' ) {
					$section = 'a2b';

					if ( $dataType =~ /^ipv[46]Address$/ ) {
						$self->{data}->[$offset] = inet_a2b( $data->[$in_offset] );
					} elsif ( $dataType =~ /^octetArray$/ ) {
						$self->{data}->[$offset] = pack( 'H*', $data->[$in_offset] );
					} else {
						croak "Invalid dataType($dataType) for transform $pre_xform"
							unless ( $dataType =~ /ipv[46]Address/ );
					}
				} elsif ( $pre_xform eq 'a2b_na' ) {
					$section = 'a2b_na';
					if ( $data->[$in_offset] eq '' ) {
						if ( $dataType eq 'ipv6Address' ) {
							$self->{data}->[$offset] = "\0" x 16;
						} elsif ( $dataType eq 'ipv4Address' ) {
							$self->{data}->[$offset] = "\0" x 4;
						} elsif ( $dataType =~ /^octetArray$/ ) {

							# no change
						} else {
							croak
								"Invalid dataType($dataType) for transform $pre_xform";
						}
					} else {
						if ( $dataType =~ /^ipv[46]Address$/ ) {
							$self->{data}->[$offset]
								= inet_a2b( $data->[$in_offset] );
						} elsif ( $dataType =~ /^octetArray$/ ) {
							$self->{data}->[$offset]
								= pack( 'H*', $data->[$in_offset] );
						} else {
							croak
								"Invalid dataType($dataType) for transform $pre_xform";
						}
					}
				}

				elsif ( $pre_xform eq 'a2b6' ) {
					$section = 'a2b6';
					croak
						"Invalid dataType($dataType) for transform $pre_xform"
						unless ( $dataType =~ /ipv[46]Address/ );

					my $ip_bin = $self->{data}->[$offset] = inet_a2b($data->[$in_offset]);
					use bytes;  # for octet length()
					if (length($ip_bin) == 4) {
						# IPv4 just has a constant prefix in IPv6.
						$self->{data}->[$offset] =~ s/^/\0\0\0\0\0\0\0\0\0\0\xff\xff/;
					}
				}
				unless ( defined $self->{data}->[$offset] ) {
					my $in_data = $data->[$in_offset] // 'undef';
					my $len = length($in_data);
					my $hex = unpack('H*', $in_data);
					croak
						"Invalid data($in_data/$len/$hex) @ $offset for transform $pre_xform tried xform:$section";
				}
			}
		}
	}
	if (VALIDATE_DATA) {
		use Scalar::Util::Numeric qw(isnum isint isfloat);

		my $elem_cnt = $self->getElementCount;
		for my $i ( 0 .. ( $elem_cnt - 1 ) ) {
			my ( $dataType, $pen, $ie, $name, $length )
				= @{ $self->{elements}[$i] }
				{qw{dataType enterpriseId elementId name length}};

			for (
				my $offset = $i + $data_end;
				$offset < @{ $self->{data} };
				$offset += $elem_cnt
				) {
				my $dataVal = $self->{data}->[$offset];
				unless ( defined($dataVal) ) {
					croak(
						"Invalid data(undef) for $name($pen/$ie)<$dataType>");
				}

				for ($dataType) {
					if (/^ipv[46]Address$/) {
						if ( $length != length($dataVal) ) {
							croak(
								'Invalid length(',
								inet_b2a($dataVal),
								'/',
								length($dataVal),
								") for $name($pen/$ie)<$dataType>[$length]"
							);
						}
					}
					elsif (/^unsigned/) {
						if ( $^O eq 'MSWin32' ) {
							unless ( $dataVal =~ /^\d+$/ ) {
								croak(
									"Invalid data($dataVal) for $name($pen/$ie)<$dataType>"
								);
							}

						} else {
							unless ( isint($dataVal) > 0 ) {
								croak(
									"Invalid data($dataVal) for $name($pen/$ie)<$dataType>"
								);
							}
						}
					}
					elsif (/^signed/) {
						if ( $^O eq 'MSWin32' ) {
							unless ( $dataVal =~ /^-?\d+$/ ) {
								croak(
									"Invalid data($dataVal) for $name($pen/$ie)<$dataType>"
								);
							}

						} else {
							unless ( isint($dataVal) ) {
								croak(
									"Invalid data($dataVal) for $name($pen/$ie)<$dataType>"
								);
							}
						}
					}
					elsif (/^float/) {
						unless ( isfloat($dataVal) ) {
							croak(
								"Invalid data($dataVal) for $name($pen/$ie)<$dataType>"
							);
						}
					}
				}
			}
		}
	}


	# return the number of flows
	return ( @{ $self->{data} } / $self->{element_cnt} );

	### return the number of flows added
	##return (  @$data / $self->{element_cnt} );
}

=pod

=head2 getElements

	 Return the Informationelements in this template as an ordered list.

=cut

sub getElements {
	return @{ $_[0]->{elements} };
}

=pod

=head2 getElementCount

	 Return the number of Informationelements in this template.  If
   there is padding this may return a smaller number than (scalar
   getElements).

=cut

sub getElementCount {
	return $_[0]->{element_cnt};
}

=pod

=head2 getTemplateHash

Get a unique id for this template.

=cut

sub getTemplateHash {
	return $_[0]->{template_hash_id};
}

=pod

=head2 addInformationElement

 TODO: make an alias named -- addInformationElements

 Appends InformationElements to the template.
 Expects a list of FDI::InformationElement

=cut

sub addInformationElement {
	my $self = shift;

	$self->{junk_cnt} //= 0;
	for my $element (@_) {
		$self->{junk_cnt}++ if $element->{dataType} eq 'junk';

		push @{ $self->{elements} }, $element;
		if ( $element->{pre_xform} ) {
			$self->{pre_xforms} //= [];
			@{ $self->{pre_xforms} }[ $#{ $self->{elements} } ]
				= $element->{pre_xform};
		}
		if ( $element->{post_xform} ) {
			$self->{post_xforms} //= [];
			@{ $self->{post_xforms} }[ $#{ $self->{elements} } ]
				= $element->{post_xforms};
		}
	}
	$self->{packstr} .= join( '', map { $_->getPackStr } @_ );

	my $packstr = $self->{packstr} . '.';

	$packstr =~ s/z/C/g;             # TODO: Fix varlen elements
	$packstr =~ s/[eE]3/N/g;         # TODO: Fix reduced length encoding
	$packstr =~ s/x2?[eE]6/a8/g;     # TODO: Fix reduced length encoding
	$packstr =~ s/[eE][5-7]/a8/g;    # TODO: Fix reduced length encoding

	my @unpacked_vals;
	@unpacked_vals = unpack( $packstr, "\0" x 5000 )
		or die "unpack error: $packstr";
	$self->{packlen}     = pop @unpacked_vals;          # remove final offset
	$self->{element_cnt} = ( scalar @unpacked_vals );

# warn "$self->{element_cnt} == " . @{ $self->{elements} } . "- $self->{junk_cnt}\n";
	croak "Bad element count"
		unless $self->{element_cnt}
		== ( @{ $self->{elements} } - $self->{junk_cnt} );

	#warn ("$self->{packstr}\n");
	#warn ("bytes/$self->{packlen} : elements/$self->{element_cnt}\n");

	$self->{description} = encode_json(
		[ map { $_->getUniquenessHash } @{ $self->{elements} } ] );
	$self->{template_hash_id} = md5_hex( $self->{description} );
}


=pod

=head2 getLength

  This returns the minimum expected packed length of a flow.  If there
  is variable length data in the template this number may be much
  lower than reality.

=cut

sub getLength {
	return $_[0]->{packlen};
}


=pod

=head2 inet_a2b

Convert a human readable (ascii) IP address (v4 or v6) to a packed
(binary) format.  The binary format follows the ASCII input's lead:
four octets for IPv4, and 16 for IPv6.

=cut

use Socket qw(:DEFAULT AF_INET);
BEGIN {
	my @imports = (qw(AF_INET6));
	my @socket6_imports;

	# This might be overkill, but I'm not certain that all these imports
	# were added to Socket at the same time.
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
		Socket::inet_ntop( AF_INET, "\0\0\0\0" );    # test
		Socket->import('inet_ntop');    # import if the test doesn't die
	};
	if ($@) {
		push @socket6_imports, 'inet_ntop';
	}
	eval {
		# Test to see if the sub works.
		# Socket::inet_pton() may exist, but die with:
		# Socket::inet_pton not implemented on this architecture
		Socket::inet_pton( AF_INET, '0.0.0.0' );    # test
		Socket->import('inet_pton');    # import if the test doesn't die
	};
	if ($@) {

		# *sigh* the Socket6 version of inet_pton doesn't always behave like
		# the version in Socket.
		{
			no warnings 'redefine';
			no strict 'refs';
			*{ __PACKAGE__ . "::inet_pton" } = sub {
				if ( $_[0] == AF_INET ) {
					return Socket::inet_aton( $_[1] );
				} else {
					return Socket6::inet_pton(@_);
				}
			};
		}
	}

	if (@socket6_imports) {
		eval { require Socket6 };
		die $@ if $@;
		Socket6->import(@socket6_imports);
	}
}

=method inet_a2b

Convert a human readable (ascii) IP address (v4 or v6) to a packed
(binary) format.

=cut

sub inet_a2b {

	# TODO return vs return undef;  This was return undef, but Perl Critic
	# complained.
  (carp "undefined address" && return $_[0]) unless defined $_[0];

  # Bug 10409 and Bug 11845
  # Socket::aton (which we used to rely on here) does some odd things with
  # empty strings.  As near as I can tell it resolves them to the
  # local IP.  Using inet_pton resolves this issue.
  my $IP_bin;
  eval {
    use bytes;
    $IP_bin = inet_pton(AF_INET,$_[0]) || inet_pton(AF_INET6,$_[0]);
  };
  if ($@) {
    carp "inet_a2b : $_[0] ($@)";
  }
  return $IP_bin;
}


=method inet_b2a

Convert a packed (binary) IP address (v4 or v6) to a human readable
(ascii) format.

=cut

sub inet_b2a {

	# TODO return vs return undef;  This was return undef, but Perl Critic
	# complained.
  (carp "undefined address" && return $_[0]) unless defined $_[0];
  (carp "bad address length" && return undef) if (length($_[0]) != 4
                                                  && length($_[0]) != 16);

  my $IP_ascii;
  eval {
    use bytes;
    $IP_ascii = ( length($_[0]) == 4
                  ? inet_ntop(AF_INET,$_[0])
                  : inet_ntop(AF_INET6,$_[0]) );
  };
  if ($@) {
    carp "inet_b2a : $_[0] ($@)";
  }

  # IPv6 addresses can contain IPv4.
  $IP_ascii =~ s/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/$1/;

  return $IP_ascii;
}

1;    # Magic true value required at end of module
__END__

=head1 NAME

FDI::Template - [One line description of module's purpose here]


=head1 VERSION

This document describes FDI::Template version 0.0.4


=head1 SYNOPSIS

    use FDI::Template;

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

FDI::Template requires no configuration files or environment variables.


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
C<bug-net-flow-template@rt.cpan.org>, or through the web interface at
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
