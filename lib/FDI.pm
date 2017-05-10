package FDI;

use warnings;
use strict;
use version 0.77;          # get latest bug-fixes and API

use FDI::InformationModel;
use FDI::Template;


use Data::Dumper;
use Carp;
# our @CARP_NOT = ('FDI');

# Handy env var to enable some (limited) debug output
$ENV{FDI_DEBUG}
	= ( $^O eq 'MSWin32' )
	? $ENV{FDI_DEBUG}
	: ( $ENV{FDI_DEBUG} // -e '/tmp/FDI_DEBUG' );

use version (); our $VERSION = 'v0.0.4';

# Module implementation here

%FDI::installed_drh = ();    # maps driver names to installed driver handles

my %net_write_cache = ();  # Interfaces are singletons.
my %socket_cache    = ();  # Sockets are singletons.

=head2 installed_drivers

What drivers are available in this install.

=cut

sub installed_drivers {%FDI::installed_drh}

#sub new {
#	my ( $class, %args ) = @_;
#
#	my $driver;
#	my $proto_imp = $args{protocol};
#
#	my $implementation = "FDD::$proto_imp";
#
#  eval "require $implementation";
#  die $@ if $@;
#
#  $implementation->import;
#
#	my $self = bless {
#		driver       => $driver,
#		header       => undef,
#		templates    => {},
#		data         => {},
#		flow_val_cnt => {},
#		pdus         => [],
#		flow_seq     => 0,
#		max_pack_len => 1500,
#		information_model => {},
#	}, $class;
#
#	$self->_init();
#	return $self;
#}

my %g_fdh_cache;

=head2 connect

Get my FDI ready or use an existing socket if already created.

=cut

sub connect_cached {
	my $class = shift;
	my ( $dsn, $attr ) = my @orig_args = @_;

	# Threads?  Seriously?
	if ( $INC{'threads.pm'} ) {
		my $tid = threads->tid();
		warn "Running thread_id: $tid" if $ENV{FDI_DEBUG};

		# If threads are being used and either not primed at all or primed
		# with a different thread id we need to clear the cache and tag it
		# it with our thread id.  Reusing a cached $fdh works, but causes
		# absolute havoc in the sequence numbering since each thread
		# increments sequence numbers independently.
		unless ( defined $g_fdh_cache{thread_id}
			&& $g_fdh_cache{thread_id} == $tid ) {

			warn "Clearing stale cache from thread_id: $g_fdh_cache{thread_id}"
				if $ENV{FDI_DEBUG} && defined $g_fdh_cache{thread_id};
			warn "Initializing cache for thread_id: $tid"
				if $ENV{FDI_DEBUG};

			%g_fdh_cache     = ( thread_id => $tid );
			%net_write_cache = ();
			%socket_cache    = ();
		}
	}
	my $cache_key = Dumper $attr;

	if ( $ENV{FDI_DEBUG} and !defined $g_fdh_cache{$cache_key} ) {
		warn "FDI cache key: $cache_key (" . (scalar keys %g_fdh_cache) . ")";
	}

	my $fdh = $g_fdh_cache{$cache_key} //= FDI->connect( "FDI:IPFIX:", $attr );

	return $fdh;
}

=head2 connect

TODO: is there a better name than connect?
Get my FDI ready

=cut

sub connect {
	my $class = shift;
	my ( $dsn, $attr ) = my @orig_args = @_;

	$dsn ||= $ENV{FDI_DSN} || 'FDI:IPFIX:';

	my ( $scheme, $driver, $dsn_attr, $dsn_attr_hash, $driver_dsn )
		= $class->parse_dsn($dsn);

	my $drh;
	eval { $drh = $class->install_driver( $driver, $attr ); };
	if ($@) {
		die "Driver error: $@";
	}
	@{$drh}{q{scheme driver dsn_attr dsn_attr_hash driver_dsn}}
		= ( $scheme, $driver, $dsn_attr, $dsn_attr_hash, $driver_dsn );

	# Nominal values.  YMMV, but how will we know?
	my $eth_ip_udp_header_size = 14 + 20 + 8;

	my $fdh = $drh;
	$fdh->{collector_port} ||= 4739;
	$fdh->{max_pack_len}   ||= 1500 - $eth_ip_udp_header_size;

	for my $attr_key ( keys %$attr ) {
		for ($attr_key) {
			if (/^MTU$/) {
				$fdh->{max_pack_len} = $attr->{$attr_key} - $eth_ip_udp_header_size;
			}
			elsif (/^CollectorIp$/) {
				$fdh->{collector_ip} = $attr->{$attr_key};
			}
			elsif (/^CollectorPort$/) {
				$fdh->{collector_port} = $attr->{$attr_key};
			}
			elsif (/^SrcMac$/) {
				$fdh->{src_mac} = $attr->{$attr_key};
			}
			elsif (/^DstMac$/) {
				$fdh->{dst_mac} = $attr->{$attr_key};
			}
			elsif (/^SendPartial$/) {
				$fdh->{send_partial} = $attr->{$attr_key};
			}
			elsif (/^LocalPort$/) {
				$fdh->{local_port} = $attr->{$attr_key};
			}
			elsif (/^ObservationDomainId$/) {
				# Not used at the time it was added.
				# Checking for it avoids the warning below, though.
				$fdh->{observaton_domain_id} = $attr->{$attr_key};
			}
			else {
				warn "Unknown attribute $attr_key\n";
			}
		}
	}

	$drh->_init_output();

	return $drh;
}

sub _init_output {
	my $drh = shift;
	my $fdh = $drh;

	require Digest::CRC;
	Digest::CRC->import('crc16');

	my $localport = $fdh->{local_port};
	unless ($localport) {
		# make an attempt to get a unique, but consistent localport
		my $uniq = $0;							#  . '-' . $fdh->{collector_ip};

		# How far up the stack is far enough?  3 seems nice.
		for (2 .. 4) {							# 0 == _init_output, 1 == connect
			next unless caller($_);
			$uniq .= '-' . join( '-', ( caller($_) )[ 0, 3 ] );
		}

		#warn $uniq, "\n";
		$localport = crc16($uniq);
		$localport += 1024 if $localport <= 1024;
	}

	use IO::Socket::INET qw( AF_INET AF_INET6 );
	my $address_family = ($fdh->{collector_ip} =~ /:/) ? AF_INET6 : AF_INET;

	if ( $fdh->{collector_ip} ) {
		require IO::Socket::INET;
		IO::Socket::INET->import();

		$fdh->{frame} = sub { return shift; };

		if ($fdh->{local_port}) {
			my $send_key = $address_family . " " . $fdh->{local_port};

			if (exists $socket_cache{$send_key}) {
				$fdh->{send} = $socket_cache{$send_key};
			}
			else {
				$fdh->{send} = IO::Socket::INET->new(
					Proto     => 'udp',
					Family    => $address_family,
					PeerAddr  => $fdh->{collector_ip},
					PeerPort  => $fdh->{collector_port},
					LocalPort => $fdh->{local_port},
				);

				unless ($fdh->{send}) {
					Carp::croak(
						"Could not connect" .
						" to $fdh->{collector_ip} : $fdh->{collector_port} : $!"
					);
				}

				warn "socket cache key: $send_key (" . (scalar keys %socket_cache) . ")"
					if ( $ENV{FDI_DEBUG} );
				$socket_cache{$send_key} = $fdh->{send};
			}
		} else {
			my $try_cnt = 0;
			for ( ; ++$try_cnt <= 100; $localport++ ) {
				$localport = 1025 if ($localport >= 0xFFFF);
				$fdh->{send} = IO::Socket::INET->new(
					Proto     => 'udp',
					Family    => $address_family,
					PeerAddr  => $fdh->{collector_ip},
					PeerPort  => $fdh->{collector_port},
					LocalPort => $localport,
				) or next;
				last;
			}

			if ( $ENV{FDI_DEBUG} ) {
				if ($try_cnt) {
					warn "$0 tried $try_cnt ports starting at $localport";
				} else {
					warn "$0 using $localport on first try\n";
				}
			}

			$fdh->{local_port} = $localport;
		}

		# Punt and let the system pick a port
		unless ( $fdh->{send} ) {
			warn
				"$0 unable to allocate deterministic LocalPort value starting at $localport";
			$fdh->{send} = IO::Socket::INET->new(
				Proto    => 'udp',
				Family   => $address_family,
				PeerAddr => $fdh->{collector_ip},
				PeerPort => $fdh->{collector_port},
				)
				or warn
				"error sending to $fdh->{collector_ip} on port $fdh->{collector_port} $!\n";
		}

	}
	else {
		Carp::croak("could not seem to figure out how to make a socket");
	}
}


=head2  prepare

TODO: is there a better name than prepare?

This function will return a handle to template.  This is the primary
interface for sending/receiving data.

=cut

sub prepare {
	my $drh      = shift;
	my $fdh      = $drh;
	my $template = shift;

	my $tph = FDI::Template->new();
	for my $spec_str ( split /\n/, $template ) {
		$spec_str =~ s/^(\s+)$//g;
		next unless $spec_str;
		my $ie = FDI::InformationElement->for_spec($spec_str);
		$tph->addInformationElement($ie);
	}

	$drh->addTemplate($tph);
	return $tph;
}


=head2 setMaxEncodeLength

AKA MTU in some contexts

=cut

sub setMaxEncodeLength {
	my $drh = $_[0];
	my $fdh = $drh;
	return $fdh->{max_pack_len} = $_[1];
}

=head2 setRecvSocket

Are you talking to me?!?

=cut

sub setRecvSocket {
	my ( $drh, $recv ) = @_;
	my $fdh = $drh;
	$fdh->{recv} = $recv;
}

=head2 setSendSocket

Where is this data going?

=cut

sub setSendSocket {
	my ( $drh, $send ) = @_;
	my $fdh = $drh;
	$fdh->{send} = $send;
}

=head2 addTemplate

Add a template.

=cut

sub addTemplate {
	my ( $drh, $template ) = @_;
	my $fdh           = $drh;
	my $template_hash = $template->getTemplateHash();

	$fdh->{$template_hash}{template}          = $template;
	$fdh->{$template_hash}{flow_val_cnt}      = $template->getElementCount;
	$fdh->{template_hashes}->{$template_hash} = 1;
	$fdh->{pdus}                              = [];

	#warn Dumper($fdh);

}

=head2 addFlow

TODO: Change this name
Push a complete flow to send later.

=cut

sub addFlow {
	my $drh           = shift;
	my $template_hash = shift;
	my $dataref       = shift;

	my $fdh = $drh;

	croak "Unknown Template: $template_hash"
		unless $fdh->{$template_hash}{template};

	my $fth = $fdh->{$template_hash}{template};

	croak "Invalid flow value count" unless $fth->validFlow($dataref);

	return $fth->addFlow($dataref);
}

=head2 haveFullPacket

stub for later

=cut

sub haveFullPacket {
	my ($drh) = @_;

	## my $headerLength = $self->{header}->getLength();
	## my $flowLength   = $self->{template}->getLength();
	##
	## my $max_flows
	## 	= int( ( $self->{max_pack_len} - $headerLength ) / $flowLength );
	## my $flows = int( @{ $self->{data} } / $self->{flow_val_cnt} );
	##
	## return $flows >= $max_flows;
}

=head2 send

put our data on the wire

=cut

sub send {
	my $drh         = shift;

	my $fdh = $drh;

	$drh->encodeData();
	my $i = 0;
	for my $pdu ( @{ $fdh->{pdus} } ) {
		$i++;
		$fdh->{send}->send( &{ $fdh->{frame} }($pdu) );    # or return -1
	}
	@{ $fdh->{pdus} } = ();

	#warn "sending done ($i)", "\n";
	return $i;
}


=head2 retrieve

retrieve() removes pending flows, encodes them into zero or more PDUs,
and returns them along with some information about the socket
endpoints.

Returns a list of one or more elements.  The first element is the
socket information, and the subsequent elements are the PDUs (if any).

	(
		{
			collector_ip => ASCII_DOTTED_QUAD,
			collector_port => ASCII_INTEGER,
			exporter_ip => ASCII_DOTTED_QUAD,
			exporter_port => ASCII_INTEGER,
		},
		$encoded_pdu_1,
		$encoded_pdu_2,
		...
	)

=cut

sub retrieve {
	my ($drh, %arg) = @_;

	$drh->encodeData(%arg);
	my @pdus = @{ $drh->{pdus} };
	@{ $drh->{pdus} } = ();

	my ($exporter_port, $exporter_packed_addr) = sockaddr_in(
		getsockname( $drh->{send} )
	);

	return(
		{
			collector_ip   => $drh->{collector_ip},
			collector_port => $drh->{collector_port},
			exporter_ip    => inet_ntoa( $exporter_packed_addr ),
			exporter_port  => $exporter_port,
		},
		@pdus,
	);
}

use constant {
	FLOW_RECV_LIMIT   => ( $ENV{FDI_FLOW_RECV_LIMIT}   || 128 ),
	FLOW_RECV_TIMEOUT => ( $ENV{FDI_FLOW_RECV_TIMEOUT} || 0 ),
};

##sub recv {
##	my $drh        = shift;
##
##  use bytes;
##
##  READ: for (1..FLOW_RECV_LIMIT) {
##    my $emitter = recv($socket, my $payload = "", UDP_MAXLEN, 0);
##
##    unless (defined $emitter) {
##      next READ if (
##        $! == EAGAIN or $! == ETIMEDOUT or $! == EINTR or $! == EWOULDBLOCK
##      );
##
##      if ($^O eq 'MSWin32' && $socket->protocol() == 17 && $! == 10054) {
##        # "An existing connection was forcibly closed by the remote host."
##        # UDP connection closed?  Really?  UDP has connections?
##        #
##        # This is Windows trying to be clever and let us know when
##        # ICMP reports that there is no listener.  Interesting, but
##        # we don't need to chatter about it in the log.  We can just
##        # fail silently.
##        warn "bogus receive: (" . ($!+0) . "): $!\n" if DEBUG ;
##      } else {
##        warn "bogus receive: (" . ($!+0) . "): $!\n";
##      }
##      last READ;
##    }
##
##    # Discard the packet if we're in startup.
##    last READ if $self->{startup};
##
##    my ($emitter_port, $emitter_addr_bin) = unpack_sockaddr_in($emitter);
##    my $emitter_addr_ascii = inet_ntoa($emitter_addr_bin);
##
##    # TODO - Cache getsockname(), unpack_sockaddr_in() and inet_ntoa()
##    # per $socket since they shouldn't change?  Is a hash lookup faster
##    # or slower than the repeated chain of syscalls?
##
##    my $collector = getsockname($socket);
##    my ($collector_port, $collector_addr_bin) = unpack_sockaddr_in($collector);
##    my $collector_addr_ascii = inet_ntoa($collector_addr_bin);
##
##    # TODO - Does this need an algorithm that guarantees the same
##    # worker isn't chosen twice?  I don't want to do that much work if
##    # success is the common case.
##
##    my $message = pack( "C/a* C/a* n/a*", $emitter, $collector, $payload );
##
##    # Get the NetFlow version.
##    #
##    # We need to route sFlow packets to the same plxr_collector each
##    # time so that the parser can subtract packet and octet samples from
##    # the previous packet's... in order to get the deltas that we
##    # eventually record in the database.  See
##    # http://bugzilla.plxr.local/show_bug.cgi?id=8073
##
##    # TODO - Tricking it into thinking everything is sFlow.
##    my $netflow_version = unpack 'n', $payload;
##
##    # Chosen at random to balance write buffering across all the
##    # sockets we're not usually writing to.
##
##    my $redirect_socket = $self->{public_socket_list}->[
##      rand $self->{public_socket_count}
##    ];
##
##    my $exporter_rec = $self->{exporters}{$emitter};
##    unless (defined $exporter_rec) {
##
##      # sFlow gets one worker per exporter due to the way sFlow works.
##      # Everybody else gets some number of workers to be determined.
##      #
##      # TODO - Is it possible for a single exporter (IP + port) to
##      # send multiple netflow protocol versions?  How deep does this
##      # rabbit hole goe?
##
##      my $max_workers = (
##        $netflow_version
##        ? $self->{collectors_per_exporter}
##        : 1
##      );
##      if ( DEBUG_WORKERS ) {
##        warn(
##             "max_workers ($max_workers) : $netflow_version ? $self->{collectors_per_exporter} : 1\n"
##            );
##      }
##      if ( DEBUG_WORKERS ) {
##        my $fmt_exporter = fmt_sockaddr_in($emitter);
##        warn(
##             "choosing_workers for $fmt_exporter\n"
##            );
##      }
##      $exporter_rec = $self->{exporters}{$emitter} = [
##        # EXPORTER_WORKERS
##        [ _choose_workers($max_workers, $self->{worker_address_list}) ],
##        time(),       # EXPORTER_TIME
##        0,            # EXPORTER_PACKETS
##        0,            # EXPORTER_WORKER_IDX
##        $max_workers, # EXPORTER_WORKER_MAX
##      ];
##      if( DEBUG_WORKERS ) {
##        my $fmt_active_workers = join ',', map { fmt_sockaddr_in($_) } (@{$exporter_rec->[EXPORTER_WORKERS]});
##        warn(
##         "new active workers ==> $fmt_active_workers\n"
##        );
##      }
##      # The first exporter starts the timer.
##
##      $kernel->delay( periodic_cleanup => CLEANUP_PERIOD ) if (
##        scalar(keys %{$self->{exporters}}) == 1
##      );
##    }
##
##    my $workers = $exporter_rec->[EXPORTER_WORKERS];
##    SEND: for (1 .. @$workers) {
##      # Select the worker to receive this packet.
##
##      my $worker = $workers->[
##        $exporter_rec->[EXPORTER_WORKER_IDX]++ % @$workers
##      ];
##
##      my ($worker_port, $worker_addr_bin) = unpack_sockaddr_in($worker);
##      my $worker_addr_ascii = inet_ntoa($worker_addr_bin);
##
##      my $needed_to_send = length($message);
##
##      DEBUG and warn(
##        "Packet #", ++$packet_index, " ($needed_to_send octets) ",
##        "from $emitter_addr_ascii:$emitter_port ",
##        "at $collector_addr_ascii:$collector_port ",
##        "-> $worker_addr_ascii:$worker_port\n",
##      );
##
##      $! = 0;
##      my $sent = send($redirect_socket, $message, 0, $worker);
##
##      if ($!) {
##        warn "error distributing packet: $!\n";
##        next SEND;
##      }
##
##      # Success!
##      if ($sent == $needed_to_send) {
##        ++$exporter_rec->[EXPORTER_PACKETS];
##        next READ;
##      }
##
##      # Bummer.  Try again.
##      warn "short send to worker: $!\n";
##    }
##
##    warn "ultimately failed to distribute packet: $!\n";
##  }
##}

=head2 available_drivers

Currently 'IPFIX', 'NetFlow_v5'

=cut

sub available_drivers { return ( 'IPFIX', 'NetFlow_v5' ) }

=head2 parse_dsn

  Pares our DSN
 FDI Data Source Name (DSN)
 DSN Format: "$scheme:$driver($attr_string):$driver_dsn)"

=cut

sub parse_dsn {
	my ( $class, $dsn ) = @_;
	$dsn =~ s/^(fdi):(\w*?)(?:\((.*?)\))?://i or return;
	my ( $scheme, $driver, $attr, $attr_hash ) = ( lc($1), $2, $3 );
	$driver ||= $ENV{DBI_DRIVER} || 'IPFIX';
	$attr_hash = { split /\s*=>?\s*|\s*,\s*/, $attr, -1 } if $attr;

	#warn Dumper ([( $scheme, $driver, $attr, $attr_hash, $dsn )]);

	return ( $scheme, $driver, $attr, $attr_hash, $dsn );
}


=head2 install_driver

  install the driver we are using

=cut

sub install_driver {    # croaks on failure
	my $class = shift;
	my ( $driver, $attr ) = @_;
	my $drh;

	Carp::croak("usage: $class->install_driver(\$driver [, \%attr])")
		unless ( $driver and @_ <= 3 );

	# already installed
	#return $drh if $drh = $FDI::installed_drh{$driver};

	my $driver_class = "FDD::$driver";

	#warn("installing: $driver_class");


	## no critic
	eval "require $driver_class;";    # load the driver
	## use critic
	if ($@) {
		Carp::croak("install_driver($driver) failed: $@\n");
	}

	#warn("setup_driver: $driver_class");
	$class->setup_driver($driver_class);

	#warn("create driver: $driver_class");
	$drh = eval { $driver_class->driver($attr) };
	if ($@) {
		Carp::croak("create driver($driver) failed: $@\n");
	}

	$FDI::installed_drh{$driver} = $drh;

	$drh;
}


=head2 setup_driver

Stub for future use

=cut

sub setup_driver {
	my ( $class, $driver_class ) = @_;

	# See DBI if needed.  Sets up ISA relationships for various classes.
}


1;    # Magic true value required at end of module

__END__

=head1 NAME

FDI - Protocol independent perl interface to send/receive flow data


=head1 VERSION

This document describes FDI version 1.0


=head1 SYNOPSIS

  use FDI;

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

  FDI requires no configuration files or environment variables.

=head1 DEPENDENCIES

This list is expected to grow over time as additional flow protocols
are added as backends for FDI.

Net::Flow

=head1 INCOMPATIBILITIES

None reported.


=head1 BUGS AND LIMITATIONS

No bugs have been reported.
sFlow is not currently supported.

Please report any bugs or feature requests to
C<bug-net-flow@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Andrew Feren  C<< <andrewf@plixer.com> >>


=head1 ACKNOWLEDGMENTS

Thanks to Plixer for their support.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2013 - 2017, Andrew Feren C<< <andrewf@plixer.com> >>. 
All rights reserved.

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

=cut


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:2 ***
# perl-indent-level:2 ***
# tab-width: 2 ***
# indent-tabs-mode: t ***
# End: ***
#
# vim: ts=2 sw=2 noexpandtab

