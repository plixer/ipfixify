#
package Plixer::Net::Packet;
#START #UTF-8#
# http://www.perl.com/pub/2012/04/perlunicook-standard-preamble.html #UTF-8#
use utf8;      # so literals and identifiers can be in UTF-8 #UTF-8#
use v5.16;     # or later to get "unicode_strings" feature #UTF-8#
use strict;    # quote strings, declare variables #UTF-8#
use warnings;  # on by default #UTF-8#
#NO#use warnings  qw(FATAL utf8);    # fatalize encoding glitches #UTF-8#
use open      qw(:std :utf8);    # undeclared streams in UTF-8 #UTF-8#
#END #UTF-8#

# Sanity checking
use strict;
use warnings;

use Exporter 'import';

our $VERSION;
our (@EXPORT);
BEGIN {
	$VERSION = 12;
	@EXPORT  = qw( getAdapterInfo );
}

sub getAdapterInfo();

BEGIN {
	# Perl OS
	if ( $^O eq 'MSWin32' ) {
		eval 'use Sys::Hostname';	die $@ if $@;
		eval 'use Socket';		 		die $@ if $@;

		*Plixer::Net::Packet::getAdapterInfo = sub() {
			my @nic_info      = ();
			my @nic_info_noip = ();
			my %description;
			my $nic;
			my ( $name, $description, $type, $speed, $ip, $mask, $mac );

			# old style of determining IP
			my $old_ip = inet_ntoa( scalar( ( hostname() && gethostbyname( hostname() ) ) || gethostbyname('localhost') ) );

			{
				@nic_info = (
					{   ip    => $old_ip,
						descr => "WMI skipped (default IP)"
					}
				);
				return @nic_info if wantarray;
				return undef if @nic_info == 0 || !exists $nic_info[0]->{ip};
				return $nic_info[0];
			}
			}
	} else {
		eval 'use Sys::HostIP';		die $@ if $@;

		*Plixer::Net::Packet::getAdapterInfo = sub() {
			my $info     = {};
			my @nic_info = ();

			unless ( @nic_info && $nic_info[0]->{ip} ) {
				@nic_info = (
					{   name  => 'Default IP',
						descr => 'Best Guess Default IP',
						ip    => Sys::HostIP->ip,
					}
				);
			}

			return @nic_info if wantarray;
			return undef if @nic_info == 0 || !exists $nic_info[0]->{ip};
			return $nic_info[0];
		}
	}
}


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
