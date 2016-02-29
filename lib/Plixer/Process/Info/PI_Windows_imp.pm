package Plixer::Process::Info::PI_Windows_imp;
#START #UTF-8#
# http://www.perl.com/pub/2012/04/perlunicook-standard-preamble.html #UTF-8#
use utf8;      # so literals and identifiers can be in UTF-8 #UTF-8#
use v5.16;     # or later to get "unicode_strings" feature #UTF-8#
use strict;    # quote strings, declare variables #UTF-8#
use warnings;  # on by default #UTF-8#
#NO#use warnings  qw(FATAL utf8);    # fatalize encoding glitches #UTF-8#
use open      qw(:std :utf8);    # undeclared streams in UTF-8 #UTF-8#
#END #UTF-8#

use warnings;
use strict;

use Win32;
use Win32::Process::Info;

use Plixer::plxr_logger ();

# expected keys : logger, startup_dir, exe_name, exe_args
sub _parse_args {
	my $self = shift;
	%{$self} = @_;
	$self->{logger}      //= Plixer::plxr_logger->new();
}


sub new {
	my $class = shift;
	my $self  = {};
	_parse_args( $self, @_ );

	return bless $self, $class;
}

sub ListPids {
	my $self = shift;

	my $pi = Win32::Process::Info->new();
	return $pi->ListPids();
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
