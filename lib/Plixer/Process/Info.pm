package Plixer::Process::Info;
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

use Exporter 'import';

use if $^O eq 'MSWin32', 'Plixer::Process::Info::PI_Windows_imp';
use if $^O ne 'MSWin32', 'Plixer::Process::Info::PI_Posix_imp';
use constant implementation => ( ( $^O eq 'MSWin32' )
	? __PACKAGE__ . '::PI_Windows_imp'
	: __PACKAGE__ . '::PI_Posix_imp' );


sub new {
  my $class = shift;

  my $obj = implementation->new(@_);
  return $obj;
}

1;

__END__


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:2 ***
# perl-indent-level:2 ***
# tab-width: 2 ***
# indent-tabs-mode: nil ***
# End: ***
#
# vim: ts=2 sw=2 expandtab

