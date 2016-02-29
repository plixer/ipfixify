package Plixer::Process;
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

BEGIN {
  # PATHEXT needs to be updated before File::Which loads.
  if ( $^O eq 'MSWin32' ) {
    $ENV{PATHEXT} .= ';.CGI' unless grep /\.cgi/i, $ENV{PATHEXT};
  }
  use File::Which qw( which );
}

use Exporter 'import';
our @EXPORT_OK;
BEGIN { @EXPORT_OK = qw( scrut_which ) };

use constant implementation => ( ( $^O eq 'MSWin32' )
	? __PACKAGE__ . '::Windows_imp'
	: __PACKAGE__ . '::Posix_imp' );

sub new {
  my $class = shift;

  my $obj = implementation->new(@_);
  return $obj;
}


sub scrut_which {
  my $exe = shift;

  return undef unless defined $exe;

  my $potential_exe = which( $exe );
  return $potential_exe if $potential_exe;

  # This little bit of foolishness is needed for *.cgi.  Exactly why
  # this is needed is a bit of a mystery at the moment.  It seems to
  # have something to do with .cgi not being an extension that is
  # expected for executables on windows.
  for my $path_dir (File::Spec->path()) {
    $potential_exe = File::Spec->catfile( $path_dir, $exe );
    return $potential_exe if -e $potential_exe && !-d $potential_exe;
  }
  return undef;
}

use if $^O eq 'MSWin32', 'Plixer::Process::Windows_imp';
use if $^O ne 'MSWin32', 'Plixer::Process::Posix_imp';


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

