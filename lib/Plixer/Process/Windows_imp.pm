package Plixer::Process::Windows_imp;
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
use Win32::Process;

# expected keys : startup_dir, exe_name, exe_args
sub _parse_args {
	my $self = shift;
	%{$self} = @_;
	$self->{startup_dir} //= '.';
	$self->{exe_args}    //= [];
}


sub new {
	my $class = shift;
	my $self  = {};
	_parse_args( $self, @_ );
	$self->{pob} = undef;

	return bless $self, $class;
}


sub pid {
	my $self = shift;
	return undef unless defined $self->{pob};
	return $self->{pob}->GetProcessID();
}


# returns true or false.  Make no other assumptions about the return value.
sub is_alive {
	my $self = shift;
	return !defined $self->exit_code();
}


# undef == still running
# anything else is an exit value
sub exit_code {
	my $exit_code;
	shift()->{pob}->GetExitCode($exit_code);
	return undef if $exit_code == Win32::Process::STILL_ACTIVE();
	return $exit_code;
}


sub kill {
	return shift()->{pob}->Kill(9);    # should this be 9 or 1?
}


sub run {
	my $self = shift;
	my %args = @_;

	my ( $startup_dir, $exe_name, $exe_args )
		= @{$self}{qw{startup_dir exe_name exe_args}};

	warn 'exe_name is empty or undefined' unless $exe_name;

	#my $rand = time() . '_' . int(rand(10000));
	#my $tmpfn = "C:\\WINDOWS\\Temp\\acf_${rand}.txt";
	#open (my $acf, '>', $tmpfn) or die "cannot open > $tmpfn $!";;
	#print $acf "$exe_name @$exe_args\n";
	#close ($acf);

	my $priority_class;
	if ( defined $self->{niceness} ) {
		if ( $self->{niceness} < -18 ) {
			$priority_class = Win32::Process::REALTIME_PRIORITY_CLASS();
		} elsif ( $self->{niceness} < 0 ) {
			$priority_class = Win32::Process::HIGH_PRIORITY_CLASS();
		} elsif ( $self->{niceness} > 0 ) {

			# "IDLE_PRIORITY_CLASS" sounds too low.
			# Leaving this option explicit for future expansion.
			$priority_class = Win32::Process::NORMAL_PRIORITY_CLASS();
		}
	}

	$priority_class //= Win32::Process::NORMAL_PRIORITY_CLASS();

	# it seem like we ought to be able to get $ENV{COMSPEC} to redirect
	# the output of the commands it runs to a file, but it didn't work
	# for me.  What I have right now at least pops up a window that you
	# can glimpse.  If I have problems with this in the future I'll make
	# an other stab and getting the command line correct.
	unless (
		Win32::Process::Create(
			$self->{pob},
			$exe_name,
			join(' ', map { qq{"$_"} } ( $exe_name, @$exe_args )), # Quote everything.
			0,    # Don't inherit file handles.
			Win32::Process::CREATE_NO_WINDOW() | $priority_class,
			$startup_dir,
		)
		) {

		my $error = Win32::FormatMessage( Win32::GetLastError() );
		warn "Process::Create ($exe_name @$exe_args) failed ($error)";
	}

	return $self->pid();
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
