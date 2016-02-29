package Plixer::Process::Posix_imp;
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

use POSIX qw(:sys_wait_h setgid setuid);

# expected keys : startup_dir, exe_name, exe_args
sub _parse_args {
	my $self = shift;
	%{$self} = @_;
	$self->{startup_dir} //= '.';
	$self->{exe_args}    //= [];
	$self->{username}    //= "plixer";
	$self->{groupname}   //= "plixer";
}


sub new {
	my $class = shift;
	my $self  = {};
	_parse_args( $self, @_ );

	return bless $self, $class;
}


# returns 0 or non 0.  Make no other assumptions about the return value.
sub is_alive {
	my $self = shift;

	# Don't use kill( 0, $self->{pid} );
	# This keeps returning true until the child is reaped.
	return !defined $self->exit_code();
}


# undef == still running
# anything else is an exit value
sub exit_code {
	my $self = shift;

	# Don't re-reap if we've already reaped.
	return $self->{exit_code} if defined $self->{exit_code};

	# Can't wait on a PID we don't have.  Return a patently bogus (but
	# defined) value so that is_alive() will return false.
	return -1 unless defined $self->{pid};

	my $wait_res = waitpid( $self->{pid}, WNOHANG );
	if ( $wait_res > 0 ) {
		$self->{exit_code} = $? >> 8;
	} elsif ( $wait_res < 0 ) {
		$self->{exit_code} = -1;		# some error, but still not running
	}

	return $self->{exit_code};
}


sub pid {
	return shift()->{pid};
}


sub kill {
	my $self = shift();
	my $pid  = $self->{pid};

	# Nothing to kill?
	return unless defined $pid;

	# Already reaped it.  Be careful not to kill it again, in case we
	# have privileges to kill another process with the same PID.
	return if defined $self->{exit_code};

	return kill( 9, $pid );
}


sub run {
	my $self = shift;

	my ( $startup_dir, $exe_name, $exe_args )
		= @{$self}{qw{startup_dir exe_name exe_args}};

	warn 'exe_name is empty or undefined' unless $exe_name;

	#open STDOUT, '>>', "/home/plixer/scrutinizer/files/logs/stdout_$$.out";
	#open STDERR, '>>', "/home/plixer/scrutinizer/files/logs/stderr_$$.out";

	$self->{pid} = fork();

	# Fork failed.
	# Returning is valid because this is still the parent process.

	unless ( defined $self->{pid} ) {
		warn "  FORK failed for ($exe_name @$exe_args): $!";
		return undef;
	}

	# Parent here.  Track the new child.

	return $self->{pid} if $self->{pid};

	# Child here.  The only way out is via exec() or POSIX::_exit().
	# Death (die) is not an option.

	# Set this process' priority.
	# We can probably cope with failure.

	if ( defined $self->{niceness} ) {
		setpriority( 0, $$, $self->{niceness} )
			or warn "setpriority(0, $$, $self->{niceness}) error: $!";
	}

	# Switch to another user.
	# Most often used to drop root privileges for code we may not trust.
	# Failure is an _exit() offense, since running things accidentally
	# as root can lead to lingering problems like permissions issues and
	# privilege escalation exploits.

	my $groupid = getgrnam( $self->{groupname} );
	if ( defined $groupid and ( $groupid != $( or $groupid != $) ) ) {
		setgid($groupid) or do {
			warn "setgid('$self->{groupname}') failed: $!";

			# A brief delay to prevent fork retrying at a debilitating rate.
			sleep 1;

			POSIX::_exit(1);
		};
	}

	# Set UID last.  Once this is done, there's no going back.
	my $userid = getpwnam $self->{username};
	if ( defined $userid and ( $userid != $< or $userid != $> ) ) {
		setuid($userid) or do {
			warn "setuid('$self->{username}') failed: $!";

			# A brief delay to prevent fork retrying at a debilitating rate.
			sleep 1;

			POSIX::_exit(1);
		};
	}

	# Setting the runtime current directory.
	# NOTE for Andrew - Should this be a fatal error?  If I recall
	# correctly, stuff assumes the current directory is set a certain
	# way, and files and directories may be created in wrong places if
	# it's not.

	unless ( chdir $startup_dir ) {
		warn "couldn't change to startup directory ($startup_dir): $!";
	}

	# The moment of truth. Exec the new program.
	# This should only return in catastrophic cases, like the kernel
	# process table is full or something.

	#warn "  EXEC ($$) ($exe_name @$exe_args)";

	# exec() followed by warn triggers a Perl warning.
	# We can't die() here.  See below.

	exec( $exe_name, @$exe_args )
		or warn( "exec ($exe_name @$exe_args) failed ($!) ($@) ($^E)" );

	# The comment for the other sleep call applies here too.
	sleep 1;

	# This is the child process after exec() failed.
	# This process must end using POSIX::_exit() or END-times cleanup
	# will do terrible things.  For example, I'm seeing the parent
	# processes crash because database handles are shutting down
	# gracefully here.  The parent's still trying to use them.

	POSIX::_exit(1);
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
