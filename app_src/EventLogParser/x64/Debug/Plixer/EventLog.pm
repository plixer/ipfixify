package Plixer::EventLog;

use strict;
use feature qw( say );
use Carp;
use Data::Dumper;

sub new {
	# Verify required number of arguments
	die "usage: PACKAGE->new(<server>, <username>, <password>)\n" 
		unless @_ >= 4;

	my ($class, $server, $fullUsername, $password, $debug) = @_;
	
	my $username;
	my $domain;
	
	# If username contains a backslash
	if( index($fullUsername, "\\") > -1 ) {
		# Split into two 
		my @result = split("\\\\", $fullUsername);
		# The second part is the username
		$username = $result[1];
		# The first part is the domain
		$domain = $result[0];
	} else {
		# If no backslash found, the entire username is the username
		$username = $fullUsername;		
	}
	
	# TODO: Add any custom validation code you wish 

	return bless {
		server => $server,
		domain => $domain,
		username => $username,
		password => $password,
		debug => $debug || 0
	} => $class;
}

sub get_last_record_id {
	my $self = shift;
	my $logName = shift;
	
	my $getLastRecordId = Win32::API::More->new(
		'EventLogParser', 
		'GetLatestEventLogRecord', 
		'PPPPPI', 
		'N'
	);	
	
	croak "Error: $^E" if !$getLastRecordId;	
	
	my $server = $self->_to_wchar($self->{server});
	my $domain = $self->_to_wchar($self->{domain});
	my $username = $self->_to_wchar($self->{username});
	my $password = $self->_to_wchar($self->{password});
	my $logName = $self->_to_wchar($logName);
	
	my $result = $getLastRecordId->Call( $server, $domain, $username, $password, $logName, $self->{debug});
	
	return $result;
}

sub parse {
	my $self = shift;						# This object
	my (%args) = @_;						# Remaining arguments
	my $logName = $args{eventlog};			# Log name (e.g. Application)
	my $useCsv = $args{csv} || 0;			# 1=CSV otherwise assume JSON
	my $startRec = $args{startrec} || 0;	# Record to start reading from
	my $endRec = $args{endrec} || 0;		# Record to stop reading at
	my $events = $args{eventfilter};		# Array of events IDs to filter		

	croak "endRec must be >= 0" 
		if $endRec < 0;
		
	croak "startRec must be >= 0"
		if $startRec < 0;
		
	my $filters = {
		lowRecord => $startRec,
		highRecord => $endRec,
		events => $events
	};

	$self->_parse_event_log( $logName, $useCsv, $filters );
}

sub open_session {
	my $self = shift;
	
	my $openSession = Win32::API::More->new(
		'EventLogParser', 
		'OpenSession', 
		'PPPI', 
		'N'
	);
	
	croak "Error: $^E" if !$openSession;	
	
	my $server = $self->_to_wchar($self->{server});
	my $domain = $self->_to_wchar($self->{domain});
	my $username = $self->_to_wchar($self->{username});
	my $password = $self->_to_wchar($self->{password});
	
	my $result = $openSession->Call( $server, $domain, $username, $password, $self->{debug} );
	
	return $result;
}

sub close_handle {
	my ($self, $handle) = @_;
	
	my $fn = Win32::API::More->new(
		'EventLogParser', 
		'CloseEventHandle', 
		'NI', 
		'N'
	);
	
	croak "Error: $^E" if !$fn;	

	my $result = $fn->Call( $handle, $self->{debug} );
	
	return $result;
}

sub read_next_event {
	my ($self, $remote_handle, $event_handle) = @_;
	
	my $fn = Win32::API::More->new(
		'EventLogParser', 
		'ReadNextEvent', 
		'PPI', 
		'N'
	);
	
	croak "Error: $^E" if !$fn;	

	my $result = $fn->Call( $remote_handle, $event_handle, $self->{debug} );
	
	return $result;
}

sub start_session {
	my $self = shift;						# This object
	my (%args) = @_;						# Remaining arguments
	my $handle = $args{handle};				# Handle to remote session opened
	my $logName = $args{eventlog};			# Log name (e.g. Application)
	my $useCsv = $args{csv} || 0;			# 1=CSV otherwise assume JSON
	my $startRec = $args{startrec} || 0;	# Record to start reading from
	my $endRec = $args{endrec} || 0;		# Record to stop reading at
	my $events = $args{eventfilter};		# Array of events IDs to filter		

	if( !$handle ) {
		# Note: Do not croak here, as we should allow the caller to
		# close any open handles to avoid memory leaks
		say "No valid handle was supplied";
	} else {		
		my $filters = {
			lowRecord => $startRec,
			highRecord => $endRec,
			events => $events
		};
		
		say "Handle: $handle, logName: $logName, useCsv: $useCsv";
		
		$self->_start_session( $handle, $logName, $useCsv, $filters );
	}
}

sub _start_session {
	my ($self, $handle, $logName, $useCsv, $filters) = @_;
	
	my $fn = Win32::API::More->new(
		'EventLogParser', 
		'StartSession', 
		'NPPI', 
		'N'
	);
	
	die "Error: $^E" if !$fn;	
	
	# Windows Event Log API requires wide char
	my $logName = $self->_to_wchar($logName);
	
	# Generate an XPath query based on supplied filters
	my $xpathQuery = $self->_get_xpath_query( $filters );
	my $xpathQueryWide = $self->_to_wchar( $xpathQuery );	

	my $result = $fn->Call( $handle, $logName, $xpathQueryWide, $self->{debug} );
	
	return $result;
}

sub _parse_event_log {
	my ($self, $logName, $useCsv, $filters) = @_;

	# Windows Event Log API requires wide char
	my $server = $self->_to_wchar($self->{server});
	my $domain = $self->_to_wchar($self->{domain});
	my $username = $self->_to_wchar($self->{username});
	my $password = $self->_to_wchar($self->{password});
	my $logName = $self->_to_wchar($logName);
	
	# Generate an XPath query based on supplied filters
	my $xpathQuery = $self->_get_xpath_query( $filters );
	my $xpathQueryWide = $self->_to_wchar( $xpathQuery );
	
	# Import the Event Log Parsing function
	my $parseEventLog = Win32::API::More->new(
		'EventLogParser', 
		'ParseEventLog', 
		'PPPPPPII', 
		'I'
	);
	
	# Prevent execution if function cannot be loaded
	croak "Error: $^E" if !$parseEventLog;
	
	# Parse the event log
	# Change the last parameter to 1 to enable verbose logging
	$parseEventLog->Call($server, $domain, $username, $password, $logName, $xpathQueryWide, $useCsv, $self->{debug});	
}

sub _get_xpath_query {	
	my ($self, $filters) = @_;

	my $recordClause;
	my $eventClause;
	my $query = "";
	
	# Build record filtering clause
	$recordClause .= "(System/EventRecordID >= $filters->{lowRecord})" 
		if $filters->{lowRecord};				
	if( $filters->{highRecord} ) {
		$recordClause .= " and " if( $filters->{lowRecord} );
		$recordClause .= "(System/EventRecordID <= $filters->{highRecord})"; 
	}

	# Build event ID filtering clause
	if( $filters->{events} ) {
		my $eventListLength = scalar @{$filters->{events}};
		for( my $i=0; $i < $eventListLength; $i++ ) {
			$eventClause .= "(System/EventID = $filters->{events}[$i])";
			$eventClause .= " or " if $i < ($eventListLength - 1);
		}
	}
	
	# Build header/footer portions of query
	if ($recordClause or $eventClause) {
		$query .= "*[";
		$query .= "($recordClause)" if $recordClause;
		$query .= " and " if ($recordClause && $eventClause);
		$query .= "($eventClause)" if $eventClause;
		$query .= "]";
	}

	return $query;
}

# Converts a string to a wide-character string (wchar_t in C)
# This is required for the Win32 Event Log API
sub _to_wchar {
	my ($self, $input) = @_;
	return join("\0", split('', $input)) . "\0\0\0";
}

1;
