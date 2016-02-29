use strict;
use Win32::API;
use Data::Dumper;
use Plixer::EventLog;
use feature qw( say );

# Connect to remote machine (the 1 means verbose logging. Remove or set to 0 to disable)
my $eventLog = Plixer::EventLog->new('host.com', 'username', 'password', 1);

## Load all records in application log
# $eventLog->parse(
#	eventlog => 'Application'
# );

## Load all records in application log in CSV format
# $eventLog->parse(
#	eventlog => 'Application',
#	csv => 1
# );

## Load all records in application log starting at record 10000 and ending at record 11000
# $eventLog->parse(
#	eventlog => 'Application',
#	startrec => 10000,
#	endre => 11000
# );

## Load all records in application log with event types 903, 1003 and 1004
# my @eventList = (902, 1003, 1004);
# $eventLog->parse(
#	eventlog => 'Application',
#	eventfilter => \@eventList
# );




