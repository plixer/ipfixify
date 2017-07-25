#!perl

package ipfixify::definitions;

use Exporter;
use FDI::InformationModel;
use strict;

our ($VERSION);
our ( @ISA, @EXPORT );

$VERSION = '1';

@ISA = qw(Exporter);

@EXPORT = qw(
	defDataType
	defDataUnits
	defSemantics
	defVersionInfo
	tempSelect
);

=pod

=head1 NAME

ipfixify::definitions

=head1 SYNOPSIS

=over 2

	%def = &ipfixify::definitions::defDataType();

	%def = &ipfixify::definitions::defDataUnits();

	%def = &ipfixify::definitions::defSemantics();

	%def = &ipfixify::definitions::defVersionInfo();

	%cfg = &ipfixify::definitions::tempSelect(
		definitions	=> function_name (e.g. sysmetricsVitalsv4)
	);

=back

=head1 DESCRIPTION

This module contains functions related to defining some internal
structures.

The following functions are part of this module.

=cut

#####################################################################

=pod

=head2 defDataType

This function defines the IPFIX datatypes.

=over 2

	&ipfixify::definitions::defDataType();

=back

There are no parameters currently supported.

=cut

sub defDataType () {
	my %dt = %FDI::DT::std_types;
	for (keys %dt) {
		$dt{lc($_)} = $dt{$_};
	}
	return %dt;
}

#####################################################################

=pod

=head2 defDataUnits

This function defines the IPFIX data units.

=over 2

	&ipfixify::definitions::defDataUnits();

=back

There are no parameters currently supported.

=cut

sub defDataUnits () {
	my %du = %FDI::DS::units;
	for (keys %du) {
		$du{lc($_)} = $du{$_};
	}
	return %du;
}

#####################################################################

=pod

=head2 defSemantics

This function defines the IPFIX data semantics.

=over 2

	&ipfixify::definitions::defSemantics();

=back

There are no parameters currently supported.

=cut

sub defSemantics () {
	my %ds = %FDI::DS::names;
	for (keys %ds) {
		$ds{lc($_)} = $ds{$_};
	}
	return %ds;
}

#####################################################################

=pod

=head2 defVersionInfo

This function defines IPFIXify versioning.

=over 2

	&ipfixify::definitions::defVersionInfo();

=back

There are no parameters currently supported.

=cut

sub defVersionInfo () {
	our ( $author, $productBuild, $productName, $website );
	do 'version.info';

	return qq {
$productName
[$productBuild]
Copyright (C) 2012 - 2017 Plixer, MIT License
Visit https://github.com/plixer/ipfixify for wiki and source
$author
$website
};
}


#####################################################################

=pod

=head2 tempSelect

This function selects the appropriate %cfg based on name passed.

=over 2

	%cfg = &ipfixify::definitions::tempSelect(
		flowCache => INTEGER
	);

=back

The currently supported parameters are:

=over 2

=item * flowCache

The flowCache mode to grab

=back

=cut

sub tempSelect {
	my %arg = (@_);
	my %cfg;

	if ($arg{flowCache} =~ m/^(1|2|3)$/) {
		%cfg =
			(
			 'columnCount'	=> 9,
			 'id' 					=> 'EpEventLog',
			 'name' 				=> 'IPFIXify: Endpoint Microsoft Eventlogs',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifylogname(13745/3038)<string>
					observationtimeseconds(322)<dateTimeSeconds>
					ipfixifyeventrecordid(13745/3001)<unsigned64>
					ipfixifyeventid(13745/3003)<signed64>
					ipfixifylogsource(13745/3004)<string>
					ipfixifymessage(13745/3005)<string>
					ipfixifydeltamessagecount(13745/3006)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 4) {
		%cfg =
			(
			 'columnCount' 	=> 6,
			 'id' 					=> 'EpVitals',
			 'name'					=> 'IPFIXify: Endpoint Vitals',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifycpuusage(13745/3007)<unsigned8>
					ipfixifyfreephysicalmemory(13745/3008)<unsigned64>
					ipfixifyfreevirtualmemory(13745/3009)<unsigned64>
					ipfixifyproccount(13745/3010)<unsigned16>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 5) {
		%cfg =
			(
			 'columnCount' 	=> 4,
			 'id' 					=> 'EpStorage',
			 'name'					=> 'IPFIXify: Endpoint Storage',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifystoragelabel(13745/3011)<string>
					ipfixifystorageavailablebytes(13745/3012)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 6) {
		%cfg =
			(
			 'columnCount' 	=> 3,
			 'id' 					=> 'EpCollect',
			 'name'					=> 'IPFIXify: Collection Statistics',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifycollectionmilliseconds(13745/3013)<unsigned32>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} =~ m/^(7|13)$/) {
		%cfg =
			(
			 'columnCount' 	=> 11,
			 'id' 					=> 'EpProcsCPU',
			 'name'					=> 'IPFIXify: Endpoint CPU per Process',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifyprocessname(13745/3014)<string>
					ipfixifyparentprocessname(13745/3037)<string>
					username(371)<string>
					ipfixifyprocesscommandline(13745/3015)<string>
					ipfixifyparentprocessid(13745/3016)<unsigned32>
					ipfixifyparentprocesshash(13745/3017)<octetArray>{xform:a2b}
					ipfixifyprocessid(13745/3018)<unsigned32>
					ipfixifyprocesshash(13745/3019)<octetArray>{xform:a2b}
					ipfixifycpuusage(13745/3007)<unsigned8>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} =~ m/^(8|14)$/) {
		%cfg =
			(
			 'columnCount' 	=> 12,
			 'id' 					=> 'EpProcsMEM',
			 'name'					=> 'IPFIXify: Endpoint Memory per Process',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ipfixifyprocessname(13745/3014)<string>
					ipfixifyparentprocessname(13745/3037)<string>
					username(371)<string>
					ipfixifyprocesscommandline(13745/3015)<string>
					ipfixifyparentprocessid(13745/3016)<unsigned32>
					ipfixifyparentprocesshash(13745/3017)<octetArray>{xform:a2b}
					ipfixifyprocessid(13745/3018)<unsigned32>
					ipfixifyprocesshash(13745/3019)<octetArray>{xform:a2b}
					ipfixifyvirtualmemoryused(13745/3020)<unsigned64>
					ipfixifyphysicalmemoryused(13745/3021)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 11) {
		%cfg =
			(
			 'columnCount'	=> 5,
			 'id' 					=> 'NameValPair',
			 'name' 				=> 'IPFIXify: Name/Value Pairs',
			 'columns' 			=> '
					exporteripv4address(130)<ipv4Address>{xform:a2b_na}
					originalexporteripv4address(403)<ipv4Address>{xform:a2b_na}
					plixergenericname(13745/5102)<string>
					plixergenericvalue(13745/5103)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 18) {
		%cfg =
			(
			 'columnCount'	=> 7,
			 'id' 					=> 'POSTFIX',
			 'name' 				=> 'IPFIXify: Postfix Email Activity',
			 'columns' 			=> '
					exporteripv4address(130)<ipv4Address>{xform:a2b_na}
					originalexporteripv4address(403)<ipv4Address>{xform:a2b_na}
					sender_address(13745/116)<string>
					recipient_address(13745/105)<string>
					octettotalcount(85)<unsigned64>
					exportedmessagetotalcount(41)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 20) {
		%cfg =
			(
			 'columnCount' 	=> 9,
			 'id' 					=> 'EpNetstat',
			 'name'					=> 'IPFIXify: Endpoint Netstat Details',
			 'originator'		=> 'ipfixifymachineid',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					protocolidentifier(4)<unsigned8>
					sourceipv4address(8)<ipv4Address>{xform:a2b}
					sourcetransportport(7)<unsigned16>
					destinationipv4address(12)<ipv4Address>{xform:a2b}
					destinationtransportport(11)<unsigned16>
					ipfixifynetstatstate(13745/3022)<unsigned8>
					ipfixifyprocessid(13745/3018)<unsigned32>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 25) {
		%cfg =
			(
			 'columnCount'	=> 13,
			 'name'					=> 'honeynet',
			 'originator'		=> 'originalexporteripv4address',
			 'columns'			=> '
					exporteripv4address(130)<ipv4Address>{xform:a2b_na}
					originalexporteripv4address(403)<ipv4Address>{xform:a2b_na}
					sourcetransportport(7)<unsigned16>
					connectionstate(13745/5340)<unsigned8>
					sourceipv4address(8)<ipv4Address>{xform:a2b}
					destinationtransportport(11)<unsigned16>
					ipfixifymessage(13745/3005)<string>
					protocolidentifier(4)<unsigned8>
					destinationipv4address(12)<ipv4Address>{xform:a2b}
					tcpcontrolbits(6)<unsigned8>
					flowstartmilliseconds(152)<unsigned64>
					octetdeltacount(1)<unsigned64>
					octetdeltacount_rev(29305/1)<unsigned64>',
			);
	} elsif ($arg{flowCache} == 26) {
		%cfg =
			(
			 'columnCount'	=> 9,
			 'id'						=> 'EpUidByIp',
			 'name'					=> 'IPFIXify: Endpoint User Identity (IP Address)',
			 'originator'		=> 'ipfixifymachineid',
			 'columns'			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					username(371)<string>
					sourceipv4address(8)<ipv4Address>{xform:a2b}
					ipfixifymachinename(13745/3002)<string>
					observationtimeseconds(322)<dateTimeSeconds>
					ipfixifyloginstate(13745/3023)<unsigned8>
					ipfixifylogintype(13745/3024)<unsigned8>
					ipfixifyloginid(13745/3025)<string>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 27) {
		%cfg =
			(
			 'columnCount'	=> 9,
			 'id'						=> 'EpUidbyMac',
			 'name'					=> 'IPFIXify: Endpoint User Identity (Mac Address)',
			 'originator'		=> 'ipfixifymachineid',
			 'columns'			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					username(371)<string>
					sourcemacaddress(56)<macAddress>
					ipfixifymachinename(13745/3002)<string>
					observationtimeseconds(322)<dateTimeSeconds>
					ipfixifyloginstate(13745/3023)<unsigned8>
					ipfixifylogintype(13745/3024)<unsigned8>
					ipfixifyloginid(13745/3025)<string>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 28) {
		%cfg =
			(
			 'columnCount'	=> 7,
			 'id'						=> 'EpIfStats',
			 'name'					=> 'IPFIXify: Endpoint Interface Statistics',
			 'originator'		=> 'ipfixifymachineid',
			 'columns'			=> '
					ipfixifymachineid(13745/3030)<string>[32]
					ingressinterface(10)<unsigned32>
					octettotalcount(85)<unsigned64>
					octettotalcount_rev(29305/85)<unsigned64>
					packettotalcount(86)<unsigned64>
					packettotalcount_rev(29305/86)<unsigned64>
					rollable(13745/5000)<unsigned8>{agg:max}',
			);
	} elsif ($arg{flowCache} == 107) {
		%cfg =
			(
			 'columnCount'	=> 9,
			 'id' 					=> 'rfc5610',
			 'name' 				=> 'Options: RFC5610',
			 'columns' 			=> '
					privateenterprisenumber(346)<unsigned32>{scope}
					informationelementid(303)<unsigned16>{scope}
					informationelementdatatype(339)<unsigned8>
					informationelementdescription(340)<string>
					informationelementname(341)<string>
					informationelementrangebegin(342)<unsigned64>
					informationelementrangeend(343)<unsigned64>
					informationelementsemantics(344)<unsigned8>
					informationelementunits(345)<unsigned16>',
			);
	} elsif ($arg{flowCache} == 108) {
		%cfg =
			(
			 'columnCount'	=> 2,
			 'id'						=> 'rfc3164Facility',
			 'name' 				=> 'Options: RFC3164 (facility)',
			 'columns' 			=> '
					syslogfacility(13745/5024)<unsigned32>{scope}
					syslogfacilityname(13745/5028)<string>',
			);
	} elsif ($arg{flowCache} == 109) {
		%cfg =
			(
			 'columnCount'	=> 2,
			 'id' 					=> 'rfc3164Severity',
			 'name'					=> 'Options: RFC3164 (severity)',
			 'columns' 			=> '
					syslogseverity(13745/5023)<unsigned32>{scope}
					syslogseverityname(13745/5027)<string>',
			);
	} elsif ($arg{flowCache} == 110) {
		%cfg =
			(
			 'columnCount'	=> 2,
			 'id' 					=> 'oLoginState',
			 'name'					=> 'Options: Login States',
			 'columns' 			=> '
					ipfixifyloginstate(13745/3023)<unsigned8>{scope}
					ipfixifyloginstatename(13745/3026)<string>',
			);
	} elsif ($arg{flowCache} == 111) {
		%cfg =
			(
			 'columnCount'	=> 2,
			 'id' 					=> 'oLoginType',
			 'name'					=> 'Options: Login Types',
			 'columns' 			=> '
					ipfixifylogintype(13745/3024)<unsigned8>{scope}
					ipfixifylogintypename(13745/3027)<string>',
			);
	} elsif ($arg{flowCache} == 112) {
		%cfg =
			(
			 'columnCount'	=> 2,
			 'id' 					=> 'oNetstat',
			 'name'					=> 'Options: Netstat States',
			 'columns' 			=> '
					ipfixifynetstatstate(13745/3022)<unsigned8>{scope}
					ipfixifynetstatstatename(13745/3028)<string>',
			);
	} elsif ($arg{flowCache} == 113) {
		%cfg =
			(
			 'columnCount'	=> 4,
			 'id'						=> 'oEpIfStats',
			 'name' 				=> 'Options: Endpoint Interfaces',
			 'columns' 			=> '
					ipfixifymachineid(13745/3030)<string>[32]{scope}
					ingressinterface(10)<unsigned32>
					interfacename(82)<string>{scope}
					ipfixifyifspeed(13745/3029)<unsigned64>',
			);
	} elsif ($arg{flowCache} == 114) {
		%cfg =
			(
			 'columnCount'	=> 10,
			 'id'						=> 'oEpIdentity',
			 'name' 				=> 'Options: Endpoint Identity',
			 'columns' 			=> '
					exporteripv4address(130)<ipv4Address>{xform:a2b_na}
					originalexporteripv4address(403)<ipv4Address>{xform:a2b_na}
					ipfixifymachineid(13745/3030)<string>[32]{scope}
					ipfixifymachinename(13745/3002)<string>[255]
					ipfixifyosname(13745/3031)<string>
					ipfixifyosversion(13745/3032)<string>
					ipfixifysystemmanufacturer(13745/3033)<string>
					ipfixifysystemtype(13745/3034)<string>
					ipfixifylatitude(13745/3035)<string>
					ipfixifylongitude(13745/3036)<string>'
			);
	}

	$cfg{columns} =~ s/\t//ig;
	$cfg{delimiter}  //= ':-:';
	$cfg{flows}      //= {};
	$cfg{originator} //= '';

	return %cfg;
}

#####################################################################

=pod

=head1 BUGS AND CAVEATS

None at this time

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 - 2017 Plixer, MIT License
Visit https://github.com/plixer/ipfixify for wiki and source

=head1 AUTHOR

Marc Bilodeau L<mailto:marc@plixer.com>

=cut

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
