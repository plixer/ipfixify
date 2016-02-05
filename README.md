# IPFIXify

## What is IPFIXify?

IPFIXify reads ordinary text based log files, receives syslogs, parses
Windows EventLogs, collects System Metrics, and more. Once collected,
IPFIXify uses the IPFIX Protocol to send flows to an IPFIX Collector.

A firm understanding of PENs, templates, elements, flows, option
templates, and data templates will be required to take full advantage
of IPFIXify.

For more information on the IPFIX Protocol, visit
[here](https://en.wikipedia.org/wiki/IP_Flow_Information_Export)

It is highly recommended that if you decide to build your own
configurations, that you acquire a PEN (Private Enterprise Number).

The application can be found at
[here](http://pen.iana.org/pen/PenApplication.page).

the examples/ directory includes a list of usable configuration files
for different modes of IPFIXify. Its a great place to start to learn
more about how IPFIXify works.

However, if you use custom elements with your PEN, most IPFIX
Collectors receiving data from IPFIXify will likely require support
for IPFIX elements outside the [standard
elements](http://www.iana.org/assignments/ipfix/ipfix.xhtml). Please
contact the vendor of the IPFIX collector for more information.

If you need an IPFIX Collector to experiment with or use in
production, visit [plixer](https://www.plixer.com) and download
[Scrutinizer](https://www.plixer.com/Scrutinizer-Netflow-Sflow/scrutinizer.html).

IPFIXify is an application orginally conceived and developed since
2012 by Plixer International, Inc. that has since been released as
open source to the community.

## Getting Started

After embarking on your crash course in IPFIX, getting started
requires 3 components.

#### The Agent

The Agent is this repo. It interprets the configuration file,
determines how to ingest data, converts it to IPFIX, and exports the
data to the IPFIX Collector.

Executing just the agent with no parameters will display the available
options.

#### Configuration File

Although the configuration file can have any name, ipfixify.cfg is
traditionally used. Depending on the mode in which the agent will run,
there may be different options available. The example/ directory
contains different configurations for different modes.

There are some basic elements such as where to send the data
(i.e. IPFIX Collector(s)), mode options, and what elements will be
used to represent the data.

The configuration file is referenced via the agent's --config option.

#### The Collector

There are many IPFIX Collectors on the market ranging in size and
capacity. The collector will receive the flows and store them so
meaningful analysis can be done.

If you need an IPFIX Collector for experimenting or use in production,
visit [plixer](https://www.plixer.com) and download
[Scrutinizer](https://www.plixer.com/Scrutinizer-Netflow-Sflow/scrutinizer.html).

## Compiling IPFIXify

IPFIXify does not have to be compiled into binary format to be
usable. It can be executed using the perl interpreter. Generally,
IPFIXify has been distributed in binary form with [Plixer's
Scrutinizer Incident Response
System](https://www.plixer.com/Scrutinizer-Netflow-Sflow/scrutinizer.html).

A Perl Packager will be required to compile IPFIXify. There are a
number of Perl Packagers available. However, the one we chose to use
is [ActiveStates Perl Development
Kit](http://www.activestate.com/perl-dev-kit).

Included in the repo is a build.bat (for windows) and a build.sh (for
linux) to create the desired binary.

If you wish to run IPFIXify as a service or daemon on start-up, it is
recommended to compile IPFIXify into a binary.

## Thank you!

Plixer would like to thank everyone who has helped shaped our products
and this project into the awesome platform it is today. Happy
IPFIXifying!
