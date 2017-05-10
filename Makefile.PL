#!perl

use 5.008008;
use ExtUtils::MakeMaker;

WriteMakefile
    (
     NAME        => 'Plixer::IPFIXify',
     PREREQ_PM   => { },
     ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (
       AUTHOR    => 'Plixer (www.plixer.com)') : ()
     ),
    );

package MY;

sub postamble {
    my ($copy_rule, $trim, $compiler, $majorVersion, $betaAplha);
    my (@svn);

    $copy_rule = qq{\$(NOECHO) \$(NOOP)};
    #$trim = '--trim '.join (' --trim ', qw ());

    for my $src (<app_src/*.pl>) {
		my $target = $src;
		$target =~ s#app_src/(.*)\.pl#$1#g;
		my $exe = $src;
		$exe = "bin/${target}.exe";
		$compiler = $^O eq 'MSWin32' ? 'perlsvc' : 'perlapp';

		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
		  localtime();

		my $buildTime = localtime();

		$year-=100;
		$mon++;

		$majorVersion = "$year.$mon.$mday";
		$betaAlpha = '';

		my $spinNumber = ""; # ".$hour$min$sec";
		open (my $ver_fh, ">version.info");
		print $ver_fh qq {
\$productBuild = '$buildTime';
\$productName = 'IPFIXify (TM) v${majorVersion}${spinNumber} $betaAlpha';
\$author = 'Business Aware, Network Secure (TM)';
\$website = 'Need an IPFIX Collector? Download Scrutinizer at http://www.plixer.com';
};
		close($ver_fh);

		$targets .= qq {
$target :: $exe
\t\$(NOECHO) \$(NOOP)

$exe :: \$(FIRST_MAKEFILE) pm_to_blib $src
\t\$(NOECHO) \$(NOOP)
\t$compiler $src --force --add Params::Validate::XS --bind EventLogParser.dll[file=./EventLogParser.dll,extract] --bind version.info[text,extract,0444] --nodyndll --blib lib -icon misc/scrutinizer.ico --exe $exe -info ProductName=IPFIXify;FileVersion=${majorVersion}
		};
	}

	return $targets;
}

sub top_targets {
	my $inherited = shift->SUPER::top_targets(@_);
 	my @t;

	if ( system('perlapp', '--version') == 0 ) {
		for my $file (<app_src/*.pl>) {
			$file =~ s#app_src/(.*)\.pl#$1#g;
			$inherited =~ s/(\npure_all\s+::.+)/$1 $file/;
			push @t, $file;
		}
	}

	my $nt = join(' ', map { 'copy_'.$_ } (@t));
	$inherited .= qq{copy :: $nt\t\$(NOECHO) \$(NOOP)};
	return $inherited;
}

1;


# Local Variables: ***
# mode:CPerl ***
# cperl-indent-level:4 ***
# perl-indent-level:4 ***
# tab-width: 4 ***
# indent-tabs-mode: t ***
# End: ***
#
# vim: ts=4 sw=4 noexpandtab
