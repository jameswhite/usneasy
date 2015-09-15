#!/usr/bin/env perl
use strict;
use AptPkg::Cache;
use Data::Dumper;
use Dpkg::Version;
use FileHandle;
use JSON;

(my $self = $0) =~ s#.*/##;

my $cache = AptPkg::Cache->new;
my $policy = $cache->policy;
my $verbose = 0;

my $fh = FileHandle->new;
my $json_text;
if ($fh->open("< ".$ARGV[0])) {
  while(my $line=<$fh>){
    $json_text = $json_text.$line;
  }
  $fh->close;
}

my $perl_scalar = decode_json( $json_text );
foreach my $pkg (sort(keys(%{ $perl_scalar->{'vulnerable_packages'} }))){
  my $p = $cache->{$pkg};
  unless($p){
    warn "$self: don't know anything about package `$pkg'\n" unless($pkg=~m/(libexpat1-udeb|linux-image-.*-(lpae|pae|omap|omap4|powerpc(64)*-smp|highbank))/);
    next;
  }
  if($p->{'CurrentState'} eq "Installed"){
    print "$pkg [$p->{CurrentVer}{VerStr}]\n";
    my $cves = '';
    foreach my $vuln_pkg_ver (keys(%{ $perl_scalar->{'vulnerable_packages'}->{$pkg} })){
      # print "comparing ".$p->{CurrentVer}{VerStr}." with ".$vuln_pkg_ver."\n";
      my $installed  = Dpkg::Version->new($p->{CurrentVer}{VerStr});
      # print $p->{CurrentVer}{VerStr};  $installed->is_valid? print " valid.\n":print " invalid.\n";
      my $vulnerable = Dpkg::Version->new($vuln_pkg_ver);
      # print $vuln_pkg_ver;  $vulnerable->is_valid? print " valid.\n":print " invalid.\n";
      foreach my $index (@{$perl_scalar->{'vulnerable_packages'}->{$pkg}->{$vuln_pkg_ver}}){
        $cves.=" ".join(", ",@{$perl_scalar->{'security_notices'}->[$index]->{'CVEs'} });
      }
      print "    vulnerable to  [$cves ] ( <= ".$vulnerable->as_string ." )\n" if($installed <= $vulnerable);
    }
  }else{
    print "$pkg [$p->{'CurrentState'}]\n" if $verbose;
  }

}

