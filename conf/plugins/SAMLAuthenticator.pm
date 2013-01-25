package Bio::Graphics::Browser2::Plugin::SAMLAuthenticator;
# $Id$
use strict;
use warnings;
use Net::SAML;
use CGI qw (:standard);
use URI::Escape;
use Data::Dumper;
use base 'Bio::Graphics::Browser2::Plugin::AuthPlugin';

$| = 1;

use constant NO_HEADER => 1;

sub authenticate {
 my ($self, $samlart) = @_;



 my $idp = $self->setting('idp');
 my $mandatoryRole = $self->setting('mandatory role');
 die "missing IDP" unless $idp;
 my $url = $self->setting('url') || url(-path_info=>1);
 warn "URL: $url";
 warn "mandatory Role: $mandatoryRole";
 die "missing role" unless $mandatoryRole;
 return _doSSO($samlart, $idp, $url, $mandatoryRole);
}

sub authentication_hint {

  return "Acme Corp Single Sign-on"
}

sub configure_form {
}


sub _doSSO {
  my $samlart = shift;
  my $idp = uri_escape(shift);

  my $q = new CGI;
  my $url = shift;  # Edit to match your situation
  my $mandatoryRole = shift;
  my $conf = "URL=$url&";
  my $cf = Net::SAML::new_conf_to_cf($conf);
  
 
    my $qs = "";
  if ($samlart) {
    $qs = "SAMLart=$samlart";
  } else {
    $qs = $ENV{'QUERY_STRING'};
    $qs = <STDIN> if $qs =~ /o=P/;
    
    $qs .= "&e=$idp&l0=TRUE"
      unless ($qs =~ /s=|(SAMLart=)|o=B/);
  }
  
  #print STDERR "QS1: $qs\n";
  #  return;
  my $res = Net::SAML::simple_cf($cf, -1, $qs, undef, 0x1828); # keep the flags 0x1828 !!!
  #print STDERR "QS2: ",$ENV{'QUERY_STRING'},"\n";
#  print STDERR "RESULT: $res\n";
  my $op = substr($res, 0, 1);
 # print STDERR "OP: $op\n";
 # open TMP, ">>/tmp/samlout.xml" or die $!;
 # print  TMP "=======SAML=========\n$res\n=======END=SAML===========\n";
 # close TMP;
  if ($op eq 'L' || $op eq 'C') { 
   
    print $res; return; } # LOCATION (Redir) or CONTENT
 # if ($op eq 'n') { exit; } # already handled
 # if ($op eq 'e') { exit; } # not logged in, should render select screen
  if ($op ne 'd') { die "Unknown Net::SAML::simple() res($res)"; }
 # $op == d means logged in
  my ($sid) = $res =~ /^sesid: (.*)$/m;  # Extract a useful attribute from SSO output
  warn ("SAML SessionId: ",$sid);
  return (_parse_saml($res, $mandatoryRole), $sid);

}


sub _parse_saml {
  my $saml = shift;
  my $mandatoryRole = shift;
  
  my %roles = map {$_,1} ($saml =~  m/^urn:oid:1\.3\.6\.1\.4\.1\.5923\.1\.1\.1\.1:\s+(.+)$/mg);
  print STDERR join "\t", %roles;
  return undef if ($mandatoryRole && !$roles{$mandatoryRole});

  my ($uid) = $saml =~ m/^urn:oid:0\.9\.2342\.19200300\.100\.1\.1:\s+(.+)$/m;
  return undef unless $uid;

  my ($displayName) = $saml =~ m/^urn:oid:2\.16\.840\.1\.113730\.3\.1\.241:\s+(.+)$/m;
  my ($mail) = $saml =~ m/^urn:oid::\s+(.+)$/m;
  
  return ($uid, $displayName, $mail)
}


1;

__END__
