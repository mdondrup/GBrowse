package Bio::Graphics::Browser2::Plugin::SAMLAuthenticator;
# $Id$
use strict;
use warnings;
use Net::SAML;
use CGI qw (:standard);
use URI::Escape;
use Data::Dumper;
use base 'Bio::Graphics::Browser2::Plugin::AuthPlugin';


use constant DEBUG => 1;

=pod

=head1 SAML 2 Authetication PlugIn for GBrowse 

=head2 Warning! This is experimental!

This plugin requires some modifications in the GBrose core modules. It doesn't work with the 
original version.

=head2 Requirements

=over 4

=item

"L<Net::SAML>" perl module

=item

An SAML2 Identity provider. This module has been tested using SimpleSAMLphp "L<http://simplesamlphp.org/>" (and this is recommended for ease of use), 
but should (in theory) work with any SAML2.0 compatible IdP.

=item 

Metadata of the  SP (Service Provider) must be imported in the IdP before it can be accessed by the PlugIn. The I<samlmeta> cgi-script
can be used to generate metadata.

=back

=head2 USAGE

To use this module, add the following line into the C<[General]> stanza of Gbrowse.conf:

C<authentication plugin = SAMLAuthenticator>

At the end of Gbrowse.conf, add a configuration stanza for the plugin:

 [SAMLAuthenticator:plugin]
 idp = http://localhost:8888/simplesaml/saml2/idp/metadata.php
 mandatory role = gbrowse

=over 4

=item 

The I<idp> configuration entry specifies the URL for the metadata of the SAML Identity Provider

=item

The I<mandatory role> entry specifies an optional affiliations that a user must have to 
be allowed to login to the resource.

=back

=head2 ToDo

Watch out for the following ToDo items in the code:

=over 4

=item
 
ICICIC: Immediately change

=item 

UGLY: 

=item 

QUESTION: I need additional information to do it right

=item 

SAMLMOD: Modifications made to the core modules

=back

=head2 AUTHOR

michael.dondrup <at> ii.uib.no

=cut


sub authenticate {
 my ($self, $samlart) = @_;

 my $idp = $self->setting('idp');
 my $mandatoryRole = $self->setting('mandatory role');
 ## IdP is required in the configuration file
 die "missing IDP" unless $idp;
 my $url = $self->setting('url') || url(-path_info=>1);
 warn "URL: $url" if DEBUG;
 warn "mandatory Role: $mandatoryRole" if DEBUG;
 # die "missing role" unless $mandatoryRole; # shouldn't require a role
 return _doSSO($samlart, $idp, $url, $mandatoryRole);
}

sub authentication_hint {

  return "SAML Authentication"
}

### SAML authentication needs to send http redirect to the IdP's address
### This is only possible, if the plugin gets full controll over the http-header
### If this hook doesn't exist of returns nothing, the normal plugin login should 
### take effect.

sub redirect_header_hook {

  unless (param('action') eq "sso_authenticate") { # avoid redirect loop!
    my $action = "?action=sso_authenticate";
    if (param('SAMLart')) {
      # not sure if uri_escape is necessary here
      # it is required at least once, because Net::SAML doesn't 
      # do it automatically
      $action .= "&SAMLart=".uri_escape(param('SAMLart'));
    }
    
    return ($action)
  }
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
  warn ("SAML SessionId: ",$sid) if DEBUG;
  return (_parse_saml($res, $mandatoryRole), $sid);

}


sub _parse_saml {
  my $saml = shift;
  my $mandatoryRole = shift;
  
  my %roles = map {$_,1} ($saml =~  m/^urn:oid:1\.3\.6\.1\.4\.1\.5923\.1\.1\.1\.1:\s+(.+)$/mg);
  print STDERR join "\t", %roles if DEBUG;
  return undef if ($mandatoryRole && !$roles{$mandatoryRole});

  my ($uid) = $saml =~ m/^urn:oid:0\.9\.2342\.19200300\.100\.1\.1:\s+(.+)$/m;
  return undef unless $uid;

  my ($displayName) = $saml =~ m/^urn:oid:2\.16\.840\.1\.113730\.3\.1\.241:\s+(.+)$/m;
  my ($mail) = $saml =~ m/^urn:oid::\s+(.+)$/m;
  
  return ($uid, $displayName, $mail)
}

sub plugin_logout_hook {
  ## I guess the whole stuff should go into a hook in the authetication module
  ## REFACTOR: create a hook logout_request_hook in SAMLauthenticator plugin.... done
  my $self = shift;
  my $action = shift;
  my $q    = shift;

  my $render    = $action->render;
  my $globals = $render->globals;
  my $session   = $render->session;
  my $sessionid = $session->id;
  my $username  = $session->username;
  my $openid    = $session->using_openid;
  my $qs = $ENV{'QUERY_STRING'};
  my $sid = $session->samlid();

  # Close the GBrowse session, before terminating the master session:
  ## QUESTION: I don't really know how to validly close the authenticated GBrowse session!
  ## What is the correct way of doing this?
  ## ICICIC: that's possibly a loophole
  ## I found that a gbrowse request ?id=logout would close the GBrowse session, however I am not able
  ## to locate and modify the receiver (need to add code for SAML session termination).
  ## Here, I just remove the username
  $session->username("");
 # $session->id("");
  $session->flush();
 # $session->delete();
 # $session->flush();

 # removed hardcoded URL, done
  my $url = $q->url().'/'.$globals->default_source.'/'; # "http://localhost:8888/cgi-bin/gb2/gbrowse/yeast/"
  my $conf = "URL=$url";
  my $cf = Net::SAML::new_conf_to_cf($conf);
  # retrieve SAML session by id
  my $ses = Net::SAML::fetch_ses($cf, $sid); 
  # generate the request to terminate the SAML session
  my $redir =  Net::SAML::sp_slo_redir($cf, -1 ,$ses); 
  # the result is the complete http header, plus some \r characters
  # but we need only the URL, so remove the rest (there seems to be no
  # not function in Net::SAML to receive the URL alone...)
  $redir =~ s/^Location: //;
  $redir =~ s/[\r|\n]//g;
  # return the redirect request
  return  (302, "text/html", $redir);
}
sub plugin_logout_action_hook {
  'action=plugin_logout';
}



1;

### Inject additional ACTION into the action package:
# Having this in the plugin pm only works with the 
# data source that requires this plugin

package Bio::Graphics::Browser2::Action;


#sub ACTION_plugin_logout {
  
  
#}



## This action is based on a copy of plugin_authenticate
## It is meant to take controll over the SAML SSO process
sub ACTION_sso_authenticate {
  my $self = shift;
  my $q    = shift;
  
  my $render = $self->render;
  $render->init_plugins();
  my $plugin = eval{$render->plugins->auth_plugin} 
    or return (204,'text/plain','no authenticator defined');
  my $script = "";
  my $result;
  my $samlart = uri_escape( $q->param("SAMLart"));
  warn ("sso_authenticate called with SAMLart $samlart") if DEBUG;
  my ($username,$fullname,$email, $sid);
    if ( ($username,$fullname,$email, $sid)  = $plugin->authenticate($samlart) ) {
      
      my $session   = $self->session;
      
      $session->unlock;
      $session->samlid($sid);
      $session->flush;     
      ## the SAML session id needs to be stored in the local session,
      ## because it is needed to terminate the SAML session in case of a logout
      warn "samlid: ".$session->samlid()." stored in session\n" if DEBUG;
      # now generate a named session
      #$session->unlock;
      my $userdb = $render->userdb;
      my $id = $userdb->check_or_add_named_session($session->id,$username);
      $userdb->set_fullname_from_username($username=>$fullname,$email) if defined $fullname;
      
      # now authenticate
      my ($sid, $nonce) = $render->authorize_user($username,$id, 1,undef);
      #warn "sid: $sid, nonce:$nonce";
      $session->username($username);
      $session->flush; 
    my $is_authorized = $render->user_authorized_for_source($username);
    if ($is_authorized) {
      #	$session->private(1); 
      ## that doesn't seem to work for me, but the session should be private, or not??? 
      # QUESTION: what exactly does private session mean, and why is incompatible with the SAML SSO approach
      warn "user IS authorized for resource" if DEBUG;
      $result = { userOK  => 1,
		  sessionid => $id,
		  username  => $username,
		  message   => 'login ok',
		 };
      ## generate the javascript call, that will load the account
      ## adding a named session alone isn't sufficient sufficient
      $script =  CGI::script({-type=>'text/javascript'}, 

<<SCRIPT

login_get_account("$username", "$id", true, false);

SCRIPT
);
    

    } else {
      warn "user IS NOT authorized for resource";
      $result = { userOK    => 0,
		  message   => 'You are not authorized to access this data source.'};
      return (200,'application/json',$result);
    }
  } 
  # failed to authenticate
  else {
    warn "user IS NOT authorized AT ALL";
    $result = { userOK   => undef,
		message  => "Invalid name/password"
	      };
    return (200,'application/json',$result);
  }  

## UGLY: Well this is realy ugly, also
# ICICIC: hardcoded URL!
my $html =	 <<HTML
<html>
<head>
<script src="/gbrowse2/js/login.js" type="text/javascript"></script> 

<script src="?action=get_translation_tables;language=en-us" type="text/javascript"></script>
<script src="/gbrowse2/js/prototype.js" type="text/javascript"></script>
<script src="/gbrowse2/js/scriptaculous.js" type="text/javascript"></script>
<script src="/gbrowse2/js/subtracktable.js" type="text/javascript"></script>
<script src="/gbrowse2/js/controls.js" type="text/javascript"></script>
<script src="/gbrowse2/js/autocomplete.js" type="text/javascript"></script>
<script src="/gbrowse2/js/login.js" type="text/javascript"></script>
<script src="/gbrowse2/js/buttons.js" type="text/javascript"></script>
<script src="/gbrowse2/js/trackFavorites.js" type="text/javascript"></script>
<script src="/gbrowse2/js/karyotype.js" type="text/javascript"></script>
<script src="/gbrowse2/js/rubber.js" type="text/javascript"></script>
<script src="/gbrowse2/js/overviewSelect.js" type="text/javascript"></script>
<script src="/gbrowse2/js/detailSelect.js" type="text/javascript"></script>
<script src="/gbrowse2/js/regionSelect.js" type="text/javascript"></script>
<script src="/gbrowse2/js/track.js" type="text/javascript"></script>
<script src="/gbrowse2/js/balloon.js" type="text/javascript"></script>
<script src="/gbrowse2/js/balloon.config.js" type="text/javascript"></script>
<script src="/gbrowse2/js/GBox.js" type="text/javascript"></script>
<script src="/gbrowse2/js/ajax_upload.js" type="text/javascript"></script>
<script src="/gbrowse2/js/tabs.js" type="text/javascript"></script>
<script src="/gbrowse2/js/track_configure.js" type="text/javascript"></script>
<script src="/gbrowse2/js/track_pan.js" type="text/javascript"></script>
<script src="/gbrowse2/js/ruler.js" type="text/javascript"></script>
<script src="/gbrowse2/js/controller.js" type="text/javascript"></script>
<script src="/gbrowse2/js/snapshotManager.js" type="text/javascript"></script>

 
</head>
<body> \n
$script
<p>


You will be redirected to GBrowse, if that doesn't happen automatically, <a href="http://localhost:8888/cgi-bin/gb2/gbrowse/yeast/">click here</a>
</p>
</body>
</html>
)
HTML
;

return  (200, "text/html", $html); 

	
   

# return (200,'application/json',$result);


}

1;



__END__
