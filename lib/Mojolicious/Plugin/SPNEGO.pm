package Mojolicious::Plugin::SPNEGO;
use Mojo::Base 'Mojolicious::Plugin';
use Net::LDAP::SPNEGO;

our $VERSION = '0.1.0';

my %cCache;

sub register {
    my $self = shift;
    my $app = shift;
    my $cfg = shift || {};
    $app->helper(
        ntlm_auth => sub {
            my $c = shift;
            my $cId = $c->tx->connection;
            my $cCache = $cCache{$cId} //= { status => 'init' };
            return if $cCache->{status} eq 'authenticated';

            my $authorization = $c->req->headers->header('Authorization') // '';
            my ($AuthBase64) = ($authorization =~ /^NTLM\s(.+)$/);
            for ($AuthBase64 and $cCache->{status} =~ /^expect(Type\d)/){
                my $ldap = $cCache->{ldapObj} //= Net::LDAP::SPNEGO->new($cg->{ad_server},debug=>$cfg->{ldap_debug});
                /^Type1/ && do {
                    my $mesg = $ldap->bind_type1($AuthBase64);
                    if ($mesg->{ntlm_type2_base64}){
                        $c->res->headers->header( 'WWW-Authenticate' => 'NTLM '.$mesg->{ntlm_type2_base64});
                        $c->render( text => 'Waiting for Type3 NTLM Token', status => 401);
                        $cCache->{status} = 'expectType3';
                        return 0;
                    }
                    # lets try with a new connection
                    $ldap->unbind;
                    delete $cCache->{ldapObj};
                };
                /^Type3/ && do {
                    my $mesg = $ldap->bind_type3($AuthBase64);
                    if (my $user = $mesg->{ldap_user_entry}){
                        if (my $cb = $cfg->{auth_success_callback}){
                            if (not $cb or $cb->($c,$user,$ldap)){
                                $cCache->{status} = 'authenticated';
                            }
                        }
                    }
                    $ldap->unbind;
                    delete $cCache->{ldapObj};
                    return  $cCache->{status} eq 'authenticated';
                };
            }
            $c->res->headers->header( 'WWW-Authenticate' => 'NTLM' );
            $c->render( text => 'Waiting for Type 1 NTLM Token', status => 401 );
            $cCache->{status} = 'expectType1';
            return 0;
        }
    );
}

1;

__END__

=head1 Mojolicious::Plugin::SPNEGO

use Mojolicious::Lite;

 my $SERVER = $ENV{AD_SERVER} // die "AD_SERVER env variable not set";

 app->secrets(['My secret passphrase here']);

 plugin 'SPNEGO';

 get '/' => sub {
    my $c = shift;
    if (not $c->session('user')){
        $c->ntlm_auth({
            ad_server => $SERVER,
            auth_success_callback => sub {
                my $c = shift;
                my $user = shift;
                my $ldap = shift; # bound Net::LDAP::SPNEGO connection
                $c->session('user',$user->{samaccountname});
                $c->session('name',$user->{displayname});
                my $groups = $ldap->get_ad_groups($user->{samaccountname});
                $c->session('groups',[ sort keys %$groups]);
                return 1;
            }
        }) or return;
    }
 } => 'index';

 app->start;

 __DATA__

 @@ index.html.ep
 <!DOCTYPE html>
 <html>
 <head>
 <title>NTLM Auth Test</title>
 </head>
 <body>
 <h1>Hello <%= session 'name' %></h1>
 <div>Your account '<%= session 'user' %>' belongs to the following groups:</div>
 <ul>
 % for my $group (@{session 'groups' }) {
    <li>'<%= $group %>'</li>
 % }
 </ul>
 </body>
 </html>

=head1 DESCRIPTION

The Mojolicious::Plugin::SPNEGO lets you provide NTLM SSO by using an
active directory server as authentication provider. The plugin uses
the L<Net::LDAP::SPNEGO> module.

The plugin provides the following helpers:

=head2 $c->ntlm_auth({ad_server => $AD_SERVER[, auth_success_callback=> $cb ])

Initiate an NTLM authentication dialog with the browser by forwarding the
tokens coming from the browser to the ad server specified in the I<ad_server>
argument.

If a callback is specified it will be executed once the ntlm dialog
has completed successfully. Depending on the return value of the
callback the entire process will be considered successfull or not.

Since ntlm authentication is reather complex, you may want to save
authentication success in a cookie.

=head1 AUTHOR

S<Tobias Oetiker, E<lt>tobi@oetiker.chE<gt>>

=head1 COPYRIGHT

Copyright OETIKER+PARTNER AG 2016

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
