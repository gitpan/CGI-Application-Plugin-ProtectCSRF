package CGI::Application::Plugin::ProtectCSRF;

=pod

=head1 NAME

CGI::Application::Plugin::ProtectCSRF - Plug-in protected from CSRF

=head1 VERSION

0.01

=head1 SYSNPSIS

  use Your::App;
  use CGI::Application::Plugin::Session; # require!!
  use CGI::Application::Plugin::ProtectCSRF;

=head1 DESCRIPTION

CGI::Application::Plugin::ProtectCSRF is C::A::P protected from CSRF.

When CSRF is detected, 403 Forbidden is returned and processing is interrupted.

=cut

use strict;
use base qw(Exporter);
use Carp;
use Digest::SHA1;
use HTML::TokeParser;
use List::Util qw(shuffle);

our(
    @EXPORT,
    $CSRFID,
    $FORBIDDEN_BODY,
    $FORBIDDEN_CODE,
    $FORBIDDEN_MODE,
    $VERSION
);

@EXPORT         = qw(clear_csrfid is_post_request);
$CSRFID         = "_csrfid";
$FORBIDDEN_CODE = 403;
$FORBIDDEN_BODY = <<FORBIDDEN;
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>$FORBIDDEN_CODE Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access on this server.</p>
</body></html>
FORBIDDEN
$FORBIDDEN_MODE = "_access_403_forbidden";
$VERSION        = 0.01;

sub import {

    my $pkg = caller;

# C::A::P::Session method check
    croak("C::A::P::Session module is not load to your app") if !$pkg->can("session");

    $pkg->add_callback("prerun",  \&_create_csrfid);
    $pkg->add_callback("prerun",  \&_csrf_forbidden);
    $pkg->add_callback("postrun", \&_add_csrfid);

    goto &Exporter::import;
}


=pod

=head1 METHOD

=head2 clear_csrfid

Clear csrfid. It is preferable to make it execute after processing ends.

Input screen => confirmation screen => completion screen(here!!)

Example : 

  sub input {
    my $self = shift;
    ....
  }
  
  sub confirm {
    my $self = shift;
    ....
  }

  sub complete {
    my $self = shift;
    ...process start(DB insert etc..)
    $self->clear_csrfid;
    ....
  }

=cut

sub clear_csrfid {

    my($self, $fast) = @_;
    $self->session->clear($CSRFID);
    $self->session->flush if $fast;
}

=pod

=head2 is_post_request

Check request method.If request method is POST, 1 is returned. 

Example : 

  my $post_flag;
  if($self->is_post_request){
     # $self->query->request_method or $ENV{REQUEST_METHOD} is POST
  }else{
     # not POST
  }

=cut

sub is_post_request {

    my $self = shift;
    return ($self->query->request_method eq "POST") ? 1 : 0;
}

# ============================================================= #
# =================== add_callback "prerun" =================== #
# ============================================================= #
sub _create_csrfid {

    my $self = shift;

    if(!$self->session->param($CSRFID)){

        my $rnd_str = join "", shuffle(split //, $self->session->id);
        my $sha1 = Digest::SHA1->new;
        $sha1->add($rnd_str);
        $self->session->param($CSRFID, $sha1->hexdigest);
    }
}


# ============================================================= #
# =================== add_callback "prerun" =================== #
# ============================================================= #
sub _csrf_forbidden {

    my($self, $rm) = @_;

# request method : POST only
    if($self->is_post_request){

        if(
            !$self->query->param($CSRFID)    || 
            !$self->session->param($CSRFID)  ||
            $self->query->param($CSRFID) ne $self->session->param($CSRFID)
        ){

            $self->run_modes( $FORBIDDEN_MODE => sub {
               
                my $self = shift;
                $self->header_props(
                                -type   => "text/html",
                                -status => $FORBIDDEN_CODE,
                                );
                return $FORBIDDEN_BODY;
            });
            $self->prerun_mode($FORBIDDEN_MODE);
        }
    }
    return 0;
}


# ============================================================= #
# ================== add_callback "postrun" =================== #
# ============================================================= #
sub _add_csrfid {

    my($self, $scalarref) = @_;

# text/html is target
    my %header = $self->header_props;

#    return if %header && $header{-type} ne "text/html";

    my $body = undef;
    my $hidden = sprintf "<input type=\"hidden\" name=\"%s\" value=\"%s\" />", $CSRFID, $self->session->param($CSRFID);

    my $parser = HTML::TokeParser->new($scalarref);
    while(my $token = $parser->get_token){

# start tag(<form> sniping)
        if($token->[0] eq "S"){
            
            if(lc($token->[1]) eq "form"){
                $body .= $token->[4] . "\n" . $hidden;
            }else{
                $body .= $token->[4];
            }

# end tag, process instructions
        }elsif($token->[0] =~ /^(E|PI)$/){
            $body .= $token->[2];
            
# text, comment, declaration
        }elsif($token->[0] =~ /^(T|C|D)$/){
            $body .= $token->[1];
        }
    }

    ${$scalarref} = $body;
}

1;

__END__

=head1 CAUTION

It has only the protection function of basic CSRF,and mount other security checks in the application, please.

=head1 SEE ALSO

L<Carp> L<CGI::Application> L<Exporter> L<Digest::SHA1> L<HTML::TokeParser> L<List::Util>

=head1 AUTHOR

Akira Horimoto <kurt0027@gmail.com>

=head1 COPYRIGHT

Copyright (C) 2006 Akira Horimoto

This module is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut



