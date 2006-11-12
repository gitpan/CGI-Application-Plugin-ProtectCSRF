use strict;
use Test::More tests => 1;

package TestApp;
use base qw(CGI::Application);
use CGI::Application::Plugin::Session;
use CGI::Application::Plugin::ProtectCSRF;

package main;

my $app = TestApp->new;
can_ok($app, qw(clear_csrfid is_post_request));


