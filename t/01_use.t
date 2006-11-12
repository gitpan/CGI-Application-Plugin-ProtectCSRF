use strict;

package TestApp;
use base qw(CGI::Application);
use CGI::Application::Plugin::Session;
use Test::More tests => 1;
use_ok("CGI::Application::Plugin::ProtectCSRF");
