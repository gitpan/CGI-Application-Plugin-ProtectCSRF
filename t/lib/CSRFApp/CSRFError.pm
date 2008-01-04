package CSRFApp::CSRFError;

use base qw(CSRFApp::Base);
use strict;
use warnings;

sub index : ProtectCSRF {
    my $self = shift;
    return "index";
}

sub finish {  
    my $self = shift;
    return "finish";
}

1;

