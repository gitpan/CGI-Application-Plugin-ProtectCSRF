use Test::More tests => 1;
use lib qw(./t/lib);
use CSRFApp::CSRFError;

$ENV{CGI_APP_RETURN_ONLY} = 1;

my $output = CSRFApp::CSRFError->new->run;
like($output, qr/<h1>your access is csrf!<\/h1>/, "csrf error message");

