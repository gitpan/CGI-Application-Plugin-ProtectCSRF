use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'CGI::Application::Plugin::ProtectCSRF',
    VERSION_FROM      => 'ProtectCSRF.pm', # finds $VERSION
    PREREQ_PM         => {
			"CGI::Application" => 4.04,
                        "CGI::Application::Plugin::Session" => 1.01,
                        "Digest::SHA1" => 2.07,
                        "List::Util" => 1.18,
			}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'ProtectCSRF.pm', # retrieve abstract from module
       AUTHOR         => 'Akira Horimoto <kurt0027@gmail.com>') : ()),
);
