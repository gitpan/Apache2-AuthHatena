use 5.008;
use ExtUtils::MakeMaker;


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Apache2::AuthHatena',
    VERSION_FROM      => 'lib/Apache2/AuthHatena.pm', # finds $VERSION
    PREREQ_PM         => {
        mod_perl2 => 2.000001,
        Class::Accessor::Fast => 0,
        Class::ErrorHandler => 0,
        Hatena::API::Auth => 0.04,
        LWP::UserAgent => 0,
        JSON::Syck => 0,
        CGI => 0,
        Digest::MD5 => 0,
        Time::Piece => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Apache2/AuthHatena.pm', # retrieve abstract from module
       AUTHOR         => 'Nobuo Danjou <danjou@hatena.ne.jp>') : ()),
);
