use 5.008;
use inc::Module::Install;

BEGIN {
    eval {
        require ModPerl::MM;
        require Apache::TestMM;
    };
    if ($@) {
        exit 0;
    }
    Apache::TestMM->import( qw( test clean ) );
}

name 'Apache2-AuthHatena';
all_from 'lib/Apache2/AuthHatena.pm';
requires Test::More => 0.32;
requires mod_perl2 => 2.000001;
requires Class::Accessor::Fast => 0;
requires Class::ErrorHandler => 0;
requires Hatena::API::Auth => 0.04;
requires LWP::UserAgent => 0;
requires JSON::Syck => 0;
requires CGI => 0;
requires Digest::MD5 => 0;
requires Time::Piece => 0;

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteAll;
