package Apache2::AuthHatena;
use strict;
use warnings;
use Apache2::RequestRec ();
use Apache2::ServerUtil ();
use Apache2::RequestIO ();
use Apache2::RequestUtil ();
use Apache2::Log ();
use Apache2::Access ();
use Apache2::Module ();
use Apache2::CmdParms ();
use Apache2::Const -compile => qw(
    FORBIDDEN OK DECLINED REDIRECT OR_AUTHCFG TAKE1
);
use APR::Table ();
use CGI;
use CGI::Cookie;
use Digest::MD5;
use Time::Piece;
use Hatena::API::Auth;

our $VERSION = '0.03';

my @directives = (
    {
        name => 'HatenaAuthKey',
        func => __PACKAGE__ . '::HatenaAuthKey',
        req_override => Apache2::Const::OR_AUTHCFG,
        args_how     => Apache2::Const::TAKE1,
        errmsg       => 'HatenaAuthKey yourkey',
    },
    {
        name => 'HatenaAuthSecret',
        func => __PACKAGE__ . '::HatenaAuthSecret',
        req_override => Apache2::Const::OR_AUTHCFG,
        args_how     => Apache2::Const::TAKE1,
        errmsg       => 'HatenaAuthSecret yoursecretkey',
    },
    {
        name => 'HatenaAuthCallback',
        func => __PACKAGE__ . '::HatenaAuthCallback',
        req_override => Apache2::Const::OR_AUTHCFG,
        args_how     => Apache2::Const::TAKE1,
        errmsg       => 'HatenaAuthCallback http://sample.com/yourcallback',
    },
    {
        name => 'AuthType',
        func => __PACKAGE__ . '::AuthType',
        req_override => Apache2::Const::OR_AUTHCFG,
        args_how     => Apache2::Const::TAKE1,
        errmsg       => 'AuthType Hatena',
    },
);

eval { Apache2::Module::add(__PACKAGE__, \@directives); };

sub HatenaAuthKey {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config( __PACKAGE__, $params->server);
    $i->{'api_key'} = $arg;
}

sub HatenaAuthSecret {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config( __PACKAGE__, $params->server);
    $i->{'secret'} = $arg;
}
sub HatenaAuthCallback {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config( __PACKAGE__, $params->server);
    $i->{'callback'} = $arg;
}

sub AuthType {
    my ($i, $params, $arg) = @_;
    if ($arg eq 'Hatena') {
        Apache2::ServerUtil->server->push_handlers(PerlAuthenHandler => \&authen_handler);
    }
}

sub authen_handler {
    my $r = shift;
    $r->auth_type ne 'Hatena' and return Apache2::Const::DECLINED;
    my $realm = $r->auth_name;
    # $r->no-cache(1);
    $r->err_headers_out->set('Pragma' => 'no-cache');
    $r->err_headers_out->set('Cache-control' => 'private, no-cache, no-store, must-revalidate, max-age=0');
    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);
    my $secret = $cf->{'secret'};
    my $callback = $cf->{'callback'};
    my $request_url = "http://".($r->hostname || '').($r->uri || '');
    my $request_url_forwarded = "http://".($r->headers_in->{'X-Forwarded-Host'} || '').($r->uri || '');
    if ($request_url eq $callback || $request_url_forwarded eq $callback) {
        $r->set_handlers(PerlAuthzHandler => \&authz_handler_bypass);
        $r->handler('modperl');
        if ($r->args eq 'logout') {
            $r->set_handlers(PerlResponseHandler => \&logout);
            return Apache2::Const::OK;
        } elsif ($r->args eq 'about') {
            $r->set_handlers(PerlResponseHandler => \&about);
            return Apache2::Const::OK;
        }
        return &callback($r);
    }
    my %cookie = CGI::Cookie->parse($r->headers_in->{Cookie});
    unless (%cookie && $cookie{"Apache2-AuthHatena_$realm"}) {
        return &process_forbidden( $r, 'no cookies');
    }
    my ($name, $token, $time) = $cookie{"Apache2-AuthHatena_$realm"}->value;
    if (!$time || $time < time()) {
        return &process_forbidden( $r, "id:$name, cookie is too old");
    }
    if (Digest::MD5::md5_hex($name,$secret.$time) ne $token) {
        return &process_forbidden( $r, "d:$name, token is broken");
    }
    $r->set_handlers(PerlAuthzHandler => \&authz_handler);
    $r->user($name);
    return Apache2::Const::OK;
}

sub authz_handler {
    my $r = shift;
    $r->auth_type ne 'Hatena' and return Apache2::Const::DECLINED;
    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);
    my $callback = $cf->{callback};
    my $name = $r->user;
    unless ($name) {
        return &process_forbidden( $r, 'no Hatena ID found');
    }
    my %required_users = ();
    my $validuser = 0;
    my $requires = $r->requires;
    for (@{$requires}) {
        if ($_->{requirement} =~ /^user\s+(.+)$/) {
            $required_users{$_} = 1 for (split /\s+/, $1);
        } elsif ($_->{requirement} eq 'valid-user') {
            $validuser = 1;
        }
    }

    if ($validuser) {
        return Apache2::Const::OK;
    }
    unless (exists $required_users{$name}) {
        return &process_forbidden($r, "id:${name}, not permitted");
    }
    return Apache2::Const::OK;
}

sub process_forbidden {
    my ($r, $reason) = @_;
    $r->set_handlers(PerlAuthzHandler => \&authz_handler_bypass);
    $r->handler('modperl');
    $r->set_handlers(PerlResponseHandler => \&forbidden_handler);
    $r->pnotes(reason => $reason);
    return Apache2::Const::OK;
}

sub authz_handler_bypass {
    return Apache2::Const::OK;
}

sub callback {
    my $r = shift;
    my $realm = $r->auth_name;
    my $q = CGI->new($r);
    my $referer = $q->param('r') || $r->headers_in->{Referer} || '';
    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);
    my $api_key = $cf->{api_key};
    my $secret = $cf->{secret};
    my $api= Hatena::API::Auth->new({
        api_key => $api_key,
        secret => $secret,
    });
    if (my $cert = $q->param('cert')) {
        my $user;
        unless ($user = $api->login($cert)) {
            return &process_forbidden($r, 'cert is broken');
        }
        my $name = $user->name;
        $r->user($name);
        my $time = time() + 3600;
        my $expires = gmtime($time)->strftime;
        my $token = Digest::MD5::md5_hex($name.$secret.$time);
        my $cookie = CGI::Cookie->new(
            -name => "Apache2-AuthHatena_$realm",
            -value => [ $name, $token, $time ],
            -expires => $expires
        );
        $r->err_headers_out->set('Set-Cookie' => $cookie);
        if ($referer && $referer !~ m{^http://auth.hatena.ne.jp/auth}) {
            $r->err_headers_out->set(Location => $referer);
            return Apache2::Const::REDIRECT;
        }
        $r->set_handlers(PerlResponseHandler => \&about);
        return Apache2::Const::OK;
    } else {
        my $uri = $api->uri_to_login(r => $referer);
        $r->err_headers_out->add(Location => $uri);
        return Apache2::Const::REDIRECT;
    }
}

sub logout {
    my $r = shift;
    my $realm = $r->auth_name;
    my $cookie = CGI::Cookie->new(
        -name => "Apache2-AuthHatena_$realm",
        -value => 'logout',
        -expires => '-1d',
    );
    $r->err_headers_out->set('Set-Cookie' => $cookie);
    $r->content_type('text/html; charset=UTF-8');
    my $lang = $r->headers_in->{'Accept-Language'} =~ /ja/ ? 'ja' : 'en';
    my $message = '';
    if ($lang eq 'ja') {
        $message = <<END
<p>ログアウトしました. </p>
<ul>
<li><a href=\"./\">インデックス</a>に戻りますか?</li>
<li><a href="http://www.hatena.ne.jp">はてな</a>に行きますか?</li>
</ul>
END
    } else {
        $message = <<END
<p>You've been signed out.</p>
<ul>
<li>Go to <a href="./">index</a>?</li>
<li>Or <a href="http://www.hatena.ne.jp">Hatena</a>?</li>
</ul>
END
    }
    $r->print(&html_message('sign out', $realm, $message, $lang));
    return Apache2::Const::OK;
}

sub about {
    my $r = shift;
    $r->content_type('text/html; charset=UTF-8');
    my $html = &html_message(
        'About Apache2::AuthHatena',
        'Apache2::AuthHatena',
        'A easy way to share fun with your friends.',
        'en'
    );
    $r->print($html);
    return Apache2::Const::OK;
}

sub forbidden_handler {
    my $r = shift;
    my $reason = $r->pnotes('reason');
    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);
    my $callback = $cf->{callback};
    my $name = $r->user;
    my $lang = $r->headers_in->{'Accept-Language'} =~ /ja/ ? 'ja' : 'en';
    my $message = '';
    if ($reason =~ /not permitted/) {
        if ($lang eq 'ja') {
            $message = <<"END";
こんにちは, id:${name}さん! あなたは閲覧許可ユーザーではありません. <br>
もし別のアカウントがあれば、<a href=\"$callback?logout\">ログアウト</a> (はてなからも) してからもう一度お越し下さい.
END
        } else {
            $message = <<"END";
Hi, id:${name}! Sorry, you are not permitted.<br>
If you have other IDs, <a href=\"$callback?logout\">sign out</a> (also from Hatena) and come again!
END
        }
    } else {
        if ($lang eq 'ja') {
            $message = "はてなIDで<a href=\"$callback\">ログイン</a>してください.";
        } else {
            $message = "Please <a href=\"$callback\">sign in</a> with Hatena ID.";
        }
    }
    my $realm = $r->auth_name;
    $r->content_type('text/html; charset=UTF-8');
    $r->print(&html_message('403 Forbidden', $realm, $message, $lang));
    $r->status(Apache2::Const::FORBIDDEN);
    $r->log->info("Apache2::AuthHatena: ${realm}: $reason");
    return Apache2::Const::OK;
}

sub html_message {
    my ($title, $h1, $message, $lang) = @_;
    $lang ||='ja';
    $message =~ /^</ or $message = "<p>$message</p>";
    return <<"EOF";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html lang="ja">
    <head>
        <title>$title</title>
        <meta http-equiv="Content-Style-Type" content="text/css">
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <style type="text/css"><!--
            body {
                color: #666;
                background-color: #fff0f0;
                margin: 100px;
                padding: 20px;
                border: 2px solid #aaa;
                font-family: "Lucida Grande", verdana, sans-serif;
                line-height: 1.5em;
            }
            address {
                text-align: right;
            }
            a {
                color: #000;
                text-decoration: none;
                border-bottom: 2px solid #000;
            }
             --></style>
    </head>
    <body>
        <h1>$h1</h1>
        $message
        <address>powered by <a href="http://search.cpan.org/~danjou/Apache2-AuthHatena/">Apache2::AuthHatena</a></address>
    </body>
</html>
EOF
}

1;
__END__

=head1 NAME

Apache2::AuthHatena - Simple authentication mod_perl module using Hatena Auth API

=head1 SYNOPSIS

  LoadModule perl_module modules/mod_perl.so
  PerlLoadModule Apache2::AuthHatena

  AuthType Hatena
  AuthName "My private documents"
  HatenaAuthKey yourauthkeygoeshere
  HatenaAuthSecret youauthsecretgoeshere
  HatenaAuthCallback http://sample.com/path/to/callback
  require valid-user

=head1 DESCRIPTION

This mod_perl module allows you to implement easy authentication with Hatena Authentication API.
You need Hatena Authentication API key from L<http://auth.hatena.ne.jp>.

Add the folloing lines to you Apache configuration file to load this module:

  LoadModule perl_module modules/mod_perl.so
  PerlLoadModule Apache2::AuthHatena

And then you can write .htaccess file like this:

  AuthType Hatena
  AuthName "My private documents"
  HatenaAuthKey yourauthkeygoeshere
  HatenaAuthSecret youauthsecretgoeshere
  HatenaAuthCallback http://sample.com/path/to/callback
  require valid-user

AuthType must be "hatena", and each of HatenaAuthKey, HatenaAuthSecret, and 
HatenaAuthCallback should be the value you've got from L<http://auth.hatena.ne.jp>.
If you assign 'valid-user' to 'require' directive, it means all people who has
Hatena ID can see the protected documents. When you want to show the document only to,
for example, id:jkondo and id:naoya, you can write like this:

  require user jkondo naoya

=head1 COMPATIBILITY

This module will only work with mod_perl2.  mod_perl1 is not supported.

=head1 SEE ALSO

L<Hatena::API::Auth>
L<http://auth.hatena.ne.jp>

=head1 AUTHOR

Nobuo Danjou, L<danjou@hatena.ne.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Nobuo Danjou

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.


=cut

