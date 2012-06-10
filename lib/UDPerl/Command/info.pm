#!/usr/bin/perl

package UDPerl::Command::info;
use UDPerl -command;
use Term::ReadKey;
use UDPerl::Auth;
use v5.10;

use strict;
use warnings;

use Net::LDAP;


sub description {
    return "Show userinformation stored in LDAP";
}

sub abstract {
    return "Show userinformation stored in LDAP";
}

sub execute {
    my ($self, $opt, $args) = @_;
    my $auth = UDPerl::Auth->new;
    my $ldap = $auth->auth();

    my $uid   = getpwuid($<);
    my $search = $ldap->search(
        base   => 'dc=grml,dc=org',
        filter => "(uid=$uid)"
    );
    $search->code && die $search->error;
    if ( $search->count() == 0 ) {
        say STDERR "Who are you? You are not in my LDAP";
        exit 1;
    }
    my $user = $search->entry(0);
    say "login: " . $user->get_value('uid');
    my $gecos = $user->get_value('gecos') ? $user->get_value('gecos') : 'unset';
    say "gecos: " . $gecos;
    say "uid: " . $user->get_value('uidNumber');
    say "gid: " . $user->get_value('gidNumber');
    say "home: " . $user->get_value('homeDirectory');
    say "shell: " . $user->get_value('loginShell');
    say "hosts:\n\t " . join("\n\t", $user->get_value('host'));
    say "sshkeys:\n\t" . join("\n\t", $user->get_value('sshPublicKey'));

}

1;
