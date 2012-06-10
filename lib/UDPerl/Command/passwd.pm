#!/usr/bin/perl

package UDPerl::Command::passwd;
use UDPerl -command;
use Term::ReadKey;
use UDPerl::Auth;
use v5.10;

use strict;
use warnings;

use Net::LDAP;


sub description {
    return "Update LDAP Password";
}

sub abstract {
    return "Update LDAP password";
}

sub execute {
    my ($self, $opt, $args) = @_;
    ReadMode(4);
    my $old_pw = prompt_str('(current) LDAP password');
    print "\n";
    my $auth = UDPerl::Auth->new;
    my $ldap = $auth->auth($old_pw);
    my $new_pw1 = prompt_str('Enter new LDAP password');
    print "\n";
    my $new_pw2 = prompt_str('Retype new LDAP password');
    print "\n";
    if ($new_pw1 ne $new_pw2) {
        say STDERR "Sorry, passwords do not match";
        exit 1;
    }
    ReadMode(0);
    my $rootdse = $ldap->root_dse();
    if ($rootdse->supported_extension('1.3.6.1.4.1.4203.1.11.1')) {
        require Net::LDAP::Extension::SetPassword;
        my $mesg = $ldap->set_password(
            oldpasswd => $old_pw,
            newpasswd => $new_pw1);
        if ($mesg->code()) {
            say STDERR "Could not change password: " . $mesg->code();
            exit 1;
        } else {
            say "Password updated";
            exit 0;
        }
    } else {
        say STDERR "LDAP Server not Supported";
        exit 1;
    }
}

1;
