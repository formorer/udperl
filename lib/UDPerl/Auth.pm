#!/usr/bin/perl

package UDPerl::Auth;

use strict;
use warnings;
use v5.10;
use Net::LDAP;
use Term::ReadKey;
use UDPerl -command;

sub new {
  my $class = shift;
  my $self = { };
  bless $self, $class;
}

sub auth {
    my $self = shift;
    my $pw = shift;

    if (! $pw) {
        ReadMode(4);
        $pw = prompt_str('LDAP Password');
        print "\n";
        ReadMode(0);
    }
    my $ldap = Net::LDAP->new ( 'ldap://10.0.3.1/' ) or die "$@";
    $ldap->bind() or die "$@";
    my $user = getpwuid( $< );
    my $search = $ldap->search( base   => 'dc=grml,dc=org',  filter =>
        "(uid=$user)" );
    if ($search->code) {
        say STDERR "Could not search in LDAP: " . $search->code;
        exit 1;
    }

    if ($search->count() == 0) {
        say STDERR "Who are you? You are not in my LDAP";
        exit 1;
    }

    my $authname=$search->entry(0)->dn();
    $ldap->unbind();
    $ldap = Net::LDAP->new( 'ldap://127.0.0.1:9389' )
        or die "$@";

    my $msg = $ldap->bind($authname, password => $pw);
    if ($msg->code() != 0) {
        say STDERR "Could not authenticate. Check your password";
        exit 1;
    }
    return $ldap;
}

1;
