#!/usr/bin/perl

package UDPerl::Command::sshkey;
use UDPerl -command;
use Term::ReadKey;
use UDPerl::Auth;
use v5.10;
use Term::ANSIColor;
use Perl6::Slurp;

use strict;
use warnings;

use Net::LDAP;

sub opt_spec {
    return ( [ "file|f=s", "Read keys(s) from file" ], );
}

sub description {
    my $desc = qq {Manage your ssh publickeys in LDAP

The sshkeys command supports several subcommands:

"list"      lists all sshkeys stored in LDAP
"add"       reads a keyfiles via --file and adds the keys(s) to LDAP.
            The keyfile may contain several public keys separed by newlines.
"remove"    starts an interactive dialog to remove public keys from LDAP
};
    return $desc;
}

sub abstract {
    return "Manage sshkeys in LDAP";
}

sub execute {
    my ( $self, $opt, $args ) = @_;
    my $command = shift( @{$args} );
    if ( !$command ) {
        say STDERR "Command for sshekys needed.\nSee `"
            . $self->app->arg0
            . " help sshkeys`";
        exit 1;
    }

    given ($command) {
        when ("list") { $self->listkeys( $opt, $args ); }
        when ("add") { $self->addkeys( $opt, $args ); }
        when ("delete") { $self->deletekeys( $opt, $args ); }
        default { say STDERR "Unkown command $command"; exit 1; }
    }
}

sub _get_keys {
    my $ldap   = shift;
    my $user   = getpwuid($<);
    my $search = $ldap->search(
        base   => 'dc=grml,dc=org',
        filter => "(uid=$user)",
        attrs  => ['sshPublicKey']
    );
    $search->code && die $search->error;
    my $entry = $search->entry(0);
    my @keys  = $entry->get_value('sshPublicKey');
    return @keys;
}

sub listkeys {
    my ( $self, $opt, $args ) = @_;
    my $auth = UDPerl::Auth->new;
    my $ldap = $auth->auth;
    my @keys = _get_keys($ldap);
    if ( !@keys ) {
        print STDERR color 'red';
        print STDERR "No keys found. Use "
            . $self->app->arg0
            . " sshkeys add to store a key in LDAP";
        print STDERR color 'reset';
        exit 1;
    } else {
        my $num = 1;
        say "You have the following sshkeys stored in LDAP:\n";
        foreach my $key (@keys) {
            print color 'green bold';
            print "[$num] ";
            print color 'reset';
            say $key;
            $num++;
        }
    }
}

sub deletekeys {
    my ( $self, $opt, $args ) = @_;

    #first get our keys
    my $auth   = UDPerl::Auth->new;
    my $ldap   = $auth->auth;
    my @keys   = _get_keys($ldap);
    my $accept = 0;
    while ( !$accept ) {
        if ( scalar(@keys) == 0 ) {
            my $rc =
                prompt_yn "No keys left, removing all keys. Are you sure?";
            exit if !$rc;
            break;
        }
        my $i = 1;
        foreach my $key (@keys) {
            print color 'green bold';
            print "[$i] ";
            print color 'reset';
            say $key;
            $i++;
        }
        my $result = prompt_str(
            "Which key do you want to remove (a for accept, q for quit)");
        given ($result) {
            when (/^a/i) { $accept = 1; }
            when (/^q/i) { exit; }
            when (/[0-9]+/) {
                @keys = grep { $_ ne $keys[ $result - 1 ] } @keys;
            }
            default { say "Invalid input" }
        }
    }
    my $user   = getpwuid($<);
    my $search = $ldap->search(
        base   => 'dc=grml,dc=org',
        filter => "(uid=$user)"
    );
    $search->code && die $search->error;
    if ( $search->count() == 0 ) {
        say STDERR "Who are you? You are not in my LDAP";
        exit 1;
    }
    my $user_dn = $search->entry(0)->dn();
    my $result =
        $ldap->modify( $user_dn, replace => { 'sshPublicKey' => \@keys } );
    if ( $result->code ) {
        say STDERR "Failed to update sshkeys: ", $result->error;
        exit 1;
    } else {
        say "Keys updated";
        exit;
    }
}

sub addkeys {
    my ( $self, $opt, $args ) = @_;

    if ( !$opt->{'file'} ) {
        say "No keyfile given with --file <FILE>";
        exit 1;
    }

    my $keyfile = slurp $opt->{'file'};

    my $auth         = UDPerl::Auth->new;
    my $ldap         = $auth->auth;
    my @keys         = split( '\n', $keyfile );
    my $i            = 1;
    my %current_keys = map { $_ => 1 } _get_keys($ldap);

    #some sanity checks
    foreach my $new_key (@keys) {
        if ( $new_key !~ /^ssh-.*/ ) {
            say STDERR
                "Line $i does not look like a valid ssh public key (sss-{rsa,dsa} ..)";
            @keys = grep { $_ ne $new_key } @keys;
        } elsif ( $current_keys{$new_key} ) {
            say STDERR "Line $i already defined. Skipping";
            @keys = grep { $_ ne $new_key } @keys;
        }
        $i++;
    }
    if ( scalar(@keys) == 0 ) {
        say STDERR "No valid keys left to add";
        exit 1;
    }
    my $user   = getpwuid($<);
    my $search = $ldap->search(
        base   => 'dc=grml,dc=org',
        filter => "(uid=$user)"
    );
    $search->code && die $search->error;
    if ( $search->count() == 0 ) {
        say STDERR "Who are you? You are not in my LDAP";
        exit 1;
    }

    my $user_dn = $search->entry(0)->dn();
    my $result =
        $ldap->modify( $user_dn, add => { 'sshPublicKey' => \@keys } );
    $result->code && warn "failed to add entry: ", $result->error;
}

1;
