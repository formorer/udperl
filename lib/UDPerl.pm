#!/usr/bin/perl

package UDPerl;

my $VERSION = '0.1';

use App::Cmd::Setup -app => {
    plugins => [ qw(Prompt) ],
};


1;
