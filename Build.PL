use strict;
use warnings;
use Module::Build;

my $build = Module::Build->new
(
        module_name => 'UDPerl',
        dist_author => 'Alexander Wirt <formorer@formorer.de>',
        dist_abstract => 'manager userinformation in LDAP',
        requires    => {
            'Net::LDAP' => 0,
            'App::Cmd::Plugin::Prompt' => 0,
            'Term::ANSIColor' => 0,
            'Term::ReadKey' => 0,
        },
        script_files => 'bin/',
    );

$build->create_build_script();
