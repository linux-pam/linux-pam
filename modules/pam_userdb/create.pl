#!/usr/bin/perl
# this program creates a database from pairs given on standard input
# $Id$

use DB_File;

my ($database, $keyonly, $hash) = (undef, 0, 'none');

while ($#ARGV > -1) {
	my $arg = shift(@ARGV);
	if ($arg eq '--keyonly') {
		$keyonly = 1;
	} elsif ($arg =~ /^--hash=(crypt|none)$/) {
		$hash = $1;
	} else {
		die "Use: create.pl [--keyonly] [--hash=<crypt|none>] <database>\n" if defined $database;
		$database = $arg;
	}
}

die "Use: create.pl [--keyonly] [--hash=<crypt|none>] <database>\n" unless defined $database;
print "Using database: $database\nKey only: $keyonly\nHash: $hash\n";

my %lusers = ();

tie %lusers, 'DB_File', $database, O_RDWR|O_CREAT, 0644, $DB_HASH;
while (<STDIN>) {
	my ($user, $pass) = split;
	warn "Empty password (line $.)" unless length $pass > 0;

	if ($hash eq 'crypt') {
		my $salt = join('', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64]);
		$pass = crypt($pass, $salt);
	}

	if ($keyonly) {
		warn "User \"$user\" contains the \"-\" character (line $.)" if $user =~ tr/-// > 0;
		$user = "$user-$pass";
		$pass = 5; # this random value was obtained by rolling a dice
	}

	$lusers{$user} = $pass;
}

untie %lusers;
