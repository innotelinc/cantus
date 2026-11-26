#!/usr/bin/perl
# The health verdict is what a container and an operator act on, so it is tested
# against finished scenario results rather than by running calls: a wrong verdict
# is a wrong verdict whatever the audio did.
use strict;
use warnings;
use Test::More;
use lib 'lib';
use Cantus::Health ();

sub result {
    my (%o) = @_;
    return {
        ok             => 1,
        frames         => 26,
        peak           => 6000,
        relay_frames   => 0,
        direct_frames  => 26,
        ended          => 1,
        premature_end  => 0,
        recovered_at   => undef,
        %o,
    };
}

my $v;

$v = Cantus::Health::verdict(result(), nat => 'none', rebind => 0);
ok($v->{ok}, 'a plain direct call is healthy');

$v = Cantus::Health::verdict(result(frames => 0), nat => 'none', rebind => 0);
ok(!$v->{ok}, 'no audio is unhealthy');
like($v->{error}, qr/no audio/, 'and says why');

$v = Cantus::Health::verdict(result(peak => 0), nat => 'none', rebind => 0);
ok(!$v->{ok}, 'silent audio is unhealthy');

$v = Cantus::Health::verdict(result(relay_frames => 26, recovered_at => 1.4), nat => 'cone', rebind => 1);
ok($v->{ok}, 'a cone rebind that returns to a direct path is healthy');

$v = Cantus::Health::verdict(result(relay_frames => 26), nat => 'cone', rebind => 1, recovered_at => undef);
ok(!$v->{ok}, 'a cone rebind that never recovers is unhealthy');
like($v->{error}, qr/direct path/, 'and says why');

# The case the plan makes the health check: symmetric NAT, mapping flushed.
my $sym = result(relay_frames => 26, direct_frames => 0, recovered_at => undef);
$v = Cantus::Health::verdict($sym, nat => 'symmetric', rebind => 1);
ok($v->{ok}, 'a symmetric rebind carried by the relay is healthy without a direct path');

$v = Cantus::Health::verdict(result(relay_frames => 0, direct_frames => 0), nat => 'symmetric', rebind => 1);
ok(!$v->{ok}, 'a symmetric rebind that never used the relay is unhealthy');

$v = Cantus::Health::verdict(result(relay_frames => 26, premature_end => 1), nat => 'symmetric', rebind => 1);
ok(!$v->{ok}, 'a call dropped by the flush is unhealthy');
like($v->{error}, qr/dropped/, 'and says why');

# The symmetric rebind ends without a clean BYE in this harness. What matters is
# that the flush did not drop the call, not how the harness tore it down.
$v = Cantus::Health::verdict(result(relay_frames => 26, ended => 0), nat => 'symmetric', rebind => 1);
ok($v->{ok}, 'an unclean ending is not unhealthy when the relay carried the call');

done_testing();
