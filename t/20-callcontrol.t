#!/usr/bin/perl
# Phase 2a's gate, run as processes: a relay, a Cantus endpoint, a gateway with
# two lines, and two phones. Dial, DTMF, hold, resume, transfer, hangup -- each
# one measured on the wire, because each one fails silently in a gateway: a
# digit that never arrives, a held line that still hears the far end, a
# transfer that leaves a channel stuck.
#
# The relay, the endpoint and the gateway are real processes on real sockets.
# The two phones share this process, so they are driven together: media only
# exists while both ends are talking, and measuring them one at a time measures
# a silence neither of them sent.
use strict;
use warnings;
use Test::More;
use lib 'lib';
use Time::HiRes qw(time sleep);
use JSON::PP ();
use IO::Socket::INET;
use Socket qw(sockaddr_in);

use Cantus::Relay ();
use Cantus::Node ();
use Cantus::Gateway ();
use Cantus::Phone ();

$ENV{GATEWAY_PASSWORD} = 'test123';
my $SECRET = 'test-key';

my $probe = fork();
plan skip_all => 'this test drives real processes and needs fork' unless defined $probe;
if (!$probe) { exit 0 }
waitpid($probe, 0);

# A port nobody holds, asked for the only way that is honest on this build.
sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Proto => 'udp', ReuseAddr => 1) or die "no free port: $!";
    my $p = (sockaddr_in($s->sockname))[0];
    close $s;
    return $p;
}

my $log_path = "/tmp/cantus-callcontrol-$$.log";
open my $logfh, '>>', $log_path or die "cannot write $log_path: $!";
$logfh->autoflush(1);

# A port pair the relay can actually have: on this host an ephemeral UDP port
# can fall in the range Windows reserves for TCP, so a :0 bind is retried.
my $relay;
for my $p (18000 .. 18120) {
    $relay = eval { Cantus::Relay->new(bind => "127.0.0.1:$p", secret => $SECRET) };
    last if $relay;
}
die "relay: $@" unless $relay;
my $relay_addr = '127.0.0.1:' . $relay->port;

# The far end a call is placed to: an ordinary node that answers and sends its
# 440 Hz tone, exactly like the one deployed on .53.
my $endpoint = Cantus::Node->new(
    id => 'node@test', secret => $SECRET, bind => '127.0.0.1:0',
    relay => $relay_addr, auto_answer => 1, require_sig => 0,
);

my $sip_port = free_port();
my $gateway = Cantus::Gateway->new(
    quiet => 1,
    on_event => sub { print $logfh JSON::PP->new->canonical->encode($_[0]), "\n" },
    config => {
        bind => "127.0.0.1:$sip_port", advertise => '127.0.0.1', realm => 'cantus',
        id => 'gateway@test', relay => $relay_addr, target => 'node@test',
        secret => $SECRET, rtp_port => free_port(),
        # The failed-transfer case must be provable in seconds, not in 25.
        ring_timeout => 2,
        accounts => [
            { user => '101', id => 'gw-101@test' },
            { user => '102', id => 'gw-102@test' },
        ],
    },
);

my @kids;
sub spawn {
    my ($code) = @_;
    my $pid = fork();
    die "fork failed: $!" unless defined $pid;
    if (!$pid) {
        $SIG{TERM} = $SIG{INT} = sub { exit 0 };
        eval { $code->() };
        exit 0;
    }
    push @kids, $pid;
    return $pid;
}
sub reap {
    return unless @kids;
    kill 'TERM', @kids;
    waitpid($_, 0) for @kids;
    @kids = ();
}

# The END block runs in the children too, including the probe forked before
# this file knew its log path, so nothing here may assume the variables exist.
our $TEST_LOG = $log_path;
END { reap(); unlink $TEST_LOG if defined $TEST_LOG && -e $TEST_LOG && !$ENV{KEEP_LOG} }

spawn(sub { while (1) { $relay->pump(0.05) } });
spawn(sub { $endpoint->register; while (1) { $endpoint->pump(0.05) } });
spawn(sub { $gateway->run });

sleep 1.5;    # the relay learns both line addresses before the first call

sub phone {
    my ($user) = @_;
    return Cantus::Phone->new(
        server => "127.0.0.1:$sip_port", user => $user, password => 'test123',
        local_port => free_port(), rtp_port => free_port(), quiet => 1,
    );
}

# Both phones talk at once, which is the only way a call carries audio in both
# directions: one phone pumping alone is a phone talking to itself.
sub talk {
    my ($seconds, @phones) = @_;
    $_->window_reset for @phones;
    my $until = time + $seconds;
    while (time < $until) {
        $_->pump_tick for @phones;
        sleep 0.002;
    }
    return { map { $_->{user} => $_->window } @phones };
}

# A new leg has to negotiate its media path before it carries anything, and
# how long that takes depends on the host.  Polling says "audio arrives", not
# "audio arrived inside one arbitrary window".
sub wait_audio {
    my ($phone, $seconds, @others) = @_;
    my $deadline = time + $seconds;
    my ($frames, $peak) = (0, 0);
    while (time < $deadline) {
        my $w = talk(0.8, $phone, @others)->{ $phone->{user} };
        $frames += $w->{rx_frames};
        $peak = $w->{rx_peak} if $w->{rx_peak} > $peak;
        last if $peak > 0;
    }
    return { rx_frames => $frames, rx_peak => $peak };
}

# Wait for the NOTIFY a REFER subscription answers with.  The phone pumps its
# own media here, so the window is the same one a real handset sits in.
# A REFER is answered with a 200 sipfrag at once and with the final outcome
# later, so a caller waiting for the *outcome* has to say which one it wants.
sub wait_sipfrag {
    my ($phone, $seconds, $match) = @_;
    my $deadline = time + $seconds;
    while (time < $deadline) {
        $phone->pump_tick;
        for my $n (@{ $phone->{notifies} || [] }) {
            next if $match && ($n->{body} // '') !~ $match;
            return $n;
        }
        sleep 0.01;
    }
    return undef;
}

sub cdr_events {
    open my $fh, '<', $log_path or return ();
    my @cdr;
    while (my $line = <$fh>) {
        my $rec = eval { JSON::PP->new->decode($line) };
        push @cdr, $rec if $rec && ($rec->{kind} // '') eq 'cdr';
    }
    return @cdr;
}

# ------------------------------------------------- dial, DTMF, hold, resume, hangup

my $a = phone('101');
my $b = phone('102');
ok($a->register, '101 registers');
ok($b->register, '102 registers');

my ($ok, $why) = $a->invite('102');
ok($ok, "101 dials 102 ($why)");
my $invite = $b->wait_invite(6);
ok($invite, '102 is rung');
ok($b->answer, '102 answers');
($ok, $why) = $a->wait_answered(8);
ok($ok, "101's call is answered ($why)");

my $w = talk(1.5, $a, $b);
cmp_ok($w->{102}{rx_frames}, '>', 20, "102 hears audio from 101 ($w->{102}{rx_frames} frames)");
cmp_ok($w->{102}{rx_peak}, '>', 0, 'and it is not silence');
cmp_ok($w->{101}{rx_frames}, '>', 20, '101 hears audio from 102');
cmp_ok($w->{101}{rx_peak}, '>', 0, 'audio both ways on an internal call');

# DTMF: 101 presses 5, and the digit has to reach 102 as a key press.
ok($a->send_dtmf('5'), '101 presses 5');
$w = talk(0.6, $a, $b);
is_deeply($w->{102}{dtmf}, ['5'], '102 receives the digit as an RFC 4733 event');

# Hold: the held line goes silent toward Cantus and hears nothing back.
ok((($a->hold))[0], '101 holds the call');
talk(0.6, $a, $b);    # a hold takes effect on the next frame; let the old ones drain
$w = talk(1.2, $a, $b);
is($w->{102}{rx_peak}, 0, 'a held line hears silence, not the far end');
ok((($a->resume))[0], '101 resumes');
talk(0.3, $a, $b);
$w = talk(1.2, $a, $b);
cmp_ok($w->{102}{rx_peak}, '>', 0, 'and the audio comes back without a new call');

ok($a->bye, '101 hangs up');
$w = talk(0.8, $b);
ok($w->{102}{ended}, '102 is released when 101 hangs up');

my @cdr = cdr_events();
my ($out) = grep { ($_->{line} // '') eq '101' && ($_->{direction} // '') eq 'outbound' } @cdr;
ok($out, 'the call left a CDR for the line that placed it');
is($out->{from}, '101', 'the CDR names the caller');
is($out->{to}, '102', 'and the number dialled');
is($out->{dtmf}, '5', 'and the digit that was pressed');
ok($out->{answered}, 'and that it was answered');
cmp_ok($out->{rx_frames}, '>', 20, 'with the audio it carried');
my ($in) = grep { ($_->{line} // '') eq '102' } @cdr;
ok($in, 'and one for the line that received it');
is($in->{direction}, 'inbound', 'marked inbound');

# ---------------------------------------------------- transfer to another line

my $c = phone('101');
my $d = phone('102');
ok($c->register, '101 registers again for the transfer');
ok($d->register, '102 registers again for the transfer');

($ok, $why) = $c->invite('node@test');
ok($ok, "101 dials the Cantus endpoint ($why)");
($ok, $why) = $c->wait_answered(8);
ok($ok, "the endpoint answers ($why)");
my $wc = $c->pump(1.5);
cmp_ok($wc->{rx_peak}, '>', 0, '101 hears the endpoint');

my ($ref, $ref_why) = $c->refer('102');
ok($ref, "101 transfers the call to 102 ($ref_why)");
my $tin = $d->wait_invite(6);
ok($tin, '102 is rung for the transferred call');
ok($d->answer, '102 answers the transfer');

my $wt = wait_audio($d, 8);
cmp_ok($wt->{rx_peak}, '>', 0, '102 now hears the endpoint the call was moved to');
# 101's BYE arrived while only 102 was being pumped; reading it now is the
# point -- a released line must have been told, not silently dropped.
my $wc2 = talk(0.8, $c);
ok($wc2->{101}{ended}, 'and 101 was released rather than left holding a dead channel');

@cdr = cdr_events();
my ($moved) = grep { ($_->{line} // '') eq '101' && ($_->{result} // '') eq 'transferred' } @cdr;
ok($moved, 'the transfer is in the CDR as a transfer, not a dropped call');

# No stuck channel: after a transfer, the same line can place a fresh call.
my $e = phone('101');
ok($e->register, '101 registers a third time');
($ok, $why) = $e->invite('node@test');
($ok, $why) = $e->wait_answered(8) if $ok;
ok($ok, "101 places a new call after the transfer ($why)");
my $we2 = wait_audio($e, 8);
ok($we2->{rx_peak} > 0,
   "and it carries audio ($we2->{rx_frames} frames, peak $we2->{rx_peak})");
$e->bye;
talk(0.6, $e);

# 102 was left in the transferred call; the next scenario needs the line free.
$d->bye;
talk(0.6, $d);

# ------------------------------- transfer whose target is rung and never answers

my $f = phone('101');
my $g = phone('102');    # registered, and deliberately never answered
ok($f->register, '101 registers for the transfer that will fail');
ok($g->register, '102 registers but will not pick up');

($ok, $why) = $f->invite('node@test');
($ok, $why) = $f->wait_answered(8) if $ok;
ok($ok, "101 is on a call to the endpoint ($why)");
ok(wait_audio($f, 6)->{rx_peak} > 0, 'and the call is carrying audio');

my $moved_before = scalar grep { ($_->{result} // '') eq 'transferred' } cdr_events();

my ($ref2, $why2) = $f->refer('102');
ok($ref2, "101 transfers the call to 102 ($why2)");
ok($g->wait_invite(5), '102 is rung for the transferred call');

# 102 never answers.  The transferor has to be told, through the REFER
# subscription it opened, that the transfer did not happen.
my $notify = wait_sipfrag($f, 12, qr/^SIP\/2\.0 408/);
ok($notify, 'the transferor gets a NOTIFY for the transfer it asked for');
like($notify->{body} // '', qr/^SIP\/2\.0 408/, 'and its sipfrag says the transfer timed out');
like($notify->{state} // '', qr/terminated/, 'and the subscription is closed, not left open');

# The original call is the part that matters: a failed transfer must not take
# the call with it.
ok(!$f->{ended}, 'the original call is still up after the failed transfer');
ok(wait_audio($f, 6)->{rx_peak} > 0, 'and it still carries audio to the endpoint');

my @cdr3 = cdr_events();
my ($noanswer) = grep { ($_->{line} // '') eq '102' && ($_->{result} // '') eq 'no answer' } @cdr3;
ok($noanswer, 'the leg that was rung and never answered has its own CDR');
is($noanswer->{answered}, 0, 'recorded as unanswered');
my $moved_after = scalar grep { ($_->{result} // '') eq 'transferred' } @cdr3;
is($moved_after, $moved_before, 'and no CDR claims the call was transferred');

ok($f->bye, '101 hangs up the call it kept');
talk(0.6, $f);

# No stuck channel: the line that was rung is free for the next call.
my $h = phone('101');
ok($h->register, '101 registers once more');
($ok, $why) = $h->invite('102');
ok($ok, "101 can dial 102 again ($why)");
ok($g->wait_invite(6), '102 is rung by an ordinary call');
ok($g->answer, '102 answers it');
($ok, $why) = $h->wait_answered(8);
ok($ok, "and the call connects ($why)");
ok(wait_audio($h, 6, $g)->{rx_peak} > 0, 'with audio');
$h->bye;

reap();
pass('all components stopped');
done_testing();
