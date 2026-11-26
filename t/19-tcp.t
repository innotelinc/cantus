#!/usr/bin/perl
# 7443/tcp: the fallback binding section 4.2 defines and section 8.8 uses.
#
# Three things are worth testing and they are different failures: the framing
# must survive a stream that splits a frame, the relay must answer a REGISTER
# that arrives on a connection, and a node whose UDP goes unanswered must move
# to TCP by itself -- then move back when UDP answers.
use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use Time::HiRes qw(time sleep);

use lib 'lib';
use Cantus::Wire ();
use Cantus::Relay ();
use Cantus::Node ();

sub drain {
    my (@svc) = @_;
    for (1 .. 30) {
        $_->pump(0) for @svc;
        sleep 0.01;
    }
}

# --------------------------------------------------------------- framing

my $dgram = Cantus::Wire::msg_encode(11, {
    1 => Cantus::Wire::S('bob@test'), 4 => Cantus::Wire::V(7),
});
my $framed = Cantus::Wire::frame_encode($dgram);
is(length($framed), length($dgram) + 2, 'a frame is the datagram plus a 2-octet prefix');
is(unpack('n', substr($framed, 0, 2)), length($dgram), 'the prefix is the datagram length, big-endian');

my ($frames, $rest) = Cantus::Wire::frame_decode($framed . substr($framed, 0, 4));
is(scalar @$frames, 1, 'one whole frame decodes');
is($frames->[0], $dgram, 'the frame body is the datagram, unchanged');
is(length $rest, 4, 'an incomplete frame is kept as the tail, not parsed as data');

my ($burst, $empty) = Cantus::Wire::frame_decode($framed . $framed);
is(scalar @$burst, 2, 'two frames in one read both decode');
is($empty, '', 'nothing is left over');

my ($garbage, $kept) = Cantus::Wire::frame_decode(pack('n', 2) . 'zz' . $framed);
is(scalar @$garbage, 1, 'a frame that is not a Cantus datagram is dropped');
is(length $kept, 0, 'and the following frame still parses');

# --------------------------------------------------------- relay bindings

my $relay = Cantus::Relay->new(bind => '127.0.0.1:0', secret => 'test-key');
isnt($relay->tcp_port, undef, 'the relay opens a TCP listener beside UDP');
is($relay->tcp_port, $relay->port, 'both bindings are on the same port number');

# ------------------------------------------------- node prefers UDP when it answers

my @relay_events;
my $udp_relay = Cantus::Relay->new(
    bind => '127.0.0.1:0', secret => 'test-key',
    on_event => sub { push @relay_events, $_[0] },
);
my $udp_node = Cantus::Node->new(
    id => 'udp@test', secret => 'test-key', bind => '127.0.0.1:0',
    relay => '127.0.0.1:' . $udp_relay->port, require_sig => 0, auto_answer => 0,
);
$udp_node->register;
for (1 .. 60) { $udp_node->pump(0); $udp_relay->pump(0); sleep 0.01 }
ok($udp_node->handle, 'a relay that answers over UDP gives the node a handle');
is($udp_node->stats->{transport}, 'udp', 'and the node stays on UDP');
is($udp_relay->stats->{tcp_clients}, 0, 'no TCP connection was opened for it');

# ------------------------------------------- UDP blocked: the node falls back

my @tcp_events;
my $tcp_relay = Cantus::Relay->new(
    bind => '127.0.0.1:0', secret => 'test-key', udp => 0,
    on_event => sub { push @tcp_events, $_[0] },
);
my $tcp_node = Cantus::Node->new(
    id => 'tcp@test', secret => 'test-key', bind => '127.0.0.1:0',
    relay => '127.0.0.1:' . $tcp_relay->port, require_sig => 0, auto_answer => 0,
);
$tcp_node->register;
for (1 .. 200) {
    $tcp_node->pump(0);
    $tcp_relay->pump(0);
    last if $tcp_node->handle;
    sleep 0.01;
}
ok($tcp_node->handle, 'a relay that only answers over TCP still registers the node');
is($tcp_node->stats->{transport}, 'tcp', 'the node is on the fallback binding');
my ($registered) = grep { ($_->{kind} // '') eq 'registered' } @tcp_events;
is($registered->{transport}, 'tcp', 'the relay knows the registration arrived over TCP');

# ------------------------------------------- forwarding back down a connection

# A second peer that registers over TCP and then only listens: this is the
# direction that can silently rot, because the relay has an address for a UDP
# peer but only a connection for this one.
my $peer = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1', PeerPort => $tcp_relay->port, Proto => 'tcp',
) or die "test peer: $!";
$peer->blocking(1);
my $reg = Cantus::Wire::msg_encode(13, {
    21 => Cantus::Wire::S('cantus/1'),
    11 => Cantus::Wire::S('peer@test'),
    1  => Cantus::Wire::S('peer@test'),
});
print {$peer} Cantus::Wire::frame_encode($reg);

my $inbuf = '';
my $handle;
my $deadline = time + 3;
while (time < $deadline && !$handle) {
    $tcp_relay->pump(0);
    my $chunk;
    my $n = sysread($peer, $chunk, 65535);
    if (defined $n && $n > 0) {
        $inbuf .= $chunk;
        my ($frames, $rest) = Cantus::Wire::frame_decode($inbuf);
        $inbuf = $rest;
        for my $body (@$frames) {
            my ($type, $f) = Cantus::Wire::msg_decode($body);
            $handle = $f->{15}[1] if $type == 14;
        }
    }
    sleep 0.01;
}
ok($handle, 'a REGISTER over TCP is answered with a framed REGISTER_ACK');

my $inner = Cantus::Wire::msg_encode(11, { 1 => Cantus::Wire::S('tcp@test') });
$tcp_node->_relay_send($handle, undef, $inner);
my $got = '';
$deadline = time + 3;
while (time < $deadline && !length $got) {
    $tcp_relay->pump(0);
    my $chunk;
    my $n = sysread($peer, $chunk, 65535);
    $inbuf .= $chunk if defined $n && $n > 0;
    my ($frames, $rest) = Cantus::Wire::frame_decode($inbuf);
    $inbuf = $rest;
    if (@$frames) { $got = $frames->[0]; last }
    sleep 0.01;
}
is($got, $inner, 'the relay forwards to a TCP peer down its own connection');
close $peer;

# ------------------------------------------ UDP returns: the fallback closes

# The TCP registration is live; an ACK arriving over UDP must retire it, or the
# fallback quietly becomes the committed path.
my $dual = Cantus::Relay->new(bind => '127.0.0.1:0', secret => 'test-key');
my $dual_node = Cantus::Node->new(
    id => 'dual@test', secret => 'test-key', bind => '127.0.0.1:0',
    relay => '127.0.0.1:' . $dual->port, require_sig => 0, auto_answer => 0,
);
ok($dual_node->_tcp_open, 'the node can open the fallback on demand');
$dual_node->{transport} = 'tcp';
$dual_node->register;    # UDP REGISTER goes out; the ACK comes back over UDP
for (1 .. 80) { $dual_node->pump(0); $dual->pump(0); sleep 0.01 }
ok($dual_node->handle, 'the UDP REGISTER is answered');
is($dual_node->stats->{transport}, 'udp', 'the node is back on UDP');
ok(!$dual_node->{tcp}, 'and the TCP connection was closed');

# ------------------------------ a relay whose name is gone is a dropped send

# Stopping the relay container also removes its Docker DNS name, so the node's
# next REGISTER resolves to nothing at all. That has to be a send that does not
# happen and is retried, not an exception that ends the daemon: measured on .53,
# a relay restart killed the node with `Undefined address for
# Socket::pack_sockaddr_in`, which turned a recoverable relay blip into an outage.
my $orphan = Cantus::Node->new(
    id => 'orphan@test', secret => 'test-key', bind => '127.0.0.1:0',
    relay => 'cantus-relay-not-here.invalid:7443', require_sig => 0, auto_answer => 0,
);
is($orphan->sendto('cantus-relay-not-here.invalid:7443', 'x'), 0,
    'an unresolvable relay is a dropped send, not a crash');
ok($orphan->register, 'and the node keeps trying instead of dying');

done_testing();
