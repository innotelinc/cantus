#!/usr/bin/perl
# Phase 2b: the carrier leg.
#
# The carrier here is a real SIP peer on a UDP socket, not a mock of our own
# code: it challenges the gateway's REGISTER and verifies the digest with the
# same arithmetic the gateway uses, it offers media as an INVITE, and it is
# where an outbound call actually goes.  What it cannot do is be voip.ms, so
# the live proof of the carrier path is a registration and a call to 4443 on
# the deployed gateway, not this file.
use strict;
use warnings;
use lib 'lib';
use Test::More;
use Time::HiRes qw(time sleep);
use IO::Socket::INET;
use Socket qw(sockaddr_in inet_aton inet_ntoa);
use JSON::PP ();

use Cantus::Relay ();
use Cantus::Node ();
use Cantus::Gateway ();
use Cantus::Phone ();
use Cantus::Sip ();
use Cantus::G711 ();
use Cantus::Media ();

my $probe = fork();
plan skip_all => 'this test drives real processes and needs fork' unless defined $probe;
if (!$probe) { exit 0 }
waitpid($probe, 0);

my $SECRET  = 'cantus-loopback';
my $DID     = '14132642700';
my $CARRIER_PASSWORD = 'carrier-secret';
$ENV{GATEWAY_PASSWORD} = 'test123';
$ENV{TRUNK_SECRET}     = $CARRIER_PASSWORD;

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Proto => 'udp', ReuseAddr => 1) or die "no free port: $!";
    my $p = (sockaddr_in($s->sockname))[0];
    close $s;
    return $p;
}

# ---------------------------------------------------------------- the carrier

package Carrier;

use Socket qw(sockaddr_in inet_aton inet_ntoa);

sub new {
    my ($class, %a) = @_;
    my $sip = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                    Proto => 'udp', ReuseAddr => 1) or die "carrier sip: $!";
    my $rtp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                    Proto => 'udp', ReuseAddr => 1) or die "carrier rtp: $!";
    $sip->blocking(0);
    $rtp->blocking(0);
    return bless {
        sip => $sip, rtp => $rtp,
        sip_port => (sockaddr_in($sip->sockname))[0],
        rtp_port => (sockaddr_in($rtp->sockname))[0],
        user => $a{user}, password => $a{password},
        registrations => 0, challenged => 0, digest_ok => 0,
        invites => [], acks => 0, byes => 0,
        in => undef, out => undef,
        rx_frames => 0, rx_peak => 0, phase => 0, seq => 0, ts => 0,
    }, $class;
}

sub port       { $_[0]{sip_port} }
sub rtp_port   { $_[0]{rtp_port} }
sub addr       { '127.0.0.1:' . $_[0]{sip_port} }

sub _send {
    my ($self, $text, $to) = @_;
    my ($ip, $port) = split /:/, $to, 2;
    return unless $ip && $port;
    CORE::send($self->{sip}, $text, 0, sockaddr_in($port, inet_aton($ip)));
}

sub _sdp {
    my ($self) = @_;
    return Cantus::Sip::sdp_answer(ip => '127.0.0.1', port => $self->{rtp_port},
                                   codec => 'PCMU', event_pt => 101);
}

sub invite_in {
    my ($self, %a) = @_;
    my $gw = $a{gw};   # host:port of the gateway's SIP socket
    my $call = 'carrier-in-' . int(rand(1_000_000_000));
    my $from_tag = 'cin' . int(rand(1_000_000));
    $self->{in} = { call => $call, did => $a{did}, caller => $a{caller} // '14135550100',
                    from_tag => $from_tag, state => 'calling', code => 0 };
    my $text = Cantus::Sip::request(
        method  => 'INVITE',
        uri     => "sip:$a{did}\@$gw",
        via     => '127.0.0.1:' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => "<sip:$self->{in}{caller}\@carrier.example>;tag=$from_tag",
        to      => "<sip:$a{did}\@$gw>",
        call_id => $call,
        cseq    => 1,
        contact => '<sip:carrier@127.0.0.1:' . $self->{sip_port} . '>',
        body    => $self->_sdp,
    );
    $self->_send($text, $gw);
}

sub bye_in {
    my ($self, $gw) = @_;
    my $c = $self->{in} or return;
    $c->{state} = 'ended';
    my $text = Cantus::Sip::request(
        method  => 'BYE',
        uri     => "sip:$c->{did}\@$gw",
        via     => '127.0.0.1:' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => "<sip:$c->{caller}\@carrier.example>;tag=$c->{from_tag}",
        to      => "<sip:$c->{did}\@$gw>;tag=" . ($c->{to_tag} // 'gw'),
        call_id => $c->{call},
        cseq    => 2,
    );
    $self->_send($text, $gw);
}

sub pump {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $peer = recv($self->{sip}, $buf, 65535, 0);
        last unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $msg = Cantus::Sip::parse($buf) or next;
        $msg->{src} = inet_ntoa($iaddr) . ':' . $port;
        if ($msg->{request}) { $self->_request($msg) } else { $self->_response($msg) }
    }
    $self->_rtp;
}

sub _request {
    my ($self, $msg) = @_;
    my $method = $msg->{method} // '';

    if ($method eq 'REGISTER') {
        my $auth = Cantus::Sip::header($msg, 'authorization');
        if (!$auth) {
            $self->{challenged}++;
            $self->_send(Cantus::Sip::response($msg, 401,
                headers => [ Cantus::Sip::challenge_header('carrier', 'nonce-' . $$) ]),
                $msg->{src});
            return;
        }
        # The same verifier the gateway uses on its own phones: a digest the
        # carrier would reject must fail here too.
        my ($ok) = Cantus::Sip::verify_digest(
            msg => $msg, method => 'REGISTER',
            user => $self->{user}, password => $self->{password}, realm => 'carrier',
        );
        $self->{digest_ok} = $ok ? 1 : 0;
        if ($ok) {
            $self->{registrations}++;
            $self->_send(Cantus::Sip::response($msg, 200, expires => 300), $msg->{src});
        } else {
            $self->_send(Cantus::Sip::response($msg, 403), $msg->{src});
        }
        return;
    }

    if ($method eq 'INVITE') {
        # voip.ms challenges an outbound INVITE the same way it challenges a
        # REGISTER: a gateway that cannot answer the challenge can register
        # perfectly and still never place a call.
        my $auth = Cantus::Sip::header($msg, 'authorization');
        if (!$auth) {
            $self->{invite_challenged}++;
            $self->_send(Cantus::Sip::response($msg, 401,
                headers => [ Cantus::Sip::challenge_header('carrier', 'nonce-inv-' . $$) ]),
                $msg->{src});
            return;
        }
        my ($aok) = Cantus::Sip::verify_digest(
            msg => $msg, method => 'INVITE',
            user => $self->{user}, password => $self->{password}, realm => 'carrier',
        );
        $self->{invite_digest_ok} = $aok ? 1 : 0;
        unless ($aok) {
            $self->_send(Cantus::Sip::response($msg, 403), $msg->{src});
            return;
        }
        my $to   = Cantus::Sip::parse_uri($msg->{uri});
        my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
        my $call = Cantus::Sip::header($msg, 'call-id');
        my $offer = Cantus::Sip::sdp_parse($msg->{body});
        push @{ $self->{invites} }, { call => $call, to => $to ? $to->{user} : undef,
                                      from => $from ? $from->{user} : undef,
                                      port => $offer ? $offer->{port} : undef };
        $self->{out} = {
            call => $call, to => $to ? $to->{user} : undef,
            from => $from ? $from->{user} : undef,
            state => 'ringing',
            remote => ($offer && $offer->{ip}) ? "$offer->{ip}:$offer->{port}" : undef,
            offer_body => $msg->{body},
        };
        $self->_send(Cantus::Sip::response($msg, 180, to_tag => 'carrier1'), $msg->{src});
        $self->_send(Cantus::Sip::response(
            $msg, 200, to_tag => 'carrier1',
            contact => '<sip:carrier@127.0.0.1:' . $self->{sip_port} . '>',
            sdp => $self->_sdp,
        ), $msg->{src});
        $self->{out}{state} = 'active';
        return;
    }

    if ($method eq 'ACK')  { $self->{acks}++; return }
    if ($method eq 'BYE')  {
        $self->{byes}++;
        $self->_send(Cantus::Sip::response($msg, 200), $msg->{src});
        $self->{out}{state} = 'ended' if $self->{out};
        return;
    }
    if ($method eq 'CANCEL') {
        $self->_send(Cantus::Sip::response($msg, 200), $msg->{src});
        return;
    }
    $self->_send(Cantus::Sip::response($msg, 405), $msg->{src});
}

sub _response {
    my ($self, $msg) = @_;
    my $code = $msg->{status} // 0;
    my $in = $self->{in} or return;
    return unless (Cantus::Sip::header($msg, 'call-id') // '') eq $in->{call};

    if ($code >= 200) {
        $in->{code} = $code;
        $in->{to_tag} = Cantus::Sip::tag($msg, 'to') // 'gw';
    }
    return if $code >= 300;
    return if $code < 200;

    my $sdp = Cantus::Sip::sdp_parse($msg->{body});
    $in->{remote} = $sdp && $sdp->{ip} ? "$sdp->{ip}:$sdp->{port}" : $msg->{src};
    $in->{state} = 'active';
    my $ack = Cantus::Sip::request(
        method  => 'ACK',
        uri     => "sip:$in->{did}\@" . $msg->{src},
        via     => '127.0.0.1:' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => "<sip:$in->{caller}\@carrier.example>;tag=$in->{from_tag}",
        to      => "<sip:$in->{did}\@carrier>;tag=$in->{to_tag}",
        call_id => $in->{call},
        cseq    => 1,
    );
    $self->_send($ack, $msg->{src});
}

# The carrier is an echo test: whatever address sends media gets media back.
# That is what voip.ms 4443 does, and it removes the SDP-port coupling from
# the proof -- audio that comes back came from the gateway, wherever it was
# sent from.
sub _rtp {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $peer = recv($self->{rtp}, $buf, 4096, 0);
        last unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $pkt = Cantus::Sip::rtp_parse($buf) or next;
        next unless $pkt->{pt} == 0;
        my $pcm = Cantus::G711::mu_to_pcm($pkt->{payload});
        next unless length $pcm;
        $self->{last_src} = inet_ntoa($iaddr) . ':' . $port;
        my $peak = Cantus::Media::peak($pcm);
        $self->{rx_frames}++;
        $self->{rx_peak} = $peak if $peak > $self->{rx_peak};
    }

    my @dest = grep { defined && length }
               (($self->{in}  && $self->{in}{state}  eq 'active' ? $self->{in}{remote}  : ()),
                ($self->{out} && $self->{out}{state} eq 'active' ? $self->{out}{remote} : ()));
    return unless @dest;
    $self->{echoes}++ if $self->{last_src};
    my ($pcm, $phase) = Cantus::Media::pcm_frame(hz => 440, amp => 6000, phase => $self->{phase});
    $self->{phase} = $phase;
    my $payload = Cantus::G711::pcm_to_mu($pcm);
    for my $to (@dest) {
        my ($ip, $port) = split /:/, $to, 2;
        next unless $ip && $port;
        my $pkt = Cantus::Sip::rtp_build(pt => 0, seq => $self->{seq}++, ts => $self->{ts},
                                         ssrc => 0xCA817, payload => $payload);
        CORE::send($self->{rtp}, $pkt, 0, sockaddr_in($port, inet_aton($ip)));
    }
    $self->{ts} += 160;
}

package main;

# ---------------------------------------------------------------- the network

my $log_path = "/tmp/cantus-trunk-$$.log";
open my $logfh, '>>', $log_path or die "cannot write $log_path: $!";
$logfh->autoflush(1);

my $relay;
for my $p (18200 .. 18320) {
    $relay = eval { Cantus::Relay->new(bind => "127.0.0.1:$p", secret => $SECRET) };
    last if $relay;
}
die "relay: $@" unless $relay;
my $relay_addr = '127.0.0.1:' . $relay->port;

my $endpoint = Cantus::Node->new(
    id => 'node@trunk.test', secret => $SECRET, bind => '127.0.0.1:0',
    relay => $relay_addr, auto_answer => 1, require_sig => 0,
);

my $carrier = Carrier->new(user => '235662_test', password => $CARRIER_PASSWORD);

my $routes_path = "/tmp/cantus-routes-$$.json";
open my $rfh, '>', $routes_path or die $!;
print $rfh JSON::PP->new->canonical->encode({
    version => 1,
    default => { reject => 3 },
    routes  => [
        { name => 'carrier-echo', when => { to => '4443' },
          then => [ { forward => { to => 'pstn:4443' } } ] },
        # Both digit forms of the same DID, because a carrier picks one of them
        # and the document, not the gateway, says where each one goes.
        { name => 'did-14132642700', when => { to => '14132642700' },
          then => [ { answer => {} }, { forward => { to => 'ext:101' } } ] },
        { name => 'did-4132642700', when => { to => '4132642700' },
          then => [ { answer => {} }, { forward => { to => 'ext:101' } } ] },
        # Numbers we own but do not answer: the document refuses them.
        { name => 'did-14135550111-fax', when => { to => '14135550111' },
          then => [ { reject => 3 } ] },
        { name => 'did-14135550112-unrouted', when => { to => '14135550112' },
          then => [ { reject => 3 } ] },
        { name => 'pstn-national', when => { to => '1*' },
          then => [ { forward => { to => 'pstn:' } } ] },
    ],
});
close $rfh;

my $sip_port = free_port();
my $gateway = Cantus::Gateway->new(
    quiet => 1,
    on_event => sub { print $logfh JSON::PP->new->canonical->encode($_[0]), "\n" },
    config => {
        bind => "127.0.0.1:$sip_port", advertise => '127.0.0.1', realm => 'cantus',
        id => 'gateway@trunk.test', relay => $relay_addr, target => 'node@trunk.test',
        secret => $SECRET, rtp_port => free_port(), ring_timeout => 3, debug => 1,
        accounts => [ { user => '101', id => 'gw-101@trunk.test' } ],
        trunk => {
            host => '127.0.0.1', port => $carrier->port,
            user => '235662_test', secret_env => 'TRUNK_SECRET',
            realm => 'carrier', from => $DID,
            routes => $routes_path,
        },
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

our $TEST_LOG = $log_path;
our $ROUTES = $routes_path;
END {
    reap();
    unlink $TEST_LOG if defined $TEST_LOG && -e $TEST_LOG && !$ENV{KEEP_LOG};
    unlink $ROUTES if defined $ROUTES && -e $ROUTES;
}

spawn(sub { while (1) { $relay->pump(0.05) } });
spawn(sub { $endpoint->register; while (1) { $endpoint->pump(0.05) } });
spawn(sub { $gateway->run });

sub events_of {
    my ($kind) = @_;
    open my $fh, '<', $log_path or return ();
    my @out;
    while (my $line = <$fh>) {
        my $rec = eval { JSON::PP->new->decode($line) };
        push @out, $rec if $rec && ($rec->{kind} // '') eq $kind;
    }
    return @out;
}

sub cdr_events { return events_of('cdr') }

# Drive the carrier and (optionally) the phone for a while.  Everything else
# runs in its own process, so this is the test's whole side of the wire.
sub spin {
    my ($seconds, $phone) = @_;
    my $until = time + $seconds;
    while (time < $until) {
        $carrier->pump;
        $phone->pump_tick if $phone;
        sleep 0.002;
    }
}

# Audio needs the media path up as well as both ends running; how many frames
# that takes depends on the host, so ask "does it arrive", not "did it arrive
# inside one window".
sub wait_audio {
    my ($phone, $seconds) = @_;
    my $deadline = time + $seconds;
    my ($peak, $frames) = (0, 0);
    while (time < $deadline) {
        $phone->window_reset;
        spin(0.6, $phone);
        my $w = $phone->window;
        $frames += $w->{rx_frames};
        $peak = $w->{rx_peak} if $w->{rx_peak} > $peak;
        last if $peak > 0;
    }
    return { rx_frames => $frames, rx_peak => $peak };
}

sub wait_for_event {
    my ($kind, $seconds, $phone) = @_;
    my $deadline = time + $seconds;
    while (time < $deadline) {
        spin(0.1, $phone);
        my ($ev) = events_of($kind);
        return $ev if $ev;
    }
    return undef;
}

# ---------------------------------------------------------------- register

my $phone = Cantus::Phone->new(
    server => "127.0.0.1:$sip_port", user => '101', password => 'test123',
    local_port => free_port(), rtp_port => free_port(), quiet => 1,
);
ok($phone->register, '101 registers with the gateway');

my $reg = wait_for_event('trunk-registered', 12);
ok($reg, 'the gateway registers its own account with the carrier');
is($carrier->{registrations}, 1, 'the carrier answered the REGISTER with 200');
ok($carrier->{digest_ok}, 'and the digest the gateway computed is the one the carrier expects');
ok($carrier->{challenged} >= 1, 'having been challenged first, not trusted on the first try');
is($reg->{user}, '235662_test', 'the registration names the sub-account');

# ---------------------------------------------------------------- inbound DID

# The routing document is the only source for an inbound DID. A carrier picks a
# digit form and the document names both; a rule that refuses is a decision the
# carrier is told about, not a lookup that failed.

sub did_event {
    my ($kind, $did, $seconds) = @_;
    my $deadline = time + ($seconds // 3);
    while (time < $deadline) {
        spin(0.2);
        my ($ev) = grep { ($_->{did} // '') eq $did } events_of($kind);
        return $ev if $ev;
    }
    return undef;
}

my $eleven = do {
    $carrier->invite_in(did => '14132642700', gw => "127.0.0.1:$sip_port");
    my $ev = did_event('trunk-invite', '14132642700');
    $carrier->bye_in("127.0.0.1:$sip_port");
    spin(0.6);
    $ev;
};
ok($eleven, 'the eleven-digit DID is placed from the document');
is($eleven->{route}, 'did-14132642700', 'quoting the eleven-digit route');
is($eleven->{to}, 'gw-101@trunk.test', 'to line 101, which the rule names');

my $ten = do {
    $carrier->invite_in(did => '4132642700', gw => "127.0.0.1:$sip_port");
    my $ev = did_event('trunk-invite', '4132642700');
    $carrier->bye_in("127.0.0.1:$sip_port");
    spin(0.6);
    $ev;
};
ok($ten, 'and the ten-digit form of the same DID lands on it');
is($ten->{route}, 'did-4132642700', 'through its own route');
is($ten->{to}, 'gw-101@trunk.test', 'to line 101');

# A fax number: the document says reject, so the carrier is refused — not 404.
$carrier->invite_in(did => '14135550111', gw => "127.0.0.1:$sip_port");
spin(1.2);
is($carrier->{in}{code}, 403, 'a fax number is refused by its rule');
my $fax = did_event('trunk-rejected-did', '14135550111', 1);
ok($fax, 'and the refusal is logged with the number');
is($fax->{route}, 'did-14135550111-fax', 'quoting the fax route');
is($fax->{code}, 403, 'with the status the carrier was sent');

# A DID we own with no line to answer it: the document refuses that too.
$carrier->invite_in(did => '14135550112', gw => "127.0.0.1:$sip_port");
spin(1.2);
is($carrier->{in}{code}, 403, 'a DID with no line is refused by its rule');
my $unrouted = did_event('trunk-rejected-did', '14135550112', 1);
is($unrouted->{route}, 'did-14135550112-unrouted', 'quoting the unrouted route');

# A number the document does not know falls to its default, which is a refusal:
# the gateway never invents a destination.
$carrier->invite_in(did => '9999999999', gw => "127.0.0.1:$sip_port");
spin(1.2);
is($carrier->{in}{code}, 403, 'an unknown number takes the document default');
my $unknown = did_event('trunk-rejected-did', '9999999999', 1);
ok($unknown, 'and is logged as rejected, not as a routing failure');
ok(!defined $unknown->{route}, 'with no route name, because none matched');

# ---------------------------------------------------------------- outbound

my ($ok, $why) = $phone->invite('4443');
ok($ok, "101 dials 4443, the carrier's echo test ($why)");
spin(2.0, $phone);
($ok, $why) = $phone->wait_answered(5);
ok($ok, "the call is answered ($why)");

my $out = $carrier->{out};
is($out->{to}, '4443', 'the carrier leg asks for the number that was dialled');
is($out->{from}, $DID, 'and presents the DID as the caller');
ok($carrier->{invite_challenged} >= 1, 'the carrier challenges the outbound INVITE, as it did the REGISTER');
ok($carrier->{invite_digest_ok}, 'and the gateway answers the challenge with a valid digest');

# Both ends have to run for either one to carry audio: the carrier only sends
# while it is pumped, so a phone-only window measures nothing.
my $rx_before = $carrier->{rx_frames};
my $pa = wait_audio($phone, 8);
cmp_ok($pa->{rx_peak}, '>', 0, "the extension hears the carrier ($pa->{rx_frames} frames)");
cmp_ok($carrier->{rx_frames} - $rx_before, '>', 5, 'and the carrier hears the extension');

ok($phone->bye, '101 hangs up the carrier call');
spin(1.0);
is($carrier->{byes}, 1, 'the carrier is told the call ended');
my ($outbound) = grep { ($_->{line} // '') eq '101' && ($_->{to} // '') eq '4443' } cdr_events();
ok($outbound, 'the outbound call is in the CDR');
ok($outbound->{answered}, 'as answered');
cmp_ok($outbound->{rx_frames}, '>', 5, 'with audio in both directions');

# A number no route allows never reaches the carrier.
my $invites_before = scalar @{ $carrier->{invites} };
my $bad = Cantus::Phone->new(
    server => "127.0.0.1:$sip_port", user => '101', password => 'test123',
    local_port => free_port(), rtp_port => free_port(), quiet => 1,
);
$bad->register;
($ok, $why) = $bad->invite('5551234');
($ok, $why) = $bad->wait_answered(4) if $ok;
ok(!$ok, "a number with no route is refused ($why)");
spin(0.6);
is(scalar @{ $carrier->{invites} }, $invites_before, 'and nothing was sent to the carrier');
my ($refused) = grep { ($_->{line} // '') eq '101' && ($_->{result} // '') eq 'no route' } cdr_events();
ok($refused, 'the refusal is in the CDR as a call that never left');

reap();
pass('all components stopped');
done_testing();
