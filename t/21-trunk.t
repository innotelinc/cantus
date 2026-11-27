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
$ENV{PEER_SECRET}      = 'peer-secret';

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
    # The carrier's signalling proxy: it records its route on the calls it
    # carries, so an in-dialog request from the far end has to come through it.
    my $proxy = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                      Proto => 'udp', ReuseAddr => 1) or die "carrier proxy: $!";
    $sip->blocking(0);
    $rtp->blocking(0);
    $proxy->blocking(0);
    return bless {
        sip => $sip, rtp => $rtp, proxy => $proxy,
        sip_port => (sockaddr_in($sip->sockname))[0],
        rtp_port => (sockaddr_in($rtp->sockname))[0],
        proxy_port => (sockaddr_in($proxy->sockname))[0],
        user => $a{user}, password => $a{password},
        registrations => 0, challenged => 0, digest_ok => 0,
        invites => [], acks => 0, byes => 0,
        proxied => [], proxy_forwarded => 0,
        in => undef, out => undef,
        rx_frames => 0, rx_peak => 0, phase => 0, seq => 0, ts => 0,
    }, $class;
}

sub port       { $_[0]{sip_port} }
sub rtp_port   { $_[0]{rtp_port} }
sub addr       { '127.0.0.1:' . $_[0]{sip_port} }

sub _send_from {
    my ($self, $sock, $text, $to) = @_;
    my ($ip, $port) = split /:/, $to, 2;
    return unless $ip && $port;
    CORE::send($sock, $text, 0, sockaddr_in($port, inet_aton($ip)));
}

sub _send {
    my ($self, $text, $to) = @_;
    $self->_send_from($self->{sip}, $text, $to);
}

# The hop that recorded its route, which is where an in-dialog request has to go
# once a proxy is in the call. A request addressed straight at the UAS never
# arrives here at all, which is exactly the failure being modelled.
sub _pump_proxy {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $peer = recv($self->{proxy}, $buf, 65535, 0);
        last unless defined $peer && length $buf;
        my $msg = Cantus::Sip::parse($buf) or next;
        next unless $msg->{request};
        push @{ $self->{proxied} }, {
            method => $msg->{method} // '?',
            uri    => $msg->{uri} // '',
            route  => join('|', @{ Cantus::Sip::headers_all($msg, 'route') }),
        };
        # Popped and passed on as a loose proxy does. The headers are forwarded
        # unchanged: where the request went and how it was addressed is the test.
        $self->_send_from($self->{proxy}, $buf, '127.0.0.1:' . $self->{sip_port});
        $self->{proxy_forwarded}++;
    }
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
    my $caller = $a{caller} // '14135550100';
    # Kept verbatim, because the dialog this carrier opened is the only thing
    # that can say whether a BYE from the gateway belongs to it. The request-URI
    # a BYE has to carry is the bare URI inside this Contact, never the
    # bracketed form.
    my $contact_uri = "sip:carrier\@127.0.0.1:$self->{sip_port}";
    my $contact = "<$contact_uri>";
    # A carrier edge in the path records itself, as voip.ms's does.
    my $route = "<sip:127.0.0.1:$self->{proxy_port};lr>";
    # voip.ms sends its INVITE at 102, and its edge counts the dialog's CSeq
    # from there: a hangup that arrives as 1 is not the next request it expects.
    my $cseq = $a{cseq} // 102;
    $self->{in} = { call => $call, did => $a{did}, caller => $caller, cseq => $cseq,
                    from_tag => $from_tag, state => 'calling', code => 0,
                    from_hdr => "<sip:$caller\@carrier.example>;tag=$from_tag",
                    to_hdr   => "<sip:$a{did}\@$gw>",
                    contact  => $contact_uri, route => $route };
    my $text = Cantus::Sip::request(
        method  => 'INVITE',
        uri     => "sip:$a{did}\@$gw",
        via     => '127.0.0.1:' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => $self->{in}{from_hdr},
        to      => $self->{in}{to_hdr},
        call_id => $call,
        cseq    => $cseq,
        contact => $contact,
        headers => [ "Record-Route: $route" ],
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
    $self->_pump_proxy;
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
            headers => [ 'Record-Route: <sip:127.0.0.1:' . $self->{proxy_port} . ';lr>' ],
            sdp => $self->_sdp,
        ), $msg->{src});
        $self->{out}{state} = 'active';
        return;
    }

    if ($method eq 'ACK')  { $self->{acks}++; return }
    if ($method eq 'BYE')  {
        $self->{byes}++;
        # A UAS places an in-dialog request only inside the dialog it opened:
        # same Call-ID, the From it sent (URI and tag), a To carrying the tag
        # from its own 200, a request-URI naming the Contact it published, and
        # a CSeq that continues the one its INVITE carried. Anything else is
        # 481 -- and a caller whose phone never drops is exactly what a 481
        # looks like from the far side of the call.
        my $in = $self->{in};
        my $call = Cantus::Sip::header($msg, 'call-id') // '';
        my $cseq = (Cantus::Sip::header($msg, 'cseq') // '') =~ /^(\d+)/ ? $1 : 0;
        $self->{bye_cseq} = $cseq;
        my ($placed, $why) = (0, 'no call to place it in');
        if ($in && $call eq $in->{call}) {
            my $from = Cantus::Sip::header($msg, 'from') // '';
            my $to   = Cantus::Sip::header($msg, 'to') // '';
            my $uri  = $msg->{uri} // '';
            my $want_to = $in->{to_hdr} . ';tag=' . ($in->{to_tag} // 'gw');
            my $want_cseq = ($in->{cseq} // 0) + 1;
            if    ($from ne $in->{from_hdr}) { $why = "From $from" }
            elsif ($to   ne $want_to)        { $why = "To $to (want $want_to)" }
            elsif ($uri  ne $in->{contact})  { $why = "request-URI $uri" }
            elsif ($cseq != $want_cseq)      { $why = "CSeq $cseq (want $want_cseq)" }
            else  { ($placed, $why) = (1, 'matched') }
        }
        $self->{bye_placed} = $placed;
        $self->{bye_why} = $why;
        $self->_send(Cantus::Sip::response($msg, $placed ? 200 : 481), $msg->{src});
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

# ---------------------------------------------------------------- the peer
#
# The internal switch, the way Asterisk answers a call addressed to `sip:101`:
# nothing authenticates it, one extension answers, and its media is an echo, so
# a frame that crosses the gateway comes back as audio.

package Peer;

use Socket qw(sockaddr_in inet_aton inet_ntoa);

sub new {
    my ($class, %a) = @_;
    my $sip = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                    Proto => 'udp', ReuseAddr => 1) or die "peer sip: $!";
    my $rtp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                    Proto => 'udp', ReuseAddr => 1) or die "peer rtp: $!";
    $sip->blocking(0);
    $rtp->blocking(0);
    return bless {
        sip => $sip, rtp => $rtp,
        port => (sockaddr_in($sip->sockname))[0],
        rtp_port => (sockaddr_in($rtp->sockname))[0],
        invites => [], acks => 0, byes => 0, cancels => 0,
        challenged => 0, auth_ok => 0, password => $a{password},
        call => undef, to_tag => 'peer1', remote => undef,
        rx_frames => 0, phase => 0, seq => 0, ts => 0,
    }, $class;
}

sub port { $_[0]{port} }
sub addr { '127.0.0.1:' . $_[0]{port} }

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

# The softphone hangs up: the switch sends the BYE, and the edge has to pass it
# on to the carrier rather than leave that leg billed.
sub hangup {
    my ($self) = @_;
    return unless $self->{call} && $self->{gw};
    my $text = Cantus::Sip::request(
        method  => 'BYE',
        uri     => 'sip:' . ($self->{to_user} // '101') . '@' . $self->{gw},
        via     => '127.0.0.1:' . $self->{port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => '<sip:' . ($self->{to_user} // '101') . "\@peer.test>;tag=$self->{to_tag}",
        to      => '<sip:' . ($self->{from_user} // 'x') . "\@peer.test>;tag=" . ($self->{gw_from_tag} // 'gw'),
        call_id => $self->{call},
        cseq    => 2,
        contact => '<sip:101@127.0.0.1:' . $self->{port} . '>',
    );
    $self->_send($text, $self->{gw});
}

sub pump {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $from = recv($self->{sip}, $buf, 65535, 0);
        last unless defined $from && length $buf;
        my ($port, $iaddr) = sockaddr_in($from);
        my $msg = Cantus::Sip::parse($buf) or next;
        $msg->{src} = inet_ntoa($iaddr) . ':' . $port;
        $self->_request($msg) if $msg->{request};
    }
    while (1) {
        my $buf;
        my $from = recv($self->{rtp}, $buf, 4096, 0);
        last unless defined $from && length $buf;
        my ($port, $iaddr) = sockaddr_in($from);
        my $pkt = Cantus::Sip::rtp_parse($buf) or next;
        next unless $pkt->{pt} == 0;
        next unless length Cantus::G711::mu_to_pcm($pkt->{payload});
        $self->{remote} = inet_ntoa($iaddr) . ':' . $port;
        $self->{rx_frames}++;
    }
    return unless $self->{call} && $self->{remote};
    my ($pcm, $phase) = Cantus::Media::pcm_frame(hz => 440, amp => 6000, phase => $self->{phase});
    $self->{phase} = $phase;
    my $payload = Cantus::G711::pcm_to_mu($pcm);
    my ($ip, $port) = split /:/, $self->{remote}, 2;
    CORE::send($self->{rtp},
        Cantus::Sip::rtp_build(pt => 0, seq => $self->{seq}++, ts => $self->{ts},
                               ssrc => 0xBEEF, payload => $payload),
        0, sockaddr_in($port, inet_aton($ip)));
    $self->{ts} += 160;
}

sub _request {
    my ($self, $msg) = @_;
    my $method = $msg->{method} // '';
    if ($method eq 'INVITE') {
        # A switch that trusts "it came from loopback" is a switch anything on
        # the host can call. The edge is challenged like any other trunk.
        my $auth = Cantus::Sip::header($msg, 'authorization');
        unless ($auth) {
            $self->{challenged}++;
            $self->_send(Cantus::Sip::response($msg, 401,
                headers => [ Cantus::Sip::challenge_header('peer.test', 'nonce-peer-' . $$) ]),
                $msg->{src});
            return;
        }
        my ($ok) = Cantus::Sip::verify_digest(
            msg => $msg, method => 'INVITE',
            user => 'cantus-edge', password => $self->{password}, realm => 'peer.test',
        );
        $self->{auth_ok} = $ok ? 1 : 0;
        unless ($ok) {
            $self->_send(Cantus::Sip::response($msg, 403), $msg->{src});
            return;
        }
        my $to = Cantus::Sip::parse_uri($msg->{uri});
        my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
        my $ext = $to ? $to->{user} : undef;
        push @{ $self->{invites} }, {
            call => Cantus::Sip::header($msg, 'call-id'),
            to   => $ext,
            from => $from ? $from->{user} : undef,
            did  => Cantus::Sip::header($msg, 'x-cantus-did'),
        };
        $self->{call} = Cantus::Sip::header($msg, 'call-id');
        $self->{gw} = $msg->{src};
        $self->{to_user} = $ext;
        $self->{from_user} = $from ? $from->{user} : undef;
        $self->{gw_from_tag} = Cantus::Sip::tag($msg, 'from');
        $self->_send(Cantus::Sip::response($msg, 180, to_tag => $self->{to_tag}), $msg->{src});
        # One extension refuses, one never picks up, the rest answer: the three
        # outcomes the gateway has to turn into a carrier response.
        if ($ext eq '102') {
            $self->_send(Cantus::Sip::response($msg, 486, to_tag => $self->{to_tag}), $msg->{src});
            return;
        }
        if ($ext eq '103') { return }
        $self->_send(Cantus::Sip::response(
            $msg, 200, to_tag => $self->{to_tag},
            contact => '<sip:101@127.0.0.1:' . $self->{port} . '>',
            sdp => $self->_sdp,
        ), $msg->{src});
        return;
    }
    if ($method eq 'ACK') { $self->{acks}++; return }
    if ($method eq 'BYE') {
        $self->{byes}++;
        $self->_send(Cantus::Sip::response($msg, 200), $msg->{src});
        $self->{call} = undef;
        return;
    }
    if ($method eq 'CANCEL') {
        $self->{cancels}++;
        $self->_send(Cantus::Sip::response($msg, 200), $msg->{src});
        return;
    }
    $self->_send(Cantus::Sip::response($msg, 405), $msg->{src});
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
my $peer = Peer->new(password => 'peer-secret');

my $routes_path = "/tmp/cantus-routes-$$.json";
open my $rfh, '>', $routes_path or die $!;
print $rfh JSON::PP->new->canonical->encode({
    version => 1,
    default => { reject => 3 },
    routes  => [
        { name => 'carrier-echo', when => { to => '4443' },
          then => [ { forward => { to => 'pstn:4443' } } ] },
        # One rule per DID. The edge normalises E.164 and the national number
        # before it decides, so the carrier's choice of form needs no route.
        { name => 'did-14132642700', when => { to => '14132642700' },
          then => [ { answer => {} }, { forward => { to => 'ext:101' } } ] },
        # Numbers we own but do not answer: the document refuses them.
        { name => 'did-14135550111-fax', when => { to => '14135550111' },
          then => [ { reject => 3 } ] },
        { name => 'did-14135550112-unrouted', when => { to => '14135550112' },
          then => [ { reject => 3 } ] },
        # Rules that name a SIP target: extensions on the internal peer.
        { name => 'did-14135550120-sip', when => { to => '14135550120' },
          then => [ { answer => {} }, { forward => { to => 'sip:101' } } ] },
        { name => 'did-14135550121-sip', when => { to => '14135550121' },
          then => [ { answer => {} }, { forward => { to => 'sip:101' } } ] },
        { name => 'did-14135550122-sip', when => { to => '14135550122' },
          then => [ { answer => {} }, { forward => { to => 'sip:102' } } ] },
        { name => 'did-14135550123-sip', when => { to => '14135550123' },
          then => [ { answer => {} }, { forward => { to => 'sip:103' } } ] },
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
        peer => { name => 'test', host => '127.0.0.1', port => $peer->port,
                  realm => 'peer.test', user => 'cantus-edge', secret_env => 'PEER_SECRET' },
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
        $peer->pump;
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
is($ten->{route}, 'did-14132642700', 'through the one rule the document carries');
is($ten->{to}, 'gw-101@trunk.test', 'to line 101');

# E.164 is the third spelling of the same number and takes the same rule.
my $e164 = do {
    my %seen = map { ($_->{call} // '') => 1 } events_of('trunk-invite');
    $carrier->invite_in(did => '+14132642700', gw => "127.0.0.1:$sip_port");
    my $ev;
    my $deadline = time + 3;
    while (time < $deadline && !$ev) {
        spin(0.2);
        ($ev) = grep { !$seen{$_->{call} // ''} } events_of('trunk-invite');
    }
    $carrier->bye_in("127.0.0.1:$sip_port");
    spin(0.6);
    $ev;
};
ok($e164, 'and the E.164 form is still the same call');
is($e164->{route}, 'did-14132642700', 'matched without a route per form');

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
# Six digits, so it is not a North American number and no outbound rule's
# `1*` pattern can match it either: the default is what is being tested.
$carrier->invite_in(did => '999999', gw => "127.0.0.1:$sip_port");
spin(1.2);
is($carrier->{in}{code}, 403, 'an unknown number takes the document default');
my $unknown = did_event('trunk-rejected-did', '999999', 1);
ok($unknown, 'and is logged as rejected, not as a routing failure');
ok(!defined $unknown->{route}, 'with no route name, because none matched');

# ------------------------------------------------- inbound DID to the peer
#
# A rule that names `sip:101` sends the call to the internal switch instead of a
# Cantus line: the carrier is answered only once that switch answers, and the
# two legs bridge audio both ways.

my $carrier_rx_before = $carrier->{rx_frames};
$carrier->invite_in(did => '14135550120', gw => "127.0.0.1:$sip_port");
my $peer_iv = did_event('peer-invite', '14135550120', 3);
ok($peer_iv, 'a sip: target places a leg to the internal peer');
is($peer_iv->{to}, '101', 'addressed to the extension the rule named');
is($peer_iv->{host}, '127.0.0.1', 'at the configured peer host');

spin(2.0);
is($carrier->{in}{code}, 200, 'the carrier is answered once the peer answers');
ok(@{ $peer->{invites} } >= 1, 'the peer saw the INVITE');
is($peer->{invites}[-1]{to}, '101', 'for extension 101');
# The peer is dialled by extension, so the DID it was reached on is not in the
# request URI. The switch behind the peer is the one that logs the call, and a
# row naming the line instead of the dialled number is a row the operator cannot
# reconcile: the number travels on the leg as a header.
is($peer->{invites}[-1]{did}, '14135550120',
   'and carries the DID it arrived on, so the switch can log the dialled number');
ok($peer->{acks} >= 1, 'and the gateway ACKed the peer 200');
cmp_ok($peer->{rx_frames}, '>', 0, 'carrier audio crossed the gateway to the peer');
cmp_ok($carrier->{rx_frames} - $carrier_rx_before, '>', 0, 'and peer audio came back');

# One 20 ms frame per leg per 20 ms. The loop runs hundreds of times a second,
# and a packet on every pass put nearly twice the audio on the wire: each
# inbound queue was drained into padding, which is what choppy audio is.
my $peer_frames_before = $peer->{rx_frames};
my $paced_at = time;
spin(2.0);
my $paced = ($peer->{rx_frames} - $peer_frames_before) / (time - $paced_at);
cmp_ok($paced, '<=', 60,
    sprintf('the peer leg is paced at 50 frames a second, not the loop rate (%.0f/s)', $paced));
cmp_ok($paced, '>=', 35, sprintf('and it is not starved below that clock (%.0f/s)', $paced));

$carrier->bye_in("127.0.0.1:$sip_port");
spin(1.0);
ok($peer->{byes} >= 1, 'hanging up the carrier leg ends the peer leg too');

# The edge is not trusted for being on loopback: the peer challenged it, and
# the call above only went through because the digest was answered.
ok($peer->{challenged} >= 1, 'the peer challenged the edge INVITE');
ok($peer->{auth_ok}, 'and the edge answered with its own secret, not its address');

# ------------------------------------------ the softphone hangs up
# The direction that was not covered: the switch holding the softphone sends
# the BYE, and the carrier leg has to be released rather than left up.
my $byes_before = $carrier->{byes};
$carrier->invite_in(did => '14135550121', gw => "127.0.0.1:$sip_port");
spin(2.0);
is($carrier->{in}{code}, 200, 'a second DID is answered by the peer');
$peer->hangup;
spin(1.2);
cmp_ok($carrier->{byes}, '>', $byes_before, 'the softphone hanging up sends the carrier a BYE');
ok($carrier->{bye_placed},
   'and the carrier can place that BYE in the dialog it opened')
    or diag("the BYE did not match the carrier's dialog: $carrier->{bye_why}");
is($carrier->{bye_cseq}, ($carrier->{in}{cseq} // 0) + 1,
   'and it continues the dialog CSeq the INVITE carried, rather than restarting at 1');

# The carrier's edge recorded its route on the INVITE, so the hangup has to travel
# through it: a BYE addressed straight at the UAS never reaches the proxy that
# holds the call, which is what a 481 and a caller still connected look like.
my ($proxy_bye) = grep { $_->{method} eq 'BYE' } @{ $carrier->{proxied} };
ok($proxy_bye, 'the BYE follows the route set to the proxy that recorded it');
is($proxy_bye ? $proxy_bye->{uri} : '', $carrier->{in}{contact},
   'addressed to the carrier Contact, not the extension');
like($proxy_bye ? $proxy_bye->{route} : '', qr/127\.0\.0\.1:$carrier->{proxy_port};lr/,
     'and carrying the hop the call came through');

# A chain arrives as repeated headers or as one comma-separated value; keeping
# only the first hop is the bug this guards against.
my $chain = Cantus::Sip::parse(
    "INVITE sip:x\@y SIP/2.0\r\nRecord-Route: <sip:p1.example;lr>\r\n"
  . "Record-Route: <sip:p2.example;lr>, <sip:p3.example;lr>\r\n\r\n");
is(scalar @{ Cantus::Sip::headers_all($chain, 'record-route') }, 2,
   'every Record-Route header is kept, not only the first');
my ($hung) = grep { ($_->{from} // '') eq '14135550121' } cdr_events();
ok($hung, 'and the call is closed in the CDR');
ok($hung->{answered}, 'as an answered call, not a failed one');

# ------------------------------------------------- a peer that refuses
$carrier->invite_in(did => '14135550122', gw => "127.0.0.1:$sip_port");
spin(1.5);
is($carrier->{in}{code}, 486, 'a refusing peer is passed to the carrier as 486');
my ($refused_cdr) = grep { ($_->{from} // '') eq '14135550122' } cdr_events();
ok($refused_cdr, 'the refusal is in the CDR');
ok(!$refused_cdr->{answered}, 'not as an answered call');

# -------------------------------------------- a peer that never answers
$carrier->invite_in(did => '14135550123', gw => "127.0.0.1:$sip_port");
spin(4.5);
is($carrier->{in}{code}, 408, 'a peer that never answers gives the carrier 408');
ok($peer->{cancels} >= 1, 'and its leg was cancelled rather than left ringing');

# The carrier gives up while the peer is still ringing: the INVITE to the peer
# has to be cancelled, or the extension rings on for a call nobody is on.
my $cancels_before = $peer->{cancels};
$carrier->invite_in(did => '14135550123', gw => "127.0.0.1:$sip_port");
spin(0.8);
$carrier->bye_in("127.0.0.1:$sip_port");
spin(1.0);
cmp_ok($peer->{cancels}, '>', $cancels_before,
    'and a carrier hangup cancels a peer leg that had not answered');

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
my ($proxy_ack) = grep { $_->{method} eq 'ACK' } @{ $carrier->{proxied} };
ok($proxy_ack, 'an ACK for a carrier answer travels the same route set');

# Both ends have to run for either one to carry audio: the carrier only sends
# while it is pumped, so a phone-only window measures nothing.
my $pa = wait_audio($phone, 8);
cmp_ok($pa->{rx_peak}, '>', 0, "the extension hears the carrier ($pa->{rx_frames} frames)");
# The carrier sends its tone the moment the call is up, so the slice above can be
# a single 0.6 s window while the phone is still starting to send. Count the
# other direction over a window of its own: at 50 frames a second this owes 60,
# and a handful of frames is a start rather than a media path.
my $tx_before = $carrier->{rx_frames};
spin(1.2, $phone);
my $carrier_got = $carrier->{rx_frames} - $tx_before;
cmp_ok($carrier_got, '>=', 20,
    "and the carrier hears the extension ($carrier_got frames in 1.2 s)");

my $byes_at_dial = $carrier->{byes};
ok($phone->bye, '101 hangs up the carrier call');
spin(1.0);
is($carrier->{byes} - $byes_at_dial, 1, 'the carrier is told the call ended');
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
