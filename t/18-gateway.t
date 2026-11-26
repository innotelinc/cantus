#!/usr/bin/perl
# The gateway is a translation layer, so the pieces that can be wrong in a way
# nobody notices are tested directly: companding, digest auth, SDP negotiation
# and RTP framing. A live call proves the rest.
use strict;
use warnings;
use Test::More;
use lib 'lib';

use Digest::MD5 qw(md5_hex);
use Cantus::G711 ();
use Cantus::Sip ();
use Cantus::Media ();

# ---------------------------------------------------------------- G.711

my ($pcm, undef) = Cantus::Media::pcm_frame(hz => 1000, amp => 6000, samples => 160);
is(length($pcm), 320, 'a 20 ms pcm-s16 frame is 320 octets');

my $mu = Cantus::G711::pcm_to_mu($pcm);
is(length($mu), 160, 'mu-law is one octet per sample');
my $back = Cantus::G711::mu_to_pcm($mu);
is(length($back), 320, 'and back to 320 octets');
my $peak = Cantus::Media::peak($back);
cmp_ok(abs($peak - 6000), '<', 400, "mu-law round-trip keeps the amplitude (peak $peak)");

my $al = Cantus::G711::pcm_to_a($pcm);
is(length($al), 160, 'a-law is one octet per sample');
my $apeak = Cantus::Media::peak(Cantus::G711::a_to_pcm($al));
cmp_ok(abs($apeak - 6000), '<', 400, "a-law round-trip keeps the amplitude (peak $apeak)");

is(Cantus::Media::peak(Cantus::G711::mu_to_pcm(Cantus::G711::mu_silence())), 0,
   'mu-law silence decodes to silence');
cmp_ok(Cantus::Media::peak(Cantus::G711::a_to_pcm(Cantus::G711::a_silence())), '<', 32,
   'a-law silence is quiet');

# A frame of zeros must encode to the idle pattern, not to noise: this is the
# difference between a quiet line and a hiss the caller hears.
my $zeros = "\0" x 320;
is(Cantus::G711::pcm_to_mu($zeros), Cantus::G711::mu_silence(),
   'digital silence encodes to the mu-law idle pattern');

# ---------------------------------------------------------------- SIP parse

my $invite = join("\r\n",
    'INVITE sip:node@192.168.1.53:5062 SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK123',
    'From: <sip:101@192.168.1.20>;tag=abc123',
    'To: <sip:node@192.168.1.53>',
    'Call-ID: call-42',
    'CSeq: 7 INVITE',
    'Contact: <sip:101@192.168.1.20:5060>',
    'Content-Type: application/sdp',
    'Content-Length: 100',
    '',
    'v=0',
    'c=IN IP4 192.168.1.20',
    'm=audio 40000 RTP/AVP 0 8 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:8 PCMA/8000',
    'a=rtpmap:101 telephone-event/8000',
    'a=ptime:20',
) . "\r\n";

my $msg = Cantus::Sip::parse($invite);
ok($msg && $msg->{request}, 'an INVITE parses as a request');
is($msg->{method}, 'INVITE', 'method');
is($msg->{uri}, 'sip:node@192.168.1.53:5062', 'uri');
is(Cantus::Sip::header($msg, 'call-id'), 'call-42', 'header lookup is case-insensitive');
is(Cantus::Sip::tag($msg, 'from'), 'abc123', 'the From tag is found');
is(Cantus::Sip::tag($msg, 'to'), undef, 'and a missing To tag is undef');

my $folded = "OPTIONS sip:x SIP/2.0\r\nSubject: one\r\n  two\r\nContent-Length: 0\r\n\r\n";
my $f = Cantus::Sip::parse($folded);
is(Cantus::Sip::header($f, 'subject'), 'one two', 'a folded header is unfolded');

my $resp = Cantus::Sip::response($msg, 200, to_tag => 'gw1', contact => '<sip:101@192.168.1.53:5062>');
like($resp, qr/^SIP\/2\.0 200 OK\r\n/, 'a 200 is built');
like($resp, qr/Via: SIP\/2\.0\/UDP 192\.168\.1\.20:5060;branch=z9hG4bK123/, 'the caller Via is echoed');
like($resp, qr/To: <sip:node\@192\.168\.1\.53>;tag=gw1/, 'the To tag is added');
like($resp, qr/CSeq: 7 INVITE/, 'the CSeq is echoed');
like($resp, qr/Content-Length: 0/, 'and the body is empty');

# ---------------------------------------------------------------- SDP

my $sdp = Cantus::Sip::sdp_parse($msg->{body});
is($sdp->{codec}, 'PCMU', 'PCMU is taken from the offer');
is($sdp->{ip}, '192.168.1.20', 'the media address is read');
is($sdp->{port}, 40000, 'the media port is read');
is($sdp->{ptime}, 20, 'ptime is read');

my $pcma = Cantus::Sip::sdp_parse("c=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 8\r\n");
is($pcma->{codec}, 'PCMA', 'PCMA is recognised');

is(Cantus::Sip::sdp_parse("c=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 18\r\n"), undef,
   'a G.729-only offer is refused rather than answered blindly');

my $answer = Cantus::Sip::sdp_answer(ip => '192.168.1.53', port => 41000, codec => 'PCMU');
like($answer, qr/m=audio 41000 RTP\/AVP 0/, 'the answer names our port and PCMU');
like($answer, qr/a=ptime:20/, 'at 20 ms');
like($answer, qr/c=IN IP4 192\.168\.1\.53/, 'and our address');

# ---------------------------------------------------------------- digest

my %d = (
    user => '101', password => 'test123', realm => 'cantus',
    method => 'REGISTER', uri => 'sip:192.168.1.53:5062', nonce => 'nonce123',
);
my $ha1 = md5_hex("101:cantus:test123");
my $ha2 = md5_hex("REGISTER:sip:192.168.1.53:5062");
my $want = md5_hex("$ha1:nonce123:$ha2");
is(Cantus::Sip::digest_response(%d), $want, 'digest matches the RFC 2617 arithmetic');

my $authed = Cantus::Sip::parse(join("\r\n",
    'REGISTER sip:192.168.1.53:5062 SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK1',
    'From: <sip:101@192.168.1.20>;tag=t1',
    'To: <sip:101@192.168.1.20>',
    'Call-ID: reg-1',
    'CSeq: 1 REGISTER',
    qq{Authorization: Digest username="101", realm="cantus", nonce="nonce123", uri="sip:192.168.1.53:5062", response="$want", algorithm=MD5},
    'Content-Length: 0', '',
))
    or die 'test REGISTER did not parse';

my ($ok, $why) = Cantus::Sip::verify_digest(
    msg => $authed, method => 'REGISTER', user => '101', password => 'test123', realm => 'cantus',
);
ok($ok, "a correctly signed REGISTER verifies ($why)");

my ($bad) = Cantus::Sip::verify_digest(
    msg => $authed, method => 'REGISTER', user => '101', password => 'wrong', realm => 'cantus',
);
ok(!$bad, 'and a wrong password does not');

my ($nouser) = Cantus::Sip::verify_digest(
    msg => $msg, method => 'INVITE', user => '101', password => 'test123', realm => 'cantus',
);
ok(!$nouser, 'a request with no credentials does not verify');

# ---------------------------------------------------------------- RTP

my $packet = Cantus::Sip::rtp_build(pt => 0, seq => 42, ts => 8000, ssrc => 0xCA97, payload => $mu);
my $rtp = Cantus::Sip::rtp_parse($packet);
is($rtp->{pt}, 0, 'RTP payload type survives');
is($rtp->{seq}, 42, 'RTP sequence survives');
is($rtp->{ts}, 8000, 'RTP timestamp survives');
is($rtp->{payload}, $mu, 'RTP payload survives');

my $csrc = "\x82\x00" . pack('nNN', 1, 0, 9) . 'csrcdata' . 'payload';
my $c = Cantus::Sip::rtp_parse($csrc);
is($c->{payload}, 'payload', 'a CSRC-bearing packet is parsed from the right offset');

# ---------------------------------------------------------------- DTMF

my $event = Cantus::Sip::rtp_event_build(
    event => Cantus::Sip::dtmf_event_id('5'), duration => 320);
is(length $event, 4, 'an RFC 4733 event is four octets');
my $pe = Cantus::Sip::rtp_event_parse($event);
is($pe->{event}, 5, 'the event id is read back');
is($pe->{duration}, 320, 'and the duration');
ok(!$pe->{end}, 'a press in progress is not the end');
ok(Cantus::Sip::rtp_event_parse(Cantus::Sip::rtp_event_build(event => 5, end => 1))->{end},
   'and the end bit survives');
is(Cantus::Sip::dtmf_digit(5), '5', 'event 5 is the digit 5');
is(Cantus::Sip::dtmf_digit(10), '*', 'event 10 is star');
is(Cantus::Sip::dtmf_digit(11), '#', 'event 11 is hash (RFC 4733: 12-15 are A-D)');
is(Cantus::Sip::dtmf_digit(12), 'A', 'and 12 is A');
is(Cantus::Sip::dtmf_event_id('#'), 11, 'and the mapping goes both ways');
is(Cantus::Sip::dtmf_digit(99), undef, 'an event outside the table is not a digit');

# ---------------------------------------------------------------- hold and REFER

is($sdp->{event_pt}, 101, 'the telephone-event payload type is taken from the offer');
like(Cantus::Sip::sdp_answer(ip => '1.2.3.4', port => 4000, codec => 'PCMU', event_pt => 101),
     qr/a=rtpmap:101 telephone-event\/8000/,
     'and answered, or the phone keeps its digits to itself');
like(Cantus::Sip::sdp_answer(ip => '1.2.3.4', port => 4000, codec => 'PCMU', direction => 'recvonly'),
     qr/^a=recvonly/m, 'a hold is answered with the mirrored direction');
is(Cantus::Sip::sdp_parse("c=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 0\r\na=sendonly\r\n")->{direction},
   'sendonly', 'hold is read from the offer');
is(Cantus::Sip::sdp_parse("c=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 0\r\n")->{direction},
   'sendrecv', 'and a call with no direction is a normal one');

my $refer = Cantus::Sip::parse(join("\r\n",
    'REFER sip:node@192.168.1.53:5062 SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.1.20:5060;branch=z9hG4bK9',
    'From: <sip:101@192.168.1.20>;tag=abc',
    'To: <sip:node@192.168.1.53>;tag=gw',
    'Call-ID: call-9',
    'CSeq: 3 REFER',
    'Refer-To: <sip:102@192.168.1.53>',
    'Content-Length: 0', '',
));
is(Cantus::Sip::refer_to($refer)->{user}, '102', 'the REFER target is read');
is(Cantus::Sip::refer_to($msg), undef, 'and an INVITE has no REFER target');

# An INVITE the gateway originates has to carry its body or the far end has no
# address to send audio to; a BYE has to not carry one.
my $out_invite = Cantus::Sip::request(
    method => 'INVITE', uri => 'sip:102@1.2.3.4', via => '1.2.3.4:5062;branch=z9hG4bK1',
    from => '<sip:101@cantus>;tag=a', to => '<sip:102@cantus>',
    call_id => 'c', cseq => 1, contact => '<sip:101@1.2.3.4:5062>',
    body => "v=0\r\n",
);
like($out_invite, qr/Content-Type: application\/sdp/, 'an originated INVITE names its SDP');
like($out_invite, qr/Content-Length: 5\r\n\r\nv=0/, 'and its body follows the length');
unlike(Cantus::Sip::request(
    method => 'BYE', uri => 'sip:102@1.2.3.4', via => '1.2.3.4:5062;branch=z9hG4bK2',
    from => '<sip:101@cantus>;tag=a', to => '<sip:102@cantus>;tag=b',
    call_id => 'c', cseq => 2, contact => '<sip:101@1.2.3.4:5062>'),
    qr/Content-Type/, 'a BYE carries no body');

done_testing();
