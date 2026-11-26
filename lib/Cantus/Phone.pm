package Cantus::Phone;
# A SIP test phone: register, invite, send a tone, measure what comes back.
#
# This exists because "audio both ways" has to be measured, not asserted. It is
# a real user agent on the wire -- REGISTER with digest auth, INVITE with SDP,
# RTP at 20 ms, BYE -- but it is deliberately dumb: one account, PCMU/PCMA, one
# call, no audio device. It sends a tone it can recognise and reports whether
# that exact tone came back, so the report is evidence rather than a success
# message.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time sleep);
use Socket qw(sockaddr_in inet_aton inet_ntoa);
use JSON::PP ();

use Cantus::Sip ();
use Cantus::G711 ();
use Cantus::Media ();

use constant {
    TICK     => 0.020,
    SAMPLES  => 160,
    TIMEOUT  => 4,
};

sub new {
    my ($class, %a) = @_;
    my $server = $a{server} // '127.0.0.1:5062';
    my ($host, $port) = split /:/, $server, 2;
    $port //= 5062;

    # Read out of the literal: `die` is a list operator, so a trailing
    # `// die "…",` would swallow the rest of the keys.
    my $password = $a{password} // die "Cantus::Phone needs a password\n";

    my $self = bless {
        server   => "$host:$port",
        host     => $host,
        port     => $port,
        user     => $a{user} // '101',
        password => $password,
        realm    => $a{realm} // 'cantus',
        target   => $a{target} // $a{user} // '101',
        seconds  => $a{seconds} // 6,
        tone_hz  => $a{tone_hz} // 1000,
        amp      => $a{amp} // 6000,
        on_event => $a{on_event} // sub { },
        quiet    => $a{quiet} ? 1 : 0,
        received => [],
        rx_frames => 0,
        tx_frames => 0,
        rx_peak   => 0,
        seq       => 0,
        ts        => 0,
    }, $class;

    # Known ports: a phone advertises both in Contact and in SDP, and a socket
    # bound to port 0 cannot be asked for its number on this build.
    for my $p (($a{local_port} // 5070) .. ($a{local_port} // 5070) + 20) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 1,
        ) or next;
        $sock->blocking(0);
        $self->{sip} = $sock;
        $self->{sip_port} = $p;
        last;
    }
    die "phone: no free SIP port\n" unless $self->{sip};
    for my $p (($a{rtp_port} // 42000) .. ($a{rtp_port} // 42000) + 20) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 1,
        ) or next;
        $sock->blocking(0);
        $self->{rtp} = $sock;
        $self->{rtp_port} = $p;
        last;
    }
    die "phone: no free RTP port\n" unless $self->{rtp};
    $self->{local_ip} = $a{local_ip} // $self->_local_ip;
    $self->{call_id}  = 'phone-' . int(rand(1_000_000_000));
    $self->{from_tag} = int(rand(1_000_000_000));
    $self->{cseq}     = 0;
    return $self;
}

sub emit {
    my ($self, $ev) = @_;
    my $rec = { %$ev, role => 'phone' };
    $self->{on_event}->($rec);
    return if $self->{quiet};
    local $| = 1;
    print JSON::PP->new->canonical->encode($rec), "\n";
}

sub _local_ip {
    my ($self) = @_;
    my $probe = IO::Socket::INET->new(
        PeerAddr => $self->{host}, PeerPort => $self->{port}, Proto => 'udp',
    );
    return '127.0.0.1' unless $probe;
    my $me = $probe->sockhost;
    close $probe;
    return $me;
}

sub _send {
    my ($self, $text) = @_;
    CORE::send($self->{sip}, $text, 0, sockaddr_in($self->{port}, inet_aton($self->{host})));
}

# Read one SIP message, or nothing if the deadline passes.
sub _recv {
    my ($self, $timeout) = @_;
    my $sel = IO::Select->new($self->{sip});
    my $deadline = time + ($timeout // TIMEOUT);
    while (time < $deadline) {
        my @r = $sel->can_read(0.05);
        next unless @r;
        my $buf;
        my $peer = recv($self->{sip}, $buf, 65535, 0);
        next unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $msg = Cantus::Sip::parse($buf) or next;
        $msg->{src} = inet_ntoa($iaddr) . ':' . $port;
        return $msg;
    }
    return undef;
}

sub _contact { my ($self) = @_; return "<sip:$self->{user}\@$self->{local_ip}:$self->{sip_port}>" }

sub register {
    my ($self) = @_;
    my $uri = "sip:$self->{server}";
    my $auth;
    for my $attempt (1, 2) {
        my $cseq = ++$self->{cseq};
        my @h = (
            "REGISTER $uri SIP/2.0",
            'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
            "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
            "To: <sip:$self->{user}\@$self->{host}>",
            "Call-ID: $self->{call_id}",
            "CSeq: $cseq REGISTER",
            'Contact: ' . $self->_contact,
            'Expires: 300',
            'Max-Forwards: 70',
            'User-Agent: cantus-phone/1',
        );
        push @h, $auth if $auth;
        push @h, 'Content-Length: 0';
        $self->_send(join("\r\n", @h) . "\r\n\r\n");

        my $resp = $self->_recv(TIMEOUT) or return (0, 'no response to REGISTER');
        if ($resp->{status} && $resp->{status} == 401) {
            # Challenged once, then prove the account.  A registrar that kept
            # asking would be a loop, so only the first challenge is answered.
            my $hdr = Cantus::Sip::header($resp, 'www-authenticate') // '';
            $auth = $self->_auth_header('REGISTER', $uri, $hdr);
            return (0, 'REGISTER challenge had no nonce') unless $auth;
            next;
        }
        return (0, "REGISTER failed: $resp->{status} $resp->{reason}")
            if $resp->{status} && $resp->{status} >= 300;

        $self->emit({ kind => 'registered', user => $self->{user}, src => $resp->{src} });
        return (1, 'ok');
    }
    return (0, 'REGISTER was never accepted');
}

sub _auth_header {
    my ($self, $method, $uri, $challenge) = @_;
    my $nonce = $challenge =~ /nonce="([^"]+)"/ ? $1 : undef;
    my $realm = $challenge =~ /realm="([^"]+)"/ ? $1 : undef;
    return undef unless defined $nonce;
    $realm //= $self->{realm};
    my $response = Cantus::Sip::digest_response(
        user => $self->{user}, password => $self->{password},
        realm => $realm, method => $method, uri => $uri, nonce => $nonce,
    );
    return Cantus::Sip::digest_authorization(
        user => $self->{user}, realm => $realm, nonce => $nonce,
        uri => $uri, response => $response,
    );
}

sub _sdp_offer {
    my ($self) = @_;
    return join("\r\n",
        'v=0',
        "o=cantus-phone 0 0 IN IP4 $self->{local_ip}",
        's=cantus phone',
        "c=IN IP4 $self->{local_ip}",
        't=0 0',
        "m=audio $self->{rtp_port} RTP/AVP 0",
        'a=rtpmap:0 PCMU/8000',
        'a=ptime:20',
        'a=sendrecv',
    ) . "\r\n";
}

# Place the call and carry audio for a fixed time.  Returns a report hash.
sub call {
    my ($self) = @_;
    my $uri = "sip:$self->{target}\@$self->{host}:$self->{port}";
    my $sdp = $self->_sdp_offer;
    my $auth;

    for my $attempt (1, 2) {
        my $cseq = ++$self->{cseq};
        my @h = (
            "INVITE $uri SIP/2.0",
            'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
            "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
            "To: <sip:$self->{target}\@$self->{host}>",
            "Call-ID: $self->{call_id}",
            "CSeq: $cseq INVITE",
            'Contact: ' . $self->_contact,
            'Max-Forwards: 70',
            'User-Agent: cantus-phone/1',
            'Content-Type: application/sdp',
            'Content-Length: ' . length $sdp,
        );
        push @h, $auth if $auth;
        $self->_send(join("\r\n", @h) . "\r\n\r\n" . $sdp);

        my $final;
        my $deadline = time + TIMEOUT;
        while (time < $deadline) {
            my $resp = $self->_recv(1) or next;
            next unless $resp->{status};
            next unless Cantus::Sip::header($resp, 'call-id') eq $self->{call_id};
            if ($resp->{status} == 401 || $resp->{status} == 407) {
                my $hdr = Cantus::Sip::header($resp, 'www-authenticate')
                       // Cantus::Sip::header($resp, 'proxy-authenticate') // '';
                $auth = $self->_auth_header('INVITE', $uri, $hdr);
                last;
            }
            $final = $resp if $resp->{status} >= 200;
            last if $final;
        }
        if ($auth && !$final) { next }
        return { ok => 0, error => "INVITE failed: " . ($final ? "$final->{status} $final->{reason}" : 'no response') }
            unless $final;
        return { ok => 0, error => "INVITE answered $final->{status} $final->{reason}" }
            unless $final->{status} == 200;

        my $answer = Cantus::Sip::sdp_parse($final->{body}) // {};
        $self->{remote_rtp} = ($answer->{ip} // $self->{host}) . ':' . ($answer->{port} // 0);
        $self->{codec} = $answer->{codec} // 'PCMU';
        $self->{to_tag} = Cantus::Sip::tag($final, 'to') // 'gw';

        # ACK completes the transaction so the gateway can start media.
        my $ack_cseq = ++$self->{cseq};
        my $ack = join("\r\n",
            "ACK $uri SIP/2.0",
            'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
            "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
            "To: <sip:$self->{target}\@$self->{host}>;tag=$self->{to_tag}",
            "Call-ID: $self->{call_id}",
            "CSeq: $ack_cseq ACK",
            'Max-Forwards: 70',
            'Content-Length: 0',
        ) . "\r\n\r\n";
        $self->_send($ack);
        $self->emit({ kind => 'answered', call => $self->{call_id}, codec => $self->{codec},
                      rtp => $self->{remote_rtp} });

        my $media = $self->_media;
        $self->_bye($uri);
        return { ok => 1, %$media };
    }
    return { ok => 0, error => 'INVITE was never accepted' };
}

sub _media {
    my ($self) = @_;
    my $deadline = time + $self->{seconds};
    my $next = time;
    my $phase = 0;
    my $sel = IO::Select->new($self->{rtp});

    while (time < $deadline) {
        if (time >= $next) {
            my $n = SAMPLES;
            my ($pcm, $ph) = Cantus::Media::pcm_frame(
                hz => $self->{tone_hz}, amp => $self->{amp}, samples => $n, phase => $phase,
            );
            $phase = $ph;
            my $payload = $self->{codec} eq 'PCMA'
                ? Cantus::G711::pcm_to_a($pcm) : Cantus::G711::pcm_to_mu($pcm);
            my $packet = Cantus::Sip::rtp_build(
                pt => ($self->{codec} eq 'PCMA' ? 8 : 0),
                seq => $self->{seq}++ // 0, ts => $self->{ts} // 0, ssrc => 0xCA97,
                payload => $payload,
            );
            $self->{ts} = ($self->{ts} // 0) + $n;
            my ($ip, $port) = split /:/, $self->{remote_rtp}, 2;
            CORE::send($self->{rtp}, $packet, 0, sockaddr_in($port, inet_aton($ip))) if $ip && $port;
            $self->{tx_frames}++;
            $next += TICK;
        }
        for my $fh ($sel->can_read(0.002)) {
            my $buf;
            my $peer = recv($self->{rtp}, $buf, 4096, 0);
            next unless defined $peer && length $buf;
            my $pkt = Cantus::Sip::rtp_parse($buf) or next;
            my $pcm = $pkt->{pt} == 8
                ? Cantus::G711::a_to_pcm($pkt->{payload})
                : Cantus::G711::mu_to_pcm($pkt->{payload});
            next unless length $pcm;
            my $peak = Cantus::Media::peak($pcm);
            $self->{rx_peak} = $peak if $peak > $self->{rx_peak};
            $self->{rx_frames}++;
            push @{ $self->{received} }, $pcm if @{ $self->{received} } < 400;
        }
    }
    my $tone = $self->_tone_strength(440);
    return {
        rx_frames    => $self->{rx_frames},
        tx_frames    => $self->{tx_frames},
        rx_peak      => $self->{rx_peak},
        tone_440     => $tone,
        heard_tone   => $tone >= 0.5 && $self->{rx_peak} > 0 ? 1 : 0,
    };
}

# Goertzel at one frequency over the frames received: the cheapest honest way to
# say "the far end's 440 Hz tone actually arrived" instead of "packets arrived".
# How much of what arrived is the far end's tone.  Measured per 20 ms frame and
# reported as the strongest frame's amplitude over the peak: a frame is short
# enough to be coherent even if the sender's phase resets between frames, and a
# silence frame contributes nothing.
sub _tone_strength {
    my ($self, $hz) = @_;
    return 0 unless @{ $self->{received} };
    my $w = 2 * 3.14159265358979 * $hz / 8000;
    my @amps;
    for my $frame (@{ $self->{received} }) {
        my @s = unpack('s<*', $frame);
        next unless @s;
        my ($re, $im) = (0, 0);
        for my $i (0 .. $#s) {
            my $a = $w * $i;
            $re += $s[$i] * cos($a);
            $im -= $s[$i] * sin($a);
        }
        # A sine of amplitude A has |X| = A*N/2.
        push @amps, 2 * sqrt($re * $re + $im * $im) / scalar(@s);
    }
    return 0 unless @amps;
    my ($best) = sort { $b <=> $a } @amps;
    my $peak = $self->{rx_peak} || 0;
    return 0 unless $peak > 0;
    my $ratio = $best / $peak;
    $ratio = 1 if $ratio > 1;
    return sprintf('%.3f', $ratio);
}

sub _bye {
    my ($self, $uri) = @_;
    my $cseq = ++$self->{cseq};
    my $text = join("\r\n",
        "BYE $uri SIP/2.0",
        'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
        "To: <sip:$self->{target}\@$self->{host}>;tag=$self->{to_tag}",
        "Call-ID: $self->{call_id}",
        "CSeq: $cseq BYE",
        'Max-Forwards: 70',
        'Content-Length: 0',
    ) . "\r\n\r\n";
    $self->_send($text);
    my $resp = $self->_recv(1);
    $self->emit({ kind => 'bye', status => $resp ? $resp->{status} : undef });
    return $resp && $resp->{status} == 200 ? 1 : 0;
}

1;
