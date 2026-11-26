package Cantus::Phone;
# A SIP test phone: register, answer or place a call, press keys, hold, transfer.
#
# This exists because "audio both ways" and "the transfer worked" have to be
# measured, not asserted. It is a real user agent on the wire -- REGISTER with
# digest auth, INVITE with SDP, RTP at 20 ms, RFC 4733 digits, re-INVITE for
# hold, REFER for transfer, BYE -- but it is deliberately dumb: one account,
# PCMU/PCMA, one call, no audio device. It sends a tone it can recognise and
# reports whether that tone came back, so a pass is evidence.
#
# Every step is a method rather than a script, so a test can drive two phones
# against a gateway without forking anything.
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
    # A call that is ringing has not failed: the far end may take a while to
    # pick up, and a phone that gives up after four seconds would call every
    # answered-by-a-human call a failure.
    INVITE_TIMEOUT => 15,
    EVENT_PACKETS => 6,
    EVENT_STEP    => 160,
    EVENT_PT      => 101,
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
        dtmf     => [],
        rx_frames => 0,
        tx_frames => 0,
        rx_peak   => 0,
        window    => { rx_frames => 0, rx_peak => 0, dtmf => [] },
        seq       => 0,
        ts        => 0,
        event_pt  => EVENT_PT,
        state     => 'idle',
        ended     => 0,
        answered  => 0,
    }, $class;

    # Known ports: a phone advertises both in Contact and in SDP, and a socket
    # bound to port 0 cannot be asked for its number on this build.
    #
    # Not ReuseAddr: two phones on one host must not both claim 5070.  With
    # SO_REUSEADDR the second bind silently succeeds and the kernel hands each
    # packet to one of them, so an INVITE rings the wrong phone and the caller
    # waits out its timeout with nothing in the log to explain it.
    for my $p (($a{local_port} // 5070) .. ($a{local_port} // 5070) + 20) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 0,
        ) or next;
        $sock->blocking(0);
        $self->{sip} = $sock;
        $self->{sip_port} = $p;
        last;
    }
    die "phone: no free SIP port\n" unless $self->{sip};
    for my $p (($a{rtp_port} // 42000) .. ($a{rtp_port} // 42000) + 20) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 0,
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
    my $rec = { %$ev, role => 'phone', user => $self->{user} };
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
    while (1) {
        # A zero timeout is a poll, not "give up": the media loop asks for one
        # on every tick and a BYE that is only read by the next blocking call
        # is a call that looks stuck.
        my $wait = $deadline - time;
        $wait = 0 if $wait < 0;
        my @r = $sel->can_read($wait);
        return undef unless @r;
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

sub _sdp {
    my ($self, %a) = @_;
    my $dir = $a{direction} // 'sendrecv';
    return join("\r\n",
        'v=0',
        "o=cantus-phone 0 0 IN IP4 $self->{local_ip}",
        's=cantus phone',
        "c=IN IP4 $self->{local_ip}",
        't=0 0',
        "m=audio $self->{rtp_port} RTP/AVP 0 " . EVENT_PT,
        'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:' . EVENT_PT . ' telephone-event/8000',
        'a=ptime:20',
        "a=$dir",
    ) . "\r\n";
}

sub _dialog_headers {
    my ($self, $method, $uri) = @_;
    return (
        "$method $uri SIP/2.0",
        'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
        "To: <sip:$self->{target}\@$self->{host}>;tag=" . ($self->{to_tag} // 'gw'),
        "Call-ID: $self->{call_id}",
        'CSeq: ' . ++$self->{cseq} . " $method",
        'Contact: ' . $self->_contact,
        'Max-Forwards: 70',
        'User-Agent: cantus-phone/1',
    );
}

# Place the call.  Sending and waiting are separate on purpose: a phone that
# blocks on its own INVITE cannot be answered by the other phone in the same
# process, which is exactly what a two-phone test does.
sub invite {
    my ($self, $target) = @_;
    $self->{target} = $target if defined $target;
    $self->{invite_uri} = "sip:$self->{target}\@$self->{host}:$self->{port}";
    $self->_send_invite;
    $self->{state} = 'ringing';
    return (1, 'sent');
}

sub _send_invite {
    my ($self) = @_;
    my $uri = $self->{invite_uri};
    my $sdp = $self->_sdp;
    my @h = (
        "INVITE $uri SIP/2.0",
        'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
        "To: <sip:$self->{target}\@$self->{host}>",
        "Call-ID: $self->{call_id}",
        'CSeq: ' . ++$self->{cseq} . ' INVITE',
        'Contact: ' . $self->_contact,
        'Max-Forwards: 70',
        'User-Agent: cantus-phone/1',
        'Content-Type: application/sdp',
        'Content-Length: ' . length $sdp,
    );
    push @h, $self->{auth} if $self->{auth};
    $self->_send(join("\r\n", @h) . "\r\n\r\n" . $sdp);
}

# Wait for the answer.  180 means the phone is ringing, not that anything
# failed, so only a final response ends the wait.
sub wait_answered {
    my ($self, $timeout) = @_;
    my $deadline = time + ($timeout // INVITE_TIMEOUT);
    while (time < $deadline) {
        my $resp = $self->_recv(0.2) or next;
        next unless $resp->{status};
        next unless (Cantus::Sip::header($resp, 'call-id') // '') eq $self->{call_id};
        if ($resp->{status} == 401 || $resp->{status} == 407) {
            my $hdr = Cantus::Sip::header($resp, 'www-authenticate')
                   // Cantus::Sip::header($resp, 'proxy-authenticate') // '';
            $self->{auth} = $self->_auth_header('INVITE', $self->{invite_uri}, $hdr);
            $self->_send_invite;
            next;
        }
        next unless $resp->{status} >= 200;
        return (0, "INVITE answered $resp->{status} $resp->{reason}")
            unless $resp->{status} == 200;

        my $answer = Cantus::Sip::sdp_parse($resp->{body}) // {};
        $self->{remote_rtp} = ($answer->{ip} // $self->{host}) . ':' . ($answer->{port} // 0);
        $self->{codec} = $answer->{codec} // 'PCMU';
        $self->{event_pt} = $answer->{event_pt} // EVENT_PT;
        $self->{to_tag} = Cantus::Sip::tag($resp, 'to') // 'gw';
        $self->_ack($self->{invite_uri});
        $self->{state} = 'active';
        $self->{answered} = 1;
        $self->emit({ kind => 'answered', call => $self->{call_id}, codec => $self->{codec},
                      rtp => $self->{remote_rtp} });
        return (1, 'ok');
    }
    return (0, 'INVITE was never accepted');
}

sub _ack {
    my ($self, $uri) = @_;
    my $text = join("\r\n",
        "ACK $uri SIP/2.0",
        'Via: SIP/2.0/UDP ' . $self->{local_ip} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        "From: <sip:$self->{user}\@$self->{host}>;tag=$self->{from_tag}",
        "To: <sip:$self->{target}\@$self->{host}>;tag=" . ($self->{to_tag} // 'gw'),
        "Call-ID: $self->{call_id}",
        'CSeq: ' . $self->{cseq} . ' ACK',
        'Max-Forwards: 70',
        'Content-Length: 0',
    ) . "\r\n\r\n";
    $self->_send($text);
}

# Wait for somebody to call this phone (the answering side of a test).
sub wait_invite {
    my ($self, $timeout) = @_;
    my $deadline = time + ($timeout // 10);
    while (time < $deadline) {
        my $msg = $self->_recv(0.2) or next;
        next unless $msg->{request};
        next unless ($msg->{method} // '') eq 'INVITE';
        $self->{invite} = $msg;
        $self->{call_id} = Cantus::Sip::header($msg, 'call-id');
        $self->{target} = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'))->{user}
            // $self->{target};
        $self->{remote_tag} = Cantus::Sip::tag($msg, 'from') // 'gw';
        $self->emit({ kind => 'incoming', call => $self->{call_id}, from => $self->{target} });
        return $msg;
    }
    return undef;
}

sub answer {
    my ($self, $msg) = @_;
    $msg //= $self->{invite} or return (0, 'no INVITE to answer');
    my $offer = Cantus::Sip::sdp_parse($msg->{body}) // {};
    $self->{codec} = $offer->{codec} // 'PCMU';
    $self->{event_pt} = $offer->{event_pt} // EVENT_PT;
    $self->{to_tag} = 'phone' . int(rand(1_000_000));
    my $sdp = Cantus::Sip::sdp_answer(
        ip => $self->{local_ip}, port => $self->{rtp_port},
        codec => $self->{codec}, event_pt => $self->{event_pt},
    );
    $self->_send(Cantus::Sip::response($msg, 200, to_tag => $self->{to_tag},
        contact => $self->_contact, sdp => $sdp));
    # ACK is the caller's job; wait briefly so the dialog is really up before
    # media starts, but do not fail the answer if it is late.
    my $deadline = time + 2;
    while (time < $deadline) {
        my $resp = $self->_recv(0.2) or next;
        last if ($resp->{method} // '') eq 'ACK';
    }
    $self->{remote_rtp} = ($offer->{ip} // $self->{host}) . ':' . ($offer->{port} // 0);
    $self->{state} = 'active';
    $self->{answered} = 1;
    $self->emit({ kind => 'answered', call => $self->{call_id}, codec => $self->{codec},
                  rtp => $self->{remote_rtp} });
    return (1, 'ok');
}

# Carry media for a while and report what actually arrived in that window.
# Windows are the point: "silence during hold" is a measurement of one window,
# not a total that a later resume would hide.
sub pump {
    my ($self, $seconds) = @_;
    $self->window_reset;
    my $deadline = time + ($seconds // 1);
    while (time < $deadline && !$self->{ended}) {
        $self->pump_tick;
        sleep 0.002;
    }
    return $self->_report;
}

sub window_reset { $_[0]{window} = { rx_frames => 0, rx_peak => 0, dtmf => [] } }
sub window       { $_[0]->_report }

# One slice of the media loop, with no waiting: a driver that also has to pump
# a gateway and a relay between frames uses this instead of pump.
sub pump_tick {
    my ($self) = @_;
    my $sel = IO::Select->new($self->{rtp});
    {
        if (time >= ($self->{next_tx} // 0) && $self->{remote_rtp} && $self->{state} eq 'active') {
            my ($pcm, $ph) = Cantus::Media::pcm_frame(
                hz => $self->{tone_hz}, amp => $self->{amp}, samples => SAMPLES,
                phase => $self->{phase} // 0,
            );
            $self->{phase} = $ph;
            my $payload = $self->{codec} eq 'PCMA'
                ? Cantus::G711::pcm_to_a($pcm) : Cantus::G711::pcm_to_mu($pcm);
            my $packet = Cantus::Sip::rtp_build(
                pt => ($self->{codec} eq 'PCMA' ? 8 : 0),
                seq => $self->{seq}++, ts => $self->{ts}, ssrc => 0xCA97,
                payload => $payload,
            );
            $self->{ts} += SAMPLES;
            my ($ip, $port) = split /:/, $self->{remote_rtp}, 2;
            CORE::send($self->{rtp}, $packet, 0, sockaddr_in($port, inet_aton($ip))) if $ip && $port;
            $self->{tx_frames}++;
            $self->{next_tx} = ($self->{next_tx} // time) + TICK;
        }

        for my $fh ($sel->can_read(0)) {
            my $buf;
            my $peer = recv($self->{rtp}, $buf, 4096, 0);
            next unless defined $peer && length $buf;
            my $pkt = Cantus::Sip::rtp_parse($buf) or next;
            if (defined $self->{event_pt} && $pkt->{pt} == $self->{event_pt}) {
                my $ev = Cantus::Sip::rtp_event_parse($pkt->{payload}) or next;
                if ($ev->{end}) { delete $self->{dtmf_live}{ $ev->{event} }; next }
                next if $self->{dtmf_live}{ $ev->{event} };
                $self->{dtmf_live}{ $ev->{event} } = 1;
                my $digit = Cantus::Sip::dtmf_digit($ev->{event});
                if (defined $digit) {
                    push @{ $self->{dtmf} }, $digit;
                    push @{ $self->{window}{dtmf} }, $digit;
                    $self->emit({ kind => 'dtmf', digit => $digit });
                }
                next;
            }
            next unless $pkt->{pt} == ($self->{codec} eq 'PCMA' ? 8 : 0);

            my $pcm = $pkt->{pt} == 8
                ? Cantus::G711::a_to_pcm($pkt->{payload})
                : Cantus::G711::mu_to_pcm($pkt->{payload});
            next unless length $pcm;
            my $peak = Cantus::Media::peak($pcm);
            $self->{rx_peak} = $peak if $peak > $self->{rx_peak};
            $self->{window}{rx_peak} = $peak if $peak > $self->{window}{rx_peak};
            $self->{rx_frames}++;
            $self->{window}{rx_frames}++;
            push @{ $self->{received} }, $pcm if @{ $self->{received} } < 400;
        }

        # A BYE from the far end ends the window early: a call that was hung up
        # must not read as a call that carried audio.
        my $msg = $self->_recv(0);
        if ($msg && ($msg->{method} // '') eq 'BYE') {
            $self->_send(Cantus::Sip::response($msg, 200));
            $self->{ended} = 1;
            $self->{state} = 'ended';
            $self->emit({ kind => 'ended', call => $self->{call_id}, by => 'far end' });
        }
    }
    return 1;
}

sub _report {
    my ($self) = @_;
    my $w = $self->{window} || {};
    my $tone = $self->_tone_strength(440);
    return {
        rx_frames  => $w->{rx_frames} // 0,
        tx_frames  => $self->{tx_frames},
        rx_peak    => $w->{rx_peak} // 0,
        tone_440   => $tone,
        heard_tone => ($tone >= 0.5 && ($w->{rx_peak} // 0) > 0) ? 1 : 0,
        dtmf       => $w->{dtmf} || [],
        ended      => $self->{ended} ? 1 : 0,
    };
}

# Goertzel at one frequency over the frames received: the cheapest honest way to
# say "the far end's 440 Hz tone actually arrived" instead of "packets arrived".
# Measured per 20 ms frame and reported as the strongest frame's amplitude over
# the peak: a frame is short enough to be coherent even if the sender's phase
# resets between frames, and a silence frame contributes nothing.
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

# RFC 4733 out: six packets, 120 ms, the shape a phone's detector expects.
sub send_dtmf {
    my ($self, $digit) = @_;
    my $id = Cantus::Sip::dtmf_event_id($digit);
    return 0 unless defined $id && $self->{remote_rtp};
    my ($ip, $port) = split /:/, $self->{remote_rtp}, 2;
    my $ts = $self->{ts};
    for my $i (1 .. EVENT_PACKETS) {
        my $packet = Cantus::Sip::rtp_build(
            pt => $self->{event_pt}, seq => $self->{seq}++, ts => $ts, ssrc => 0xCA97,
            marker => ($i == 1 ? 1 : 0),
            payload => Cantus::Sip::rtp_event_build(
                event => $id, end => ($i == EVENT_PACKETS ? 1 : 0), duration => $i * EVENT_STEP),
        );
        CORE::send($self->{rtp}, $packet, 0, sockaddr_in($port, inet_aton($ip)));
    }
    $self->{ts} = $ts + EVENT_PACKETS * EVENT_STEP;
    $self->emit({ kind => 'dtmf-sent', digit => $digit });
    return 1;
}

# Hold is a re-INVITE that says what this phone will and will not do.  The
# gateway answers it and stops sending the far end; resume is the same message
# with sendrecv, so the call comes back rather than being rebuilt.
sub _reinvite {
    my ($self, $direction) = @_;
    my $uri = "sip:$self->{target}\@$self->{host}:$self->{port}";
    my $sdp = $self->_sdp(direction => $direction);
    my @h = (
        $self->_dialog_headers('INVITE', $uri),
        'Content-Type: application/sdp',
        'Content-Length: ' . length $sdp,
    );
    $self->_send(join("\r\n", @h) . "\r\n\r\n" . $sdp);
    my $deadline = time + TIMEOUT;
    while (time < $deadline) {
        my $resp = $self->_recv(0.5) or next;
        next unless $resp->{status} && $resp->{status} >= 200;
        $self->_ack($uri);
        $self->emit({ kind => $direction eq 'sendonly' ? 'held' : 'resumed',
                      call => $self->{call_id}, code => $resp->{status} });
        return ($resp->{status} == 200, "re-INVITE answered $resp->{status}");
    }
    return (0, 're-INVITE was not answered');
}

sub hold   { $_[0]->_reinvite('sendonly') }
sub resume { $_[0]->_reinvite('sendrecv') }

# Blind transfer: ask the gateway to hand the call to another line.  A 202 is
# the only answer that means "the request was taken"; anything else leaves the
# call where it is.
sub refer {
    my ($self, $target) = @_;
    my $uri = "sip:$self->{target}\@$self->{host}:$self->{port}";
    my @h = (
        $self->_dialog_headers('REFER', $uri),
        "Refer-To: <sip:$target\@$self->{host}>",
        'Referred-By: <sip:' . $self->{user} . '@' . $self->{host} . '>',
        'Content-Length: 0',
    );
    $self->_send(join("\r\n", @h) . "\r\n\r\n");
    my $deadline = time + TIMEOUT;
    while (time < $deadline) {
        my $resp = $self->_recv(0.5) or next;
        next unless $resp->{status};
        $self->emit({ kind => 'referred', to => $target, code => $resp->{status} });
        return ($resp->{status} == 202, "REFER answered $resp->{status} $resp->{reason}");
    }
    return (0, 'REFER was not answered');
}

sub bye {
    my ($self) = @_;
    my $uri = "sip:$self->{target}\@$self->{host}:$self->{port}";
    $self->_send(join("\r\n", $self->_dialog_headers('BYE', $uri), 'Content-Length: 0') . "\r\n\r\n");
    my $resp = $self->_recv(1);
    $self->{state} = 'ended';
    $self->{ended} = 1;
    $self->emit({ kind => 'bye', status => $resp ? $resp->{status} : undef });
    return $resp && $resp->{status} == 200 ? 1 : 0;
}

# The old one-shot entry point: place the call, carry audio, hang up.
sub call {
    my ($self) = @_;
    my ($ok, $why) = $self->invite;
    ($ok, $why) = $self->wait_answered if $ok;
    return { ok => 0, error => $why } unless $ok;
    my $media = $self->pump($self->{seconds});
    $self->bye;
    return { ok => 1, %$media };
}

1;
