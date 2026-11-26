package Cantus::Gateway;
# The SIP edge: one account, one extension, G.711 in, Cantus out.
#
# A softphone speaks SIP and RTP; Cantus carries pcm-s16 on one socket. This is
# the smallest thing that stands between them and still does the real work:
# register the account, answer an INVITE with SDP, translate mu-law to pcm-s16
# and back at 20 ms, and place the call through a Cantus::Node so the path
# negotiation, relay fallback and rebinding are the same code a production node
# runs -- not a parallel copy of it.
#
# What it deliberately does not do: TCP/TLS, multiple accounts, hold, transfer,
# DTMF, a registration database. Each of those is a feature with a state machine
# of its own, and none of them is needed to prove audio crosses both ways.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time sleep);
use JSON::PP ();
use Socket qw(sockaddr_in inet_aton inet_ntoa);

use Cantus::Node ();
use Cantus::Sip ();
use Cantus::G711 ();
use Cantus::Media ();

use constant {
    RTP_TICK      => 0.020,
    FRAME_SAMPLES => 160,       # 20 ms at 8 kHz
    FRAME_BYTES   => 320,       # pcm-s16
    QUEUE_MAX     => 8,         # 160 ms of buffer, then it is too late to help
    REFRESH       => 20,
    TICK          => 0.002,
};

sub new {
    my ($class, %a) = @_;
    my $cfg = $a{config} // die "Cantus::Gateway requires a config\n";

    # Validated before the hash literal: `die` is a list operator, so a
    # `// die "…",` inside the literal would swallow every key after it.
    my $target = $cfg->{target}
        // die "gateway config needs a target (the Cantus node)\n";

    my $self = bless {
        cfg        => $cfg,
        realm      => $cfg->{realm}  // 'cantus',
        advertise  => $cfg->{advertise} // '127.0.0.1',
        target     => $target,
        account    => $cfg->{account} // {},    # password comes from GATEWAY_PASSWORD
        dialogs    => {},
        by_cantus  => {},
        contacts   => {},
        running    => 1,
        started    => time,
        next_rtp   => time,
        next_reg   => 0,
        rtp_frames => 0,
        sip_frames => 0,
        events     => [],
        on_event   => $a{on_event} // sub { },
        quiet      => $a{quiet} ? 1 : 0,
    }, $class;

    # The account secret belongs in the environment, not in a committed file,
    # for the same reason CANTUS_SECRET does: the config is reviewable, the key
    # is handed to the process.
    $self->{account} = { %{ $self->{account} } };
    if (defined $ENV{GATEWAY_PASSWORD} && length $ENV{GATEWAY_PASSWORD}) {
        $self->{account}{password} = $ENV{GATEWAY_PASSWORD};
    }

    my $bind = $cfg->{bind} // '0.0.0.0:5062';
    my ($sh, $sp) = split /:/, $bind, 2;
    $self->{sip} = IO::Socket::INET->new(
        LocalAddr => $sh || '0.0.0.0', LocalPort => ($sp || 5062),
        Proto => 'udp', ReuseAddr => 1,
    ) or die "cantus gateway: cannot bind SIP $bind: $!\n";
    $self->{sip}->blocking(0);
    # IO::Socket::INET reports sockport 0 for an unconnected UDP socket on this
    # build, so the port has to come from the bound address itself.
    $self->{sip_port} = (sockaddr_in($self->{sip}->sockname))[0];

    # An ephemeral port cannot be advertised: SDP and the int() arithmetic here
    # have to name the port before a call exists, and this build reports 0 for a
    # socket bound to port 0. A small fixed range is both knowable and honest.
    my $rtp_base = $cfg->{rtp_port} // 41000;
    for my $p ($rtp_base .. $rtp_base + 20) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 1,
        ) or next;
        $sock->blocking(0);
        $self->{rtp} = $sock;
        $self->{rtp_port} = $p;
        last;
    }
    die "cantus gateway: no free RTP port in $rtp_base.." . ($rtp_base + 20) . "\n"
        unless $self->{rtp};

    # The Cantus side is a node like any other: it registers with the relay and
    # places an ordinary call.  audio_source and on_audio are the two hooks that
    # make it a bridge rather than a tone generator.
    $self->{node} = Cantus::Node->new(
        id           => $cfg->{id} // 'gateway@switch.example',
        bind         => '0.0.0.0:0',
        secret       => $cfg->{secret} // 'cantus-loopback',
        relay        => $cfg->{relay},
        auto_answer  => 1,
        debug        => $cfg->{debug} // 0,
        audio_source => sub { $self->_audio_from_softphone(@_) },
        on_audio     => sub { $self->_audio_from_cantus(@_) },
        on_event     => sub { $self->_cantus_event(@_) },
    );
    return $self;
}

sub sip_port { $_[0]{sip_port} }
sub rtp_port { $_[0]{rtp_port} }
sub node     { $_[0]{node} }
sub dialogs  { $_[0]{dialogs} }

sub emit {
    my ($self, $ev) = @_;
    my $rec = { %$ev, role => 'gateway', t => sprintf('%.3f', time - $self->{started}) };
    push @{ $self->{events} }, $rec;
    shift @{ $self->{events} } while @{ $self->{events} } > 500;
    $self->{on_event}->($rec);
    return unless !$self->{quiet};
    local $| = 1;
    print JSON::PP->new->canonical->encode($rec), "\n";
}

sub stats {
    my ($self) = @_;
    my %d;
    for my $id (keys %{ $self->{dialogs} }) {
        my $d = $self->{dialogs}{$id};
        $d = { %$d };
        delete @$d{qw(in out invite)};
        $d{$id} = $d;
    }
    return {
        dialogs    => \%d,
        contacts   => { map { $_ => $self->{contacts}{$_}{addr} } keys %{ $self->{contacts} } },
        rtp_frames => $self->{rtp_frames},
        sip_frames => $self->{sip_frames},
        cantus     => $self->{node}->stats,
    };
}

# ------------------------------------------------------------------ loop

sub stop { $_[0]{running} = 0 }

sub run {
    my ($self) = @_;
    $SIG{INT} = $SIG{TERM} = sub { $self->{running} = 0 };
    $self->emit({ kind => 'ready', sip => "$self->{advertise}:$self->{sip_port}",
                  rtp => $self->{rtp_port}, target => $self->{target} });
    $self->{node}->register if $self->{cfg}{relay};

    my $sel = IO::Select->new($self->{sip}, $self->{rtp});
    while ($self->{running}) {
        for my $fh ($sel->can_read(0)) {
            if ($fh == $self->{sip}) { $self->_drain_sip }
            else                     { $self->_drain_rtp }
        }
        eval { $self->{node}->pump(0) };
        $self->emit({ kind => 'error', error => $@ }) if $@;

        if ($self->{cfg}{relay} && time >= $self->{next_reg}) {
            $self->{node}->register;
            $self->{next_reg} = time + REFRESH;
        }
        $self->_rtp_tick if time >= $self->{next_rtp};
        sleep TICK;
    }
    $self->emit({ kind => 'stopped', %{ $self->stats } });
    return 0;
}

# ------------------------------------------------------------------ SIP

sub _drain_sip {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $peer = recv($self->{sip}, $buf, 65535, 0);
        last unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $src = inet_ntoa($iaddr) . ':' . $port;
        my $msg = Cantus::Sip::parse($buf);
        unless ($msg) {
            $self->emit({ kind => 'sip-bad', src => $src, len => length $buf });
            next;
        }
        $self->{sip_frames}++;
        $msg->{src} = $src;
        $self->emit({ kind => 'sip', method => $msg->{method}, code => $msg->{status},
                      src => $src, call => Cantus::Sip::header($msg, 'call-id') })
            if $self->{cfg}{debug};
        next unless $msg->{request};
        my $m = $msg->{method};
        my $fn = $self->can('_on_' . lc $m) or do {
            $self->_reply($msg, 405);
            next;
        };
        eval { $self->$fn($msg) };
        $self->emit({ kind => 'error', error => $@ }) if $@;
    }
}

sub _reply {
    my ($self, $req, $code, %a) = @_;
    my $text = Cantus::Sip::response($req, $code, %a);
    my ($ip, $port) = split /:/, $req->{src}, 2;
    CORE::send($self->{sip}, $text, 0, sockaddr_in($port, inet_aton($ip)));
}

# Refusals are throttled per source: a device retrying in a loop must cost a
# reply and nothing else, or the log becomes the attack surface.
sub _refuse {
    my ($self, $msg, $code, $why, %a) = @_;
    my $now = time;
    my $key = "$code:" . ($msg->{src} // '?');
    if (!($self->{refuse_at}{$key} // 0) || $now - $self->{refuse_at}{$key} > 30) {
        $self->{refuse_at}{$key} = $now;
        $self->emit({ kind => 'refused', code => $code, why => $why, src => $msg->{src} });
    }
    $self->_reply($msg, $code, %a);
}

sub _on_options {
    my ($self, $msg) = @_;
    $self->_reply($msg, 200);
}

# One account.  A REGISTER is challenged once and then remembered; the contact
# is what a later INVITE is checked against, so an unregistered source cannot
# place a call by guessing the extension.
sub _on_register {
    my ($self, $msg) = @_;
    my $user = $self->{account}{user} // '';

    # Only the configured account is challenged. Challenging everyone turns the
    # gateway into an oracle for whatever else on the LAN is looking for a
    # registrar, and the challenge/response storm starves the media loop.
    my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
    unless ($from && defined $from->{user} && $from->{user} eq $user) {
        $self->_refuse($msg, 403, 'unknown account');
        return;
    }

    my $pass = $self->{account}{password} // '';
    my ($ok, $why) = Cantus::Sip::verify_digest(
        msg => $msg, method => 'REGISTER', user => $user,
        password => $pass, realm => $self->{realm},
    );
    unless ($ok) {
        my $nonce = Cantus::Sip::nonce();
        $self->_refuse($msg, 401, $why,
            headers => [ Cantus::Sip::challenge_header($self->{realm}, $nonce) ]);
        return;
    }
    my $contact = Cantus::Sip::header($msg, 'contact') // '';
    my $uri = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
    my $expires = Cantus::Sip::header($msg, 'expires') // 3600;
    $self->{contacts}{ $user } = {
        addr    => $msg->{src},
        contact => $contact,
        uri     => $uri,
        expires => time + $expires,
    };
    $self->emit({ kind => 'registered', user => $user, addr => $msg->{src}, expires => $expires });
    $self->_reply($msg, 200, contact => $contact, expires => $expires);
}

sub _authorized {
    my ($self, $msg) = @_;
    my $user = $self->{account}{user} // '';
    my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
    return 0 unless $from && defined $from->{user} && $from->{user} eq $user;
    my $c = $self->{contacts}{$user};
    return 0 unless $c && $c->{expires} > time;
    return 1;
}

# An INVITE becomes a Cantus call.  The SIP side is answered with 180 at once
# (so a softphone rings rather than retransmitting), and with 200 + SDP when the
# Cantus peer accepts -- the gateway never claims a call it has not established.
sub _on_invite {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;

    if (my $existing = $self->{dialogs}{$call_id}) {
        # Retransmission: answer as before instead of starting a second call.
        $self->_reply($msg, 200, sdp => $existing->{sdp}, contact => $self->_contact,
                      to_tag => $existing->{to_tag});
        return;
    }
    unless ($self->_authorized($msg)) {
        $self->emit({ kind => 'invite-refused', call => $call_id, src => $msg->{src} });
        $self->_reply($msg, 403);
        return;
    }

    my $sdp = Cantus::Sip::sdp_parse($msg->{body});
    unless ($sdp && $sdp->{ip}) {
        $self->emit({ kind => 'invite-no-codec', call => $call_id });
        $self->_reply($msg, 488);
        return;
    }

    my $d = {
        call_id  => $call_id,
        invite   => $msg,
        from_tag => Cantus::Sip::tag($msg, 'from') // 'gw',
        to_tag   => 'cantus' . int(rand(1_000_000)),
        cseq     => (Cantus::Sip::header($msg, 'cseq') // '1') =~ /^(\d+)/ ? $1 : 1,
        remote   => "$sdp->{ip}:$sdp->{port}",
        codec    => $sdp->{codec},
        pt       => $sdp->{codec} eq 'PCMA' ? 8 : 0,
        ssrc     => int(rand(2_000_000_000)),
        seq      => int(rand(30_000)),
        ts       => int(rand(100_000)),
        state    => 'ringing',
        in       => [],
        out      => [],
        rx_frames => 0,
        tx_frames => 0,
        rx_peak   => 0,
        tx_peak   => 0,
        started   => time,
        sdp       => '',
    };
    $self->{dialogs}{$call_id} = $d;
    $d->{sdp} = Cantus::Sip::sdp_answer(
        ip => $self->{advertise}, port => $self->{rtp_port}, codec => $d->{codec},
    );

    $self->_reply($msg, 180, to_tag => $d->{to_tag});
    $self->emit({ kind => 'invite', call => $call_id, from => $d->{remote},
                  codec => $d->{codec} });

    $self->_place($d);
}

# Placing the Cantus leg is a separate step because it can be too early: the
# gateway registers with the relay after the socket opens, and an INVITE that
# arrives in the first milliseconds cannot be routed by name yet. Such a call
# waits (the phone is already hearing ringback) and is placed on the ack.
sub _place {
    my ($self, $d) = @_;
    return if $d->{cantus};
    unless ($self->{node}->handle) {
        $self->{node}->register;
        $d->{waiting} = 1;
        $self->emit({ kind => 'cantus-waiting', call => $d->{call_id} });
        return;
    }
    my $cantus = $self->{node}->call($self->{target});
    unless ($cantus) {
        $self->emit({ kind => 'cantus-failed', call => $d->{call_id}, target => $self->{target} });
        $self->_reply($d->{invite}, 503, to_tag => $d->{to_tag});
        $d->{state} = 'ended';
        delete $self->{dialogs}{ $d->{call_id} };
        return;
    }
    $d->{waiting} = 0;
    $d->{cantus} = $cantus;
    $self->{by_cantus}{$cantus} = $d->{call_id};
}

sub _on_ack {
    my ($self, $msg) = @_;
    my $d = $self->{dialogs}{ Cantus::Sip::header($msg, 'call-id') // '' } or return;
    $d->{state} = 'active' if $d->{state} eq 'ringing' && length $d->{sdp};
    $self->emit({ kind => 'ack', call => $d->{call_id}, state => $d->{state} });
}

sub _on_bye {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;
    my $d = $self->{dialogs}{$call_id};
    $self->_reply($msg, 200);
    return unless $d;
    $self->_end_dialog($d, 'peer hung up');
}

sub _on_cancel {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;
    my $d = $self->{dialogs}{$call_id};
    $self->_reply($msg, 200);
    $self->_end_dialog($d, 'cancelled') if $d;
}

sub _contact {
    my ($self) = @_;
    return '<sip:' . ($self->{account}{user} // 'gateway') . '@'
        . $self->{advertise} . ':' . $self->{sip_port} . '>';
}

sub _end_dialog {
    my ($self, $d, $why) = @_;
    return if $d->{state} eq 'ended';
    $d->{state} = 'ended';
    delete $self->{dialogs}{ $d->{call_id} };
    if ($d->{cantus}) {
        delete $self->{by_cantus}{ $d->{cantus} };
        eval { $self->{node}->hangup($d->{cantus}, 'NORMAL') };
    }
    $self->emit({
        kind => 'ended', call => $d->{call_id}, why => $why,
        rx_frames => $d->{rx_frames}, tx_frames => $d->{tx_frames},
        rx_peak => $d->{rx_peak}, tx_peak => $d->{tx_peak},
        seconds => sprintf('%.1f', time - $d->{started}),
    });
}

# ------------------------------------------------------------------ Cantus

sub _session_dialog {
    my ($self, $s) = @_;
    return undef unless $s && defined $s->{call};
    my $call_id = $self->{by_cantus}{ $s->{call} } or return undef;
    return $self->{dialogs}{$call_id};
}

sub _cantus_event {
    my ($self, $ev) = @_;
    if (($ev->{kind} // '') eq 'registered') {
        for my $d (values %{ $self->{dialogs} }) {
            next unless $d->{waiting} && $d->{state} eq 'ringing';
            $self->_place($d);
        }
        return;
    }
    my $call = $ev->{call} // return;
    my $d = $self->{dialogs}{ $self->{by_cantus}{$call} // '' } or return;
    if ($ev->{kind} eq 'accepted' && $d->{state} eq 'ringing') {
        $self->_reply($d->{invite}, 200, to_tag => $d->{to_tag},
                      contact => $self->_contact, sdp => $d->{sdp});
        $self->emit({ kind => 'answered', call => $d->{call_id}, codec => $ev->{codec} });
    }
    elsif ($ev->{kind} eq 'ended' && $d->{state} ne 'ended') {
        $self->_send_bye($d, $ev->{reason} // 'NORMAL');
    }
}

sub _send_bye {
    my ($self, $d, $reason) = @_;
    my $req = $d->{invite};
    my ($ip, $port) = split /:/, $d->{remote}, 2;
    my $text = Cantus::Sip::request(
        method  => 'BYE',
        uri     => $req->{uri},
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => Cantus::Sip::header($req, 'from'),
        to      => (Cantus::Sip::header($req, 'to') =~ /;tag=/)
                    ? Cantus::Sip::header($req, 'to')
                    : Cantus::Sip::header($req, 'to') . ';tag=' . $d->{to_tag},
        call_id => $d->{call_id},
        cseq    => $d->{cseq} + 1,
        contact => $self->_contact,
    );
    eval { CORE::send($self->{sip}, $text, 0, sockaddr_in($port, inet_aton($ip))) };
    $self->emit({ kind => 'bye-sent', call => $d->{call_id}, reason => $reason });
}

# Called by Cantus::Node for every frame it is about to send.  Returning undef
# would fall back to the node's test tone; returning silence would be lying, so
# an empty buffer returns true silence -- the softphone should hear a quiet line,
# not a 440 Hz hum it never asked for.
sub _audio_from_softphone {
    my ($self, $s, $n) = @_;
    my $d = $self->_session_dialog($s) or return "\0" x FRAME_BYTES;
    my $pcm = shift @{ $d->{in} };
    $d->{cantus_out_frames}++ if $pcm;
    return $pcm ? $pcm : "\0" x FRAME_BYTES;
}

sub _audio_from_cantus {
    my ($self, $s, $payload, $codec) = @_;
    my $d = $self->_session_dialog($s) or return;
    return unless defined $payload && length $payload;
    my $peak = Cantus::Media::peak($payload);
    $d->{tx_peak} = $peak if $peak > $d->{tx_peak};
    push @{ $d->{out} }, $payload;
    shift @{ $d->{out} } while @{ $d->{out} } > QUEUE_MAX;
    $d->{from_cantus_frames}++;
}

# ------------------------------------------------------------------ RTP

sub _drain_rtp {
    my ($self) = @_;
    while (1) {
        my $buf;
        my $peer = recv($self->{rtp}, $buf, 4096, 0);
        last unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $src = inet_ntoa($iaddr) . ':' . $port;
        my $pkt = Cantus::Sip::rtp_parse($buf) or next;
        my ($d) = grep { $_->{state} ne 'ended' } values %{ $self->{dialogs} };
        next unless $d;
        next unless $pkt->{pt} == $d->{pt};
        # Symmetric RTP: follow the source. A softphone behind a NAT is reachable
        # only at the address its packets come from, not the one in its SDP.
        $d->{remote} = $src if $src ne $d->{remote} && $d->{rx_frames} == 0;

        my $pcm = $d->{codec} eq 'PCMA'
            ? Cantus::G711::a_to_pcm($pkt->{payload})
            : Cantus::G711::mu_to_pcm($pkt->{payload});
        next unless length $pcm;
        my $peak = Cantus::Media::peak($pcm);
        $d->{rx_peak} = $peak if $peak > $d->{rx_peak};
        $d->{rx_frames}++;
        $self->{rtp_frames}++;
        push @{ $d->{in} }, $pcm;
        shift @{ $d->{in} } while @{ $d->{in} } > QUEUE_MAX;
    }
}

# One 20 ms frame per active call, every tick.  Silence is padded rather than
# skipped: a softphone that stops receiving packets stops playing, and a call
# with a gap every time the far end pauses sounds broken.
sub _rtp_tick {
    my ($self, $now) = @_;
    $now //= time;
    $self->{next_rtp} += RTP_TICK;
    $self->{next_rtp} = $now + RTP_TICK if $self->{next_rtp} < $now - 1;

    for my $d (values %{ $self->{dialogs} }) {
        next unless $d->{state} eq 'active';
        my $pcm = shift @{ $d->{out} };
        my $payload = $pcm
            ? ($d->{codec} eq 'PCMA' ? Cantus::G711::pcm_to_a($pcm) : Cantus::G711::pcm_to_mu($pcm))
            : ($d->{codec} eq 'PCMA' ? Cantus::G711::a_silence() : Cantus::G711::mu_silence());
        my $packet = Cantus::Sip::rtp_build(
            pt => $d->{pt}, seq => $d->{seq}++, ts => $d->{ts}, ssrc => $d->{ssrc},
            payload => $payload,
        );
        $d->{ts} += FRAME_SAMPLES;
        my ($ip, $port) = split /:/, $d->{remote}, 2;
        next unless $ip && $port;
        CORE::send($self->{rtp}, $packet, 0, sockaddr_in($port, inet_aton($ip)));
        $d->{tx_frames}++;
    }
}

1;
