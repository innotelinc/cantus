package Cantus::Gateway;
# The SIP edge: lines, calls, and the three things a switch has to understand.
#
# Phase 2a turned one account into a small switch. Every configured line has its
# own SIP account, its own Cantus node and one call at a time, and a call is
# placed through Cantus whether it goes to the configured endpoint or to another
# line's address of record -- so extension dialling uses the same media path a
# production node uses instead of a second, private one.
#
#   DTMF   RFC 4733 telephone-events in, a Cantus INFO out, and the reverse:
#          the far end's digit arrives at the phone as a real key press.
#   Hold   a re-INVITE with `a=sendonly`: the held line sends silence toward
#          Cantus and hears nothing back, and resumes where it was.
#   REFER  a blind transfer: the target line is rung (or handed the call it is
#          already on), the new leg is placed, and only then is the
#          transferor's released -- so a failed transfer leaves the call up.
#
# Every call ends in a CDR line: who, to what, how long, how much audio, which
# digits, and how it ended. Without that, "no stuck channel" is an opinion.
#
# Deliberately absent: TCP/TLS, SRTP, MWI, call waiting, conferencing. A line is
# one call; a second call to a busy line is 486, which is what a phone with one
# line expects to hear.
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
use Cantus::Session ();

use constant {
    RTP_TICK      => 0.020,
    FRAME_SAMPLES => 160,       # 20 ms at 8 kHz
    FRAME_BYTES   => 320,       # pcm-s16
    QUEUE_MAX     => 8,         # 160 ms of buffer, then it is too late to help
    REFRESH       => 20,
    TICK          => 0.002,
    RING_TIMEOUT  => 25,
    CDR_MAX       => 200,
    EVENT_PACKETS => 6,         # a 120 ms key press, as RFC 4733 asks
    EVENT_STEP    => 160,       # samples per 20 ms packet
    EVENT_PT      => 101,
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
        realm      => $cfg->{realm} // 'cantus',
        advertise  => $cfg->{advertise} // '127.0.0.1',
        target     => $target,
        base_id    => $cfg->{id} // 'gateway@switch.example',
        lines      => {},
        order      => [],
        pending    => {},
        handoff    => {},
        running    => 1,
        started    => time,
        next_rtp   => time,
        next_reg   => 0,
        rtp_frames => 0,
        sip_frames => 0,
        events     => [],
        cdrs       => [],
        on_event   => $a{on_event} // sub { },
        quiet      => $a{quiet} ? 1 : 0,
    }, $class;

    $self->_load_lines($cfg);
    $self->_bind_sip($cfg);
    $self->_bind_rtp($cfg);
    $self->_make_node($_) for @{ $self->{order} };
    return $self;
}

# ------------------------------------------------------------------ setup

sub _load_lines {
    my ($self, $cfg) = @_;
    my @accounts = @{ $cfg->{accounts} || [ $cfg->{account} || { user => '101' } ] };
    my ($local, $domain) = split /\@/, $self->{base_id}, 2;
    $domain //= 'switch.example';

    for my $a (@accounts) {
        my $user = $a->{user} // die "gateway: an account needs a user\n";
        die "gateway: duplicate account $user\n" if $self->{lines}{$user};

        # The secret belongs in the environment, per line first so two
        # extensions can differ: GATEWAY_PASSWORD_102 beats GATEWAY_PASSWORD,
        # and neither is ever written into the config that gets reviewed.
        my $password = $ENV{"GATEWAY_PASSWORD_$user"} // $ENV{GATEWAY_PASSWORD} // $a->{password};

        my $line = {
            user     => $user,
            password => $password,
            target   => $a->{target} // $cfg->{target},
            id       => $a->{id} // "$local-$user\@$domain",
            contact  => undef,
            dialog   => undef,
        };
        $self->{lines}{$user} = $line;
        push @{ $self->{order} }, $line;
    }
    die "gateway: no lines configured\n" unless @{ $self->{order} };
}

sub _bind_sip {
    my ($self, $cfg) = @_;
    my $bind = $cfg->{bind} // '0.0.0.0:5062';
    my ($host, $port) = split /:/, $bind, 2;
    $self->{sip} = IO::Socket::INET->new(
        LocalAddr => $host || '0.0.0.0', LocalPort => ($port || 5062),
        Proto => 'udp', ReuseAddr => 1,
    ) or die "cantus gateway: cannot bind SIP $bind: $!\n";
    $self->{sip}->blocking(0);
    # IO::Socket::INET reports sockport 0 for an unconnected UDP socket on this
    # build, so the port has to come from the bound address itself.
    $self->{sip_port} = (sockaddr_in($self->{sip}->sockname))[0];
}

# A port per call, opened when the call is and closed when it ends.
#
# The first version kept a fixed pool and handed a released port straight to
# the next call. A phone that had not yet processed its BYE kept sending to
# that port, and symmetric RTP -- which exists so a NATted phone is reachable --
# latched the new call onto the *old* phone's address: audio went nowhere and
# the new call looked dead while both ends were fine. A released port now
# closes and stays closed for a few seconds, which is longer than any phone
# needs to notice the BYE.
sub _bind_rtp {
    my ($self, $cfg) = @_;
    $self->{rtp_base}     = $cfg->{rtp_port} // 41000;
    $self->{rtp_used}     = {};
    $self->{rtp_cooldown} = {};
    $self->{rtp_port}     = $self->{rtp_base};
}

sub _take_rtp {
    my ($self) = @_;
    my $now = time;
    for my $p ($self->{rtp_base} .. $self->{rtp_base} + 40) {
        next if $self->{rtp_used}{$p};
        next if ($self->{rtp_cooldown}{$p} // 0) > $now;
        my $sock = IO::Socket::INET->new(
            LocalAddr => '0.0.0.0', LocalPort => $p, Proto => 'udp', ReuseAddr => 1,
        ) or next;
        $sock->blocking(0);
        $self->{rtp_used}{$p} = 1;
        return { sock => $sock, port => $p };
    }
    return undef;
}

# The Cantus side of a line is a node like any other: it registers with the
# relay and places ordinary calls.  audio_source and on_audio are what make it
# a bridge rather than a tone generator, and auto_answer is off because the
# phone decides when a call is answered, not the edge.
sub _make_node {
    my ($self, $line) = @_;
    $line->{node} = Cantus::Node->new(
        id           => $line->{id},
        bind         => '0.0.0.0:0',
        secret       => $self->{cfg}{secret} // 'cantus-loopback',
        relay        => $self->{cfg}{relay},
        auto_answer  => 0,
        debug        => $self->{cfg}{debug} // 0,
        audio_source => sub { $self->_from_phone($line, @_) },
        on_audio     => sub { $self->_to_phone($line, @_) },
        on_event     => sub { $self->_cantus_event($line, @_) },
    );
}

# ------------------------------------------------------------------ access

sub sip_port { $_[0]{sip_port} }
sub rtp_port { $_[0]{rtp_port} }
sub lines    { $_[0]{lines} }
sub node     { $_[0]{order}[0]{node} }
sub dialogs  { { map { $_->{user} => $_->{dialog} } grep { $_->{dialog} } @{ $_[0]{order} } } }
sub cdrs     { $_[0]{cdrs} }

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
    my %dialogs;
    for my $line (@{ $self->{order} }) {
        my $d = $line->{dialog} or next;
        my %copy = %$d;
        delete @copy{qw(in out events invite rtp line)};
        $dialogs{ $line->{user} } = \%copy;
    }
    return {
        lines      => { map { $_->{user} => ($_->{contact} ? $_->{contact}{addr} : undef) } @{ $self->{order} } },
        dialogs    => \%dialogs,
        cdrs       => scalar @{ $self->{cdrs} },
        rtp_frames => $self->{rtp_frames},
        sip_frames => $self->{sip_frames},
        cantus     => { map { $_->{user} => $_->{node}->stats } @{ $self->{order} } },
    };
}

# ------------------------------------------------------------------ loop

sub stop { $_[0]{running} = 0 }

sub run {
    my ($self) = @_;
    $SIG{INT} = $SIG{TERM} = sub { $self->{running} = 0 };
    $self->emit({ kind => 'ready', sip => "$self->{advertise}:$self->{sip_port}",
                  rtp => $self->{rtp_port}, target => $self->{target},
                  lines => [ map { $_->{user} } @{ $self->{order} } ] });
    $self->_register_all;
    while ($self->{running}) {
        $self->pump(TICK);
        sleep TICK;
    }
    $self->emit({ kind => 'stopped', %{ $self->stats } });
    return 0;
}

# One iteration of the loop, without the sleep.  `run` is pump in a loop, which
# is what lets a test drive a gateway, a relay and two phones in one process
# instead of guessing at process timing.
sub pump {
    my ($self, $timeout) = @_;
    my @socks = ($self->{sip},
        map { $_->{dialog}{rtp} } grep { $_->{dialog} } @{ $self->{order} });
    my $sel = IO::Select->new(@socks);
    for my $fh ($sel->can_read($timeout // 0)) {
        if ($fh == $self->{sip}) { $self->_drain_sip }
        else                     { $self->_drain_rtp($fh) }
    }

    for my $line (@{ $self->{order} }) {
        eval { $line->{node}->pump(0) };
        $self->emit({ kind => 'error', line => $line->{user}, error => $@ }) if $@;
    }

    if ($self->{cfg}{relay} && time >= $self->{next_reg}) {
        $self->_register_all;
        $self->{next_reg} = time + REFRESH;
    }
    $self->_rtp_tick;
    $self->_timers;
    return 1;
}

sub _register_all {
    my ($self) = @_;
    $_->{node}->register for @{ $self->{order} };
}

sub _timers {
    my ($self) = @_;
    my $now = time;
    for my $call_id (keys %{ $self->{pending} }) {
        my $d = $self->{pending}{$call_id} or next;
        next if $now < ($d->{ring_deadline} // 0);
        delete $self->{pending}{$call_id};
        $self->emit({ kind => 'ring-timeout', call => $call_id, line => $d->{line}{user} });
        $self->_send_cancel($d);
        if (my $s = $self->_session_of($d)) {
            $d->{line}{node}->reject($s, Cantus::Session::reason_id('TIMEOUT'));
        }
        $self->_fail_peer($d, 408);
        $self->_end_dialog($d, 'no answer', notify => 0);
    }
    for my $user (keys %{ $self->{handoff} }) {
        next if $now - ($self->{handoff}{$user}{at} // 0) < RING_TIMEOUT;
        delete $self->{handoff}{$user};
        $self->emit({ kind => 'transfer-timeout', line => $user });
    }
}

# ------------------------------------------------------------------ SIP in

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
        unless ($msg->{request}) { $self->_on_response($msg); next }
        my $m = $msg->{method};
        my $fn = $self->can('_on_' . lc $m) or do {
            $self->_reply($msg, 405);
            next;
        };
        eval { $self->$fn($msg) };
        $self->emit({ kind => 'error', error => $@ }) if $@;
    }
}

sub _send_to {
    my ($self, $addr, $text) = @_;
    my ($ip, $port) = split /:/, $addr // '', 2;
    return 0 unless $ip && $port;
    my $packed = inet_aton($ip) or return 0;
    CORE::send($self->{sip}, $text, 0, sockaddr_in($port, $packed));
    return 1;
}

sub _reply {
    my ($self, $req, $code, %a) = @_;
    my $text = Cantus::Sip::response($req, $code, %a);
    $self->_send_to($req->{src}, $text);
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

sub _contact {
    my ($self, $line) = @_;
    return '<sip:' . $line->{user} . '@' . $self->{advertise} . ':' . $self->{sip_port} . '>';
}

sub _line_for {
    my ($self, $msg) = @_;
    my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
    return undef unless $from && defined $from->{user};
    my $line = $self->{lines}{ $from->{user} } or return undef;
    my $c = $line->{contact};
    return undef unless $c && $c->{expires} > time;
    return $line;
}

sub _on_options {
    my ($self, $msg) = @_;
    $self->_reply($msg, 200);
}

# Every line is challenged once and then remembered; the contact is what a
# later INVITE is checked against, so an unregistered source cannot place a
# call by guessing an extension.
sub _on_register {
    my ($self, $msg) = @_;
    my $from = Cantus::Sip::parse_uri(Cantus::Sip::header($msg, 'from'));
    my $user = $from && defined $from->{user} ? $from->{user} : '';
    my $line = $self->{lines}{$user};

    # Only configured accounts are challenged. Challenging everyone turns the
    # gateway into an oracle for whatever else on the LAN is looking for a
    # registrar, and the challenge/response storm starves the media loop.
    unless ($line) {
        $self->_refuse($msg, 403, 'unknown account');
        return;
    }

    my ($ok, $why) = Cantus::Sip::verify_digest(
        msg => $msg, method => 'REGISTER', user => $user,
        password => $line->{password} // '', realm => $self->{realm},
    );
    unless ($ok) {
        my $nonce = Cantus::Sip::nonce();
        $self->_refuse($msg, 401, $why,
            headers => [ Cantus::Sip::challenge_header($self->{realm}, $nonce) ]);
        return;
    }
    my $contact = Cantus::Sip::header($msg, 'contact') // '';
    my $expires = Cantus::Sip::header($msg, 'expires') // 3600;
    $line->{contact} = {
        addr    => $msg->{src},
        contact => $contact,
        uri     => $from,
        expires => time + $expires,
    };
    $self->emit({ kind => 'registered', user => $user, addr => $msg->{src}, expires => $expires });
    $self->_reply($msg, 200, contact => $contact, expires => $expires);
}

# An INVITE becomes a Cantus call.  The SIP side is answered with 180 at once
# (so a softphone rings rather than retransmitting), and with 200 + SDP when
# the Cantus peer accepts -- the gateway never claims a call it has not
# established.
sub _on_invite {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;

    my $line = $self->_line_for($msg);
    unless ($line) {
        $self->emit({ kind => 'invite-refused', call => $call_id, src => $msg->{src} });
        $self->_refuse($msg, 403, 'unregistered caller');
        return;
    }

    if (my $existing = $line->{dialog}) {
        # A re-INVITE on the dialog that is already up is hold, resume or a
        # media change -- not a second call.
        if (Cantus::Sip::tag($msg, 'to')) { $self->_reinvite($existing, $msg); return }
        if ($existing->{call_id} eq $call_id) {
            $self->_reply($msg, 200, sdp => $existing->{sdp}, contact => $self->_contact($line),
                          to_tag => $existing->{to_tag});
            return;
        }
        $self->emit({ kind => 'busy', line => $line->{user}, call => $call_id });
        $self->_reply($msg, 486);
        return;
    }

    my $sdp = Cantus::Sip::sdp_parse($msg->{body});
    unless ($sdp && $sdp->{ip}) {
        $self->emit({ kind => 'invite-no-codec', call => $call_id, line => $line->{user} });
        $self->_reply($msg, 488);
        return;
    }

    my $to = Cantus::Sip::parse_uri($msg->{uri});
    my $to_user = $to && defined $to->{user} ? $to->{user} : '';
    my $peer_line = $self->{lines}{$to_user};
    # Dialling another line's number is an internal call: the Cantus leg goes
    # to that line's own address of record, so both ends are ordinary nodes.
    my $aor = $peer_line ? $peer_line->{id} : $line->{target};

    my $d = $self->_new_dialog($line,
        call_id => $call_id, from_tag => Cantus::Sip::tag($msg, 'from') // 'gw',
        cseq => (Cantus::Sip::header($msg, 'cseq') // '1') =~ /^(\d+)/ ? $1 : 1,
        codec => $sdp->{codec}, event_pt => $sdp->{event_pt},
        phone_placed => 1, from_user => $line->{user},
        to_user => $to_user || $line->{target},
        target_aor => $aor, peer_line => $peer_line ? $peer_line->{user} : undef,
    );
    $d->{invite} = $msg;
    $d->{remote} = "$sdp->{ip}:$sdp->{port}";

    $self->_reply($msg, 180, to_tag => $d->{to_tag});
    $self->emit({ kind => 'invite', call => $call_id, line => $line->{user},
                  to => $d->{to_user}, codec => $d->{codec} });
    $self->_place($line, $d);
}

# Hold and resume are the same message with a different direction.  The answer
# mirrors the offer (sendonly is answered recvonly), and the media hooks read
# `held` so a held line neither sends nor hears the far end.
sub _reinvite {
    my ($self, $d, $msg) = @_;
    my $sdp = Cantus::Sip::sdp_parse($msg->{body});
    my $dir = $sdp ? $sdp->{direction} : 'sendrecv';
    my $was_held = $d->{held};
    $d->{held} = ($dir eq 'sendonly' || $dir eq 'inactive') ? 1 : 0;
    if ($d->{held} && !$was_held) {
        # A hold takes effect now, not 160 ms from now: the queues hold the far
        # end's last frames, and playing them out is exactly the "held line
        # still hears the caller" that makes a hold button look broken.
        @{ $d->{in} } = ();
        @{ $d->{out} } = ();
        if (my $peer = $self->{lines}{ $d->{peer_line} // '' }) {
            @{ $peer->{dialog}{out} } = () if $peer->{dialog};
        }
    }
    my $answer_dir = $dir eq 'sendonly' ? 'recvonly'
                   : $dir eq 'recvonly' ? 'sendonly'
                   : $dir;
    $self->_reply($msg, 200, to_tag => $d->{to_tag},
        contact => $self->_contact($d->{line}),
        sdp => Cantus::Sip::sdp_answer(
            ip => $self->{advertise}, port => $d->{rtp_port},
            codec => $d->{codec}, event_pt => $d->{event_pt}, direction => $answer_dir,
        ));
    $self->emit({ kind => $d->{held} ? 'hold' : 'resume', call => $d->{call_id},
                  line => $d->{line}{user} });
}

sub _on_ack {
    my ($self, $msg) = @_;
    my $d = $self->{dialogs_by_call}{ Cantus::Sip::header($msg, 'call-id') // '' } or return;
    $d->{state} = 'active' if $d->{state} eq 'ringing' && length $d->{sdp};
    $self->emit({ kind => 'ack', call => $d->{call_id}, state => $d->{state} });
}

sub _on_bye {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;
    $self->_reply($msg, 200);
    my $d = $self->{dialogs_by_call}{$call_id} or return;
    $self->_end_dialog($d, 'peer hung up', notify => 0);
}

sub _on_cancel {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;
    $self->_reply($msg, 200);
    my $d = $self->{dialogs_by_call}{$call_id} or return;
    $self->_end_dialog($d, 'cancelled', notify => 0);
}

# A REFER hands the call to another line.  Answering it first and moving the
# call second is the only order that cannot lose a call: a transfer that is
# accepted and then fails leaves the transferor still connected.
sub _on_refer {
    my ($self, $msg) = @_;
    my $line = $self->_line_for($msg);
    unless ($line) { $self->_refuse($msg, 403, 'unregistered referrer'); return }
    my $d = $line->{dialog};
    unless ($d && $d->{state} eq 'active') { $self->_reply($msg, 481); return }

    my $to = Cantus::Sip::refer_to($msg);
    my $target = $to && defined $to->{user} ? $self->{lines}{ $to->{user} } : undef;
    unless ($target) {
        $self->emit({ kind => 'refer-unknown', call => $d->{call_id},
                      to => $to ? $to->{user} : undef });
        $self->_reply($msg, 404);
        return;
    }
    if ($target->{user} eq $line->{user}) { $self->_reply($msg, 400); return }
    if ($target->{dialog}) {
        $self->emit({ kind => 'refer-busy', call => $d->{call_id}, to => $target->{user} });
        $self->_reply($msg, 486);
        return;
    }

    $self->_reply($msg, 202, contact => $self->_contact($line));
    $self->_notify_refer($msg, $d, 200);

    # The party that stays: another line (B) or the Cantus endpoint the call
    # was placed to.  B is already on the call, so it is handed the new session
    # instead of being rung again.
    my $peer = $d->{peer_line} ? $self->{lines}{ $d->{peer_line} } : undef;
    if ($peer) {
        $self->{handoff}{ $peer->{user} } = { from => $line->{user}, at => time };
        my $call = $target->{node}->call($peer->{id});
        unless ($call) {
            delete $self->{handoff}{ $peer->{user} };
            $self->_notify_refer($msg, $d, 503);
            return;
        }
        $self->emit({ kind => 'transfer', call => $d->{call_id}, from => $line->{user},
                      to => $target->{user}, peer => $peer->{user} });
        return;
    }

    my $ring = $self->_ring_line($target, undef,
        from => $line->{user}, dial_aor => $d->{target_aor}, transfer_of => $d);
    unless ($ring) {
        $self->_notify_refer($msg, $d, 480);
        return;
    }
    $self->emit({ kind => 'transfer', call => $d->{call_id}, from => $line->{user},
                  to => $target->{user}, to_line => $target->{user} });
}

# RFC 3515 progress report.  A phone that sent REFER waits for this before it
# tears its own leg down, so a transfer without it hangs up the wrong end.
sub _notify_refer {
    my ($self, $refer, $d, $code) = @_;
    my $to = Cantus::Sip::header($refer, 'to') // return;
    $to .= ';tag=' . $d->{to_tag} unless $to =~ /;tag=/;
    my $cseq = (Cantus::Sip::header($refer, 'cseq') // '1') =~ /^(\d+)/ ? $1 + 1 : 2;
    my $body = 'SIP/2.0 ' . $code . ' ' . Cantus::Sip::reason_for($code) . "\r\n";
    my $text = Cantus::Sip::request(
        method  => 'NOTIFY',
        uri     => $refer->{uri},
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => Cantus::Sip::header($refer, 'from'),
        to      => $to,
        call_id => $d->{call_id},
        cseq    => $cseq,
        contact => $self->_contact($d->{line}),
        headers => [ 'Event: refer', 'Subscription-State: terminated;reason=noresource' ],
        body    => $body, content_type => 'message/sipfrag',
    );
    $self->_send_to($refer->{src}, $text);
}

# ------------------------------------------------------------------ SIP out

sub _new_dialog {
    my ($self, $line, %a) = @_;
    my $slot = $self->_take_rtp;
    unless ($slot) {
        $self->emit({ kind => 'error', error => 'no free RTP port' });
        return undef;
    }
    my $codec = $a{codec} // 'PCMU';
    my $d = {
        line      => $line,
        rtp       => $slot->{sock},
        rtp_port  => $slot->{port},
        call_id   => $a{call_id} // ('gw-' . int(rand(1_000_000_000)) . '-' . $$),
        from_tag  => $a{from_tag} // ('gw' . int(rand(1_000_000))),
        to_tag    => $a{to_tag} // ('cantus' . int(rand(1_000_000))),
        cseq      => $a{cseq} // 0,
        state     => 'ringing',
        held      => 0,
        codec     => $codec,
        pt        => $codec eq 'PCMA' ? 8 : 0,
        event_pt  => $a{event_pt} // EVENT_PT,
        ssrc      => int(rand(2_000_000_000)),
        seq       => int(rand(30_000)),
        ts        => int(rand(100_000)),
        in        => [],
        out       => [],
        events    => [],
        dtmf      => [],
        dtmf_live => {},
        rx_frames => 0,
        tx_frames => 0,
        rx_peak   => 0,
        tx_peak   => 0,
        started   => time,
        phone_placed => $a{phone_placed} ? 1 : 0,
        outbound     => $a{outbound} ? 1 : 0,
        from_user    => $a{from_user} // $line->{user},
        to_user      => $a{to_user} // $line->{user},
        target_aor   => $a{target_aor},
        peer_line    => $a{peer_line},
        transfer_of  => $a{transfer_of},
        direction    => 'sendrecv',
        session      => undef,
    };
    $d->{sdp} = Cantus::Sip::sdp_answer(
        ip => $self->{advertise}, port => $d->{rtp_port},
        codec => $codec, event_pt => $d->{event_pt},
    );
    $line->{dialog} = $d;
    $self->{dialogs_by_call}{ $d->{call_id} } = $d;
    return $d;
}

sub _release_dialog {
    my ($self, $d) = @_;
    delete $self->{dialogs_by_call}{ $d->{call_id} };
    return unless $d->{rtp};
    close $d->{rtp};
    delete $self->{rtp_used}{ $d->{rtp_port} };
    $self->{rtp_cooldown}{ $d->{rtp_port} } = time + 10;
    delete $d->{rtp};
}

# Ring a line's phone.  `$s` is the Cantus session that is waiting for the
# phone to pick up (incoming call) or undef (a transfer, where the leg is
# placed after the phone answers).
sub _ring_line {
    my ($self, $line, $s, %ctx) = @_;
    my $c = $line->{contact};
    if (!$c || $c->{expires} <= time) {
        $self->emit({ kind => 'line-unavailable', line => $line->{user}, why => 'not registered' });
        $line->{node}->reject($s, Cantus::Session::reason_id('UNAVAILABLE')) if $s;
        return undef;
    }
    my $d = $self->_new_dialog($line,
        outbound    => 1,
        from_user   => $ctx{from} // $line->{user},
        to_user     => $line->{user},
        target_aor  => $ctx{dial_aor},
        transfer_of => $ctx{transfer_of},
    ) or return undef;
    $d->{session} = $s->{call} if $s;
    $d->{ring_deadline} = time + RING_TIMEOUT;
    $self->{pending}{ $d->{call_id} } = $d;
    $self->_send_invite($d);
    $self->emit({ kind => 'ringing', call => $d->{call_id}, line => $line->{user},
                  from => $d->{from_user} });
    return $d;
}

sub _send_invite {
    my ($self, $d) = @_;
    my $uri = 'sip:' . $d->{to_user} . '@' . $self->{advertise};
    my $text = Cantus::Sip::request(
        method  => 'INVITE',
        uri     => $uri,
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => '<sip:' . $d->{from_user} . '@' . $self->{realm} . '>;tag=' . $d->{from_tag},
        to      => '<sip:' . $d->{to_user} . '@' . $self->{realm} . '>',
        call_id => $d->{call_id},
        cseq    => ++$d->{cseq},
        contact => $self->_contact($d->{line}),
        body    => $d->{sdp},
    );
    $self->_send_to($d->{line}{contact}{addr}, $text);
}

sub _send_ack {
    my ($self, $d, $addr) = @_;
    my $text = Cantus::Sip::request(
        method  => 'ACK',
        uri     => 'sip:' . $d->{to_user} . '@' . $self->{advertise},
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => '<sip:' . $d->{from_user} . '@' . $self->{realm} . '>;tag=' . $d->{from_tag},
        to      => '<sip:' . $d->{to_user} . '@' . $self->{realm} . '>;tag=' . $d->{to_tag},
        call_id => $d->{call_id},
        cseq    => $d->{cseq},
        contact => $self->_contact($d->{line}),
    );
    $self->_send_to($addr // $d->{line}{contact}{addr}, $text);
}

sub _send_cancel {
    my ($self, $d) = @_;
    my $text = Cantus::Sip::request(
        method  => 'CANCEL',
        uri     => 'sip:' . $d->{to_user} . '@' . $self->{advertise},
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => '<sip:' . $d->{from_user} . '@' . $self->{realm} . '>;tag=' . $d->{from_tag},
        to      => '<sip:' . $d->{to_user} . '@' . $self->{realm} . '>',
        call_id => $d->{call_id},
        cseq    => $d->{cseq},
        contact => $self->_contact($d->{line}),
    );
    $self->_send_to($d->{line}{contact}{addr}, $text);
}

sub _send_bye {
    my ($self, $d, $reason) = @_;
    my $text = Cantus::Sip::request(
        method  => 'BYE',
        uri     => 'sip:' . $d->{to_user} . '@' . $self->{advertise},
        via     => $self->{advertise} . ':' . $self->{sip_port} . ';branch=z9hG4bK' . int(rand(1_000_000)),
        from    => '<sip:' . $d->{from_user} . '@' . $self->{realm} . '>;tag=' . $d->{from_tag},
        to      => '<sip:' . $d->{to_user} . '@' . $self->{realm} . '>;tag=' . $d->{to_tag},
        call_id => $d->{call_id},
        cseq    => ++$d->{cseq},
        contact => $self->_contact($d->{line}),
    );
    $self->_send_to($d->{line}{contact}{addr}, $text);
    $self->emit({ kind => 'bye-sent', call => $d->{call_id}, reason => $reason });
}

sub _on_response {
    my ($self, $msg) = @_;
    my $call_id = Cantus::Sip::header($msg, 'call-id') // return;
    my $d = $self->{pending}{$call_id} or return;
    my $code = $msg->{status} // 0;
    return if $code < 200;
    delete $self->{pending}{$call_id};
    my $line = $d->{line};

    if ($code >= 300) {
        $self->emit({ kind => 'line-unavailable', call => $call_id,
                      line => $line->{user}, code => $code });
        if (my $s = $self->_session_of($d)) {
            $line->{node}->reject($s, Cantus::Session::reason_id('UNAVAILABLE'));
        }
        $self->_fail_peer($d, $code == 486 ? 486 : ($code == 408 ? 408 : 480));
        $self->_end_dialog($d, "phone $code", notify => 0);
        return;
    }

    my $answer = Cantus::Sip::sdp_parse($msg->{body}) // {};
    my ($ip, $port) = split /:/, $msg->{src} // '', 2;
    $d->{remote} = ($answer->{ip} // $ip) . ':' . ($answer->{port} // 0);
    $d->{codec} = $answer->{codec} // $d->{codec};
    $d->{pt} = $d->{codec} eq 'PCMA' ? 8 : 0;
    $d->{event_pt} = $answer->{event_pt} // $d->{event_pt};
    $d->{to_tag} = Cantus::Sip::tag($msg, 'to') // $d->{to_tag};
    $d->{state} = 'active';
    $d->{answered_at} = time;
    $self->_send_ack($d, $msg->{src});
    $self->emit({ kind => 'answered', call => $call_id, line => $line->{user},
                  codec => $d->{codec}, remote => $d->{remote},
                  rtp_port => $d->{rtp_port} });

    # The phone is up; only now does the Cantus side get to answer.
    if (my $s = $self->_session_of($d)) {
        $line->{node}->accept($s);
    }
    elsif ($d->{target_aor}) {
        my $call = $line->{node}->call($d->{target_aor});
        if ($call) { $d->{session} = $call }
        else       { $self->_end_dialog($d, 'cantus-failed', notify => 1) }
    }
}

# ------------------------------------------------------------------ dialogs

sub _session_of {
    my ($self, $d) = @_;
    return undef unless $d && $d->{session};
    return $d->{line}{node}->session($d->{session});
}

sub _place {
    my ($self, $line, $d) = @_;
    return if $d->{session};
    unless ($line->{node}->handle) {
        $line->{node}->register;
        $d->{waiting} = 1;
        $self->emit({ kind => 'cantus-waiting', call => $d->{call_id}, line => $line->{user} });
        return;
    }
    my $call = $line->{node}->call($d->{target_aor});
    unless ($call) {
        $self->emit({ kind => 'cantus-failed', call => $d->{call_id}, target => $d->{target_aor} });
        $self->_reply($d->{invite}, 503, to_tag => $d->{to_tag}) if $d->{invite};
        $self->_end_dialog($d, 'cantus-failed', notify => 0);
        return;
    }
    $d->{waiting} = 0;
    $d->{session} = $call;
}

sub _fail_peer {
    my ($self, $d, $code) = @_;
    return unless $d && $d->{invite};
    $self->_reply($d->{invite}, $code, to_tag => $d->{to_tag});
    $self->_end_dialog($d, "peer $code", notify => 0);
}

sub _end_dialog {
    my ($self, $d, $why, %a) = @_;
    return if !$d || $d->{state} eq 'ended';
    $d->{state} = 'ended';
    $d->{ended_at} = time;
    my $line = $d->{line};
    $line->{dialog} = undef if $line->{dialog} && $line->{dialog} == $d;
    delete $self->{pending}{ $d->{call_id} };
    delete $self->{handoff}{ $line->{user} }
        if ($self->{handoff}{ $line->{user} }{call} // '') eq $d->{call_id};

    if ($d->{session} && ($a{terminate} // 1)) {
        eval { $line->{node}->hangup($d->{session}, 'NORMAL') };
    }
    $self->_send_bye($d, $why) if $a{notify};
    $self->_release_dialog($d);
    $self->_cdr($d, $why);
}

# One line per call, in the log and in `stats`.  A CDR that is written only
# when someone asks for it is a CDR that is missing when it matters.
sub _cdr {
    my ($self, $d, $result) = @_;
    my $rec = {
        kind      => 'cdr',
        call      => $d->{call_id},
        line      => $d->{line}{user},
        from      => $d->{from_user},
        to        => $d->{to_user},
        direction => $d->{phone_placed} ? 'outbound' : 'inbound',
        result    => $result,
        answered  => $d->{answered_at} ? 1 : 0,
        seconds   => sprintf('%.1f', ($d->{ended_at} // time) - $d->{started}),
        rx_frames => $d->{rx_frames},
        tx_frames => $d->{tx_frames},
        dtmf      => join('', @{ $d->{dtmf} || [] }),
    };
    push @{ $self->{cdrs} }, $rec;
    shift @{ $self->{cdrs} } while @{ $self->{cdrs} } > CDR_MAX;
    $self->emit($rec);
}

# ------------------------------------------------------------------ Cantus

sub _cantus_event {
    my ($self, $line, $ev) = @_;
    my $kind = $ev->{kind} // '';

    if ($kind eq 'registered') {
        my $d = $line->{dialog};
        $self->_place($line, $d) if $d && $d->{waiting};
        return;
    }

    if ($kind eq 'incoming') {
        my $s = $line->{node}->session($ev->{call}) or return;
        # A transfer lands here: the line being handed the call is already on
        # one, and the hand-off replaces its session instead of ringing it.
        if (my $t = delete $self->{handoff}{ $line->{user} }) {
            $self->_takeover($line, $s, $t);
            return;
        }
        if ($line->{dialog}) {
            $self->emit({ kind => 'busy', line => $line->{user}, from => $ev->{from} });
            $line->{node}->reject($s, Cantus::Session::reason_id('BUSY'));
            return;
        }
        $self->_ring_line($line, $s, from => $ev->{from});
        return;
    }

    if ($kind eq 'accepted') {
        my $d = $line->{dialog};
        return unless $d && ($d->{session} // '') eq ($ev->{call} // '');
        if ($d->{state} eq 'ringing') {
            $d->{state} = 'active';
            $d->{answered_at} = time;
            $self->_reply($d->{invite}, 200, to_tag => $d->{to_tag},
                          contact => $self->_contact($line), sdp => $d->{sdp});
            $self->emit({ kind => 'answered', call => $d->{call_id}, line => $line->{user},
                          codec => $ev->{codec}, remote => $d->{remote},
                          rtp_port => $d->{rtp_port} });
        }
        # A transfer's new leg is up: now the transferor's can go.
        if (my $td = delete $d->{transfer_of}) {
            $self->_end_dialog($td, 'transferred', notify => 1);
        }
        return;
    }

    if ($kind eq 'dtmf') {
        my $d = $line->{dialog};
        return unless $d && ($d->{session} // '') eq ($ev->{call} // '');
        push @{ $d->{dtmf} }, $ev->{digit};
        $self->_dtmf_to_phone($d, $ev->{digit});
        $self->emit({ kind => 'dtmf', call => $d->{call_id}, line => $line->{user},
                      digit => $ev->{digit}, source => 'cantus' });
        return;
    }

    if ($kind eq 'ended' || $kind eq 'rejected') {
        my $d = $line->{dialog} or return;
        return unless ($d->{session} // '') eq ($ev->{call} // '');
        my $why = $kind eq 'rejected' ? 'rejected' : ($ev->{reason} // 'NORMAL');
        if ($d->{state} eq 'ringing' && $d->{invite}) {
            # The far end never answered, or could not be reached at all.  The
            # phone gets a final response -- a BYE for a call it was never told
            # it had leaves a softphone ringing until it gives up on its own.
            $self->_reply($d->{invite}, $kind eq 'rejected' ? 480 : 408,
                          to_tag => $d->{to_tag});
            $self->_end_dialog($d, $why, notify => 0);
            return;
        }
        $self->_end_dialog($d, $why, notify => 1);
        return;
    }
}

# The party that stays is handed the new session: its phone keeps its dialog,
# its media follows the new call, and the transferor's leg is released.
sub _takeover {
    my ($self, $line, $s, $t) = @_;
    my $d = $line->{dialog};
    unless ($d) {
        $line->{node}->reject($s, Cantus::Session::reason_id('UNAVAILABLE'));
        return;
    }
    my $old = $d->{session};
    $d->{session} = $s->{call};
    $d->{from_user} = $t->{from};
    $line->{node}->accept($s);
    $self->emit({ kind => 'transfer-taken', call => $d->{call_id},
                  line => $line->{user}, from => $t->{from} });

    my $from = $self->{lines}{ $t->{from} };
    if ($from && $from->{dialog} && ($from->{dialog}{session} // '') eq ($old // '')) {
        $self->_end_dialog($from->{dialog}, 'transferred', notify => 1);
    }
}

# ------------------------------------------------------------------ media

sub _from_phone {
    my ($self, $line, $s, $n) = @_;
    my $d = $line->{dialog};
    return "\0" x FRAME_BYTES
        unless $d && ($d->{session} // '') eq ($s->{call} // '');
    return "\0" x FRAME_BYTES if $d->{held};
    my $pcm = shift @{ $d->{in} };
    $d->{cantus_out_frames}++ if $pcm;
    return $pcm ? $pcm : "\0" x FRAME_BYTES;
}

sub _to_phone {
    my ($self, $line, $s, $payload, $codec) = @_;
    my $d = $line->{dialog};
    return unless $d && ($d->{session} // '') eq ($s->{call} // '');
    return unless defined $payload && length $payload;
    # A held line hears nothing: the far end is still there, but not in this
    # conversation any more.
    return if $d->{held};
    my $peak = Cantus::Media::peak($payload);
    $d->{tx_peak} = $peak if $peak > $d->{tx_peak};
    push @{ $d->{out} }, $payload;
    shift @{ $d->{out} } while @{ $d->{out} } > QUEUE_MAX;
    $d->{from_cantus_frames}++;
}

# Digits travel to the phone as RFC 4733 events, six packets at 20 ms: a real
# key press, not a burst a phone's detector can miss.
sub _dtmf_to_phone {
    my ($self, $d, $digit) = @_;
    my $id = Cantus::Sip::dtmf_event_id($digit);
    return unless defined $id;
    $d->{event_ts} //= $d->{ts};
    for my $i (1 .. EVENT_PACKETS) {
        push @{ $d->{events} }, {
            event    => $id,
            end      => ($i == EVENT_PACKETS ? 1 : 0),
            duration => $i * EVENT_STEP,
        };
    }
}

sub _drain_rtp {
    my ($self, $fh) = @_;
    my ($d) = grep { $_ && $_->{rtp} && $_->{rtp} == $fh }
              map { $_->{dialog} } @{ $self->{order} };
    return unless $d;

    while (1) {
        my $buf;
        my $peer = recv($fh, $buf, 4096, 0);
        last unless defined $peer && length $buf;
        my ($port, $iaddr) = sockaddr_in($peer);
        my $src = inet_ntoa($iaddr) . ':' . $port;
        my $pkt = Cantus::Sip::rtp_parse($buf) or next;

        # RFC 4733 first: a digit is not audio and must not be decoded as any.
        if (defined $d->{event_pt} && $pkt->{pt} == $d->{event_pt}) {
            my $ev = Cantus::Sip::rtp_event_parse($pkt->{payload}) or next;
            if ($ev->{end}) { delete $d->{dtmf_live}{ $ev->{event} }; next }
            next if $d->{dtmf_live}{ $ev->{event} };   # retransmissions of one press
            $d->{dtmf_live}{ $ev->{event} } = 1;
            my $digit = Cantus::Sip::dtmf_digit($ev->{event}) // next;
            push @{ $d->{dtmf} }, $digit;
            $self->emit({ kind => 'dtmf', call => $d->{call_id},
                          line => $d->{line}{user}, digit => $digit, source => 'phone' });
            if (my $s = $self->_session_of($d)) {
                $d->{line}{node}->send_dtmf($s, $digit);
            }
            next;
        }

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

    for my $line (@{ $self->{order} }) {
        my $d = $line->{dialog} or next;
        next unless $d->{state} eq 'active' && $d->{rtp} && $d->{remote};
        my ($ip, $port) = split /:/, $d->{remote}, 2;
        next unless $ip && $port;

        my $packed = inet_aton($ip) or next;
        my $to = sockaddr_in($port, $packed);

        if (@{ $d->{events} }) {
            my $ev = shift @{ $d->{events} };
            my $packet = Cantus::Sip::rtp_build(
                pt => $d->{event_pt}, seq => $d->{seq}++, ts => $d->{event_ts},
                ssrc => $d->{ssrc}, marker => ($ev->{duration} == EVENT_STEP ? 1 : 0),
                payload => Cantus::Sip::rtp_event_build(
                    event => $ev->{event}, end => $ev->{end}, duration => $ev->{duration}),
            );
            CORE::send($d->{rtp}, $packet, 0, $to);
            if ($ev->{end}) {
                # The event occupied its own time on the clock; audio resumes
                # after it rather than overlapping it.
                $d->{ts} = $d->{event_ts} + $ev->{duration};
                delete $d->{event_ts};
            }
            next;
        }

        my $pcm = shift @{ $d->{out} };
        my $payload = $pcm
            ? ($d->{codec} eq 'PCMA' ? Cantus::G711::pcm_to_a($pcm) : Cantus::G711::pcm_to_mu($pcm))
            : ($d->{codec} eq 'PCMA' ? Cantus::G711::a_silence() : Cantus::G711::mu_silence());
        my $packet = Cantus::Sip::rtp_build(
            pt => $d->{pt}, seq => $d->{seq}++, ts => $d->{ts}, ssrc => $d->{ssrc},
            payload => $payload,
        );
        $d->{ts} += FRAME_SAMPLES;
        CORE::send($d->{rtp}, $packet, 0, $to);
        $d->{tx_frames}++;
    }
}

1;
