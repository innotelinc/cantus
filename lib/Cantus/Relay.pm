package Cantus::Relay;
# A Cantus relay: a registry, an observed-address reporter, and a forwarder.
# It holds no call state and cannot read media.
# See spec/CANTUS-1.0.md sections 4.2, 8.2, 8.3, 9.6.
#
# It listens on the same port twice: UDP is the baseline binding, and TCP is the
# fallback an endpoint reaches for when its NAT drops UDP (section 8.8).  A
# registration records which binding it arrived on, and forwarding to a TCP
# registration writes framed datagrams back down that connection, because the
# address a TCP peer came from is a NAT binding that expires, not an endpoint.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Socket qw(sockaddr_in inet_aton inet_ntoa);
use Time::HiRes qw(time);

use Cantus::Wire ();
use Cantus::Identity ();
use Cantus::Pump ();

sub new {
    my ($class, %a) = @_;
    my $self = bless {
        secret    => $a{secret} // 'cantus-loopback',
        on_event  => $a{on_event} // sub { },
        by_handle => {},     # handle -> { addr, tcp, id, expires }
        by_id     => {},     # endpoint id -> handle
        conns     => {},     # fileno -> { fh, buf, addr }
        next_handle => 1000,
        forwarded => 0,
        dropped   => 0,
        debug     => $a{debug} // 0,
        ttl       => $a{ttl} // 60,     # how long a registration is true
        running   => 1,
        log       => [],
        tcp_clients => 0,
    }, $class;
    my $bind = $a{bind} // '127.0.0.1:0';
    my ($h, $p) = split /:/, $bind, 2;

    if ($a{udp} // 1) {
        $self->{sock} = IO::Socket::INET->new(
            LocalAddr => $h, LocalPort => ($p || 0), Proto => 'udp', ReuseAddr => 1,
        ) or die "Cantus::Relay bind $bind: $!";
        $self->{sock}->blocking(0);
    }

    # The fallback lives on the same port as the UDP binding unless a config
    # says otherwise: that is the port the standard names, and on a host that
    # blocks UDP the TCP half still answers there.
    my $port = $self->{sock} ? $self->{sock}->sockport : ($p || 0);
    if ($a{tcp} // 1) {
        my $tcp_bind = $a{tcp_bind} // (($h eq '0.0.0.0' || !$h ? '0.0.0.0' : $h) . ':' . $port);
        my ($th, $tp) = split /:/, $tcp_bind, 2;
        $self->{listener} = IO::Socket::INET->new(
            LocalAddr => $th,
            LocalPort => ($tp || 0),
            Proto     => 'tcp',
            ReuseAddr => 1,
            Listen    => 128,
        ) or die "Cantus::Relay tcp bind $tcp_bind: $!";
        $self->{listener}->blocking(0);
        $self->{tcp_port} = $self->{listener}->sockport;
    }

    my $shown = $self->{sock} ? $self->{sock}->sockport : $self->{tcp_port};
    $self->{addr} = (($h eq '0.0.0.0' || !$h) ? '127.0.0.1' : $h) . ':' . $shown;
    $self->{ident} = Cantus::Identity->new(name => 'relay@' . $self->{addr}, secret => $self->{secret});
    $self->{started} = time;
    return $self;
}

sub addr     { $_[0]{addr} }
sub port     { my ($s) = @_; return $s->{sock} ? $s->{sock}->sockport : $s->{tcp_port} }
sub tcp_port { $_[0]{tcp_port} }
sub stop     { $_[0]{running} = 0 }
sub registry { $_[0]{by_handle} }
sub stats {
    my ($s) = @_;
    return {
        forwarded => $s->{forwarded},
        dropped => $s->{dropped},
        endpoints => scalar(keys %{ $s->{by_handle} }),
        tcp_clients => $s->{tcp_clients},
    };
}

sub emit {
    my ($self, $ev) = @_;
    my $rec = { %$ev, t => time - $self->{started} };
    push @{ $self->{log} }, $rec;
    $self->{on_event}->($rec);
}

# See Cantus::Pump and spec §15: pump(0) drains the queue and returns without
# waiting; pump($t) serves for at most $t; pump() is one default slice.
sub pump {
    my ($self, $seconds) = @_;
    my $until = Cantus::Pump::deadline($seconds);
    while ($self->{running}) {
        last if Cantus::Pump::expired($seconds, $until);
        my @ready;
        my $wait = Cantus::Pump::wait_for($seconds, $until - time);
        my $sel = IO::Select->new();
        $sel->add($self->{sock})     if $self->{sock};
        $sel->add($self->{listener}) if $self->{listener};
        $sel->add($_->{fh}) for values %{ $self->{conns} };
        @ready = $sel->can_read($wait);
        last if Cantus::Pump::finished($seconds, \@ready);
        $self->recv_one($_) for @ready;
    }
}

sub recv_one {
    my ($self, $fh) = @_;
    if ($self->{listener} && $fh == $self->{listener}) {
        my $conn = $self->{listener}->accept;
        return unless $conn;
        $conn->blocking(0);
        my ($port, $iaddr) = sockaddr_in($conn->peername // '');
        my $src = inet_ntoa($iaddr) . ':' . $port;
        $self->{conns}{ fileno($conn) } = { fh => $conn, buf => '', addr => $src };
        $self->{tcp_clients}++;
        $self->emit({ kind => 'tcp-open', src => $src }) if $self->{debug};
        return;
    }

    if (my $conn = $self->{conns}{ fileno($fh) }) {
        my $chunk;
        my $n = sysread($fh, $chunk, 65535);
        unless (defined $n && $n > 0) {
            $self->drop_conn($conn);
            return;
        }
        $conn->{buf} .= $chunk;
        my ($frames, $rest) = Cantus::Wire::frame_decode($conn->{buf});
        $conn->{buf} = $rest;
        for my $body (@$frames) {
            $self->emit({ kind => 'rx', src => $conn->{addr}, len => length $body,
                          dgram => (Cantus::Wire::kind($body) // -1), transport => 'tcp' })
                if $self->{debug};
            eval { $self->handle_datagram($body, $conn->{addr}, $conn) };
            $self->emit({ kind => 'error', error => $@ }) if $@;
        }
        return;
    }

    my $buf;
    my $peer = recv($self->{sock}, $buf, 65535, 0);
    return unless defined $peer && length $buf;
    my ($port, $iaddr) = sockaddr_in($peer);
    my $src = inet_ntoa($iaddr) . ':' . $port;
    $self->emit({ kind => 'rx', src => $src, len => length $buf,
                  dgram => (Cantus::Wire::kind($buf) // -1) }) if $self->{debug};
    eval { $self->handle_datagram($buf, $src) };
    $self->emit({ kind => 'error', error => $@ }) if $@;
}

sub sendto {
    my ($self, $dest, $bytes) = @_;
    return unless $self->{sock};
    my ($ip, $port) = split /:/, $dest, 2;
    return unless defined $port;
    $self->{sock}->send($bytes, 0, scalar sockaddr_in($port, inet_aton($ip)));
}

# A registration that came over TCP is a live connection, not an address: write
# the frame down it.  A half-written frame is unrecoverable, so the connection
# is dropped rather than left with the tail of a datagram in its stream.
sub _tcp_send {
    my ($self, $conn, $bytes) = @_;
    my $fh = $conn->{fh} or return 0;
    my $data = Cantus::Wire::frame_encode($bytes);
    my $n = syswrite($fh, $data);
    unless (defined $n && $n == length $data) {
        $self->drop_conn($conn);
        return 0;
    }
    return 1;
}

sub drop_conn {
    my ($self, $conn) = @_;
    return unless $conn && $conn->{fh};
    my $key = fileno($conn->{fh});
    delete $self->{conns}{$key};
    close $conn->{fh};
    $conn->{fh} = undef;
    $self->{tcp_clients}-- if $self->{tcp_clients} > 0;
    # A handle that pointed at this connection is no longer deliverable.
    for my $handle (keys %{ $self->{by_handle} }) {
        my $entry = $self->{by_handle}{$handle};
        next unless $entry->{tcp} && !$entry->{tcp}{fh};
        delete $self->{by_handle}{$handle};
        delete $self->{by_id}{ $entry->{id} } if defined $entry->{id};
    }
    $self->emit({ kind => 'tcp-close', src => $conn->{addr} }) if $self->{debug};
}

sub deliver {
    my ($self, $entry, $bytes) = @_;
    return $self->_tcp_send($entry->{tcp}, $bytes) if $entry->{tcp};
    return $self->sendto($entry->{addr}, $bytes);
}

# A registration is only true while the node keeps refreshing it (§8.2).  A
# long-lived relay has to forget the ones that stopped, or a name that moved to
# another host keeps sending to an address nobody is listening on.
sub sweep {
    my ($self) = @_;
    my $now = time;
    my $expired = 0;
    for my $handle (keys %{ $self->{by_handle} }) {
        my $entry = $self->{by_handle}{$handle};
        next unless defined $entry->{expires} && $entry->{expires} < $now;
        delete $self->{by_handle}{$handle};
        if (defined $entry->{id} && ($self->{by_id}{ $entry->{id} } // '') eq $handle) {
            delete $self->{by_id}{ $entry->{id} };
        }
        $expired++;
    }
    $self->emit({ kind => 'expired', count => $expired }) if $expired;
    return $expired;
}

sub handle_datagram {
    my ($self, $buf, $src, $conn) = @_;
    my $kind = Cantus::Wire::kind($buf);
    return unless defined $kind;

    if ($kind == 2) {
        my $r = Cantus::Wire::relay_decode($buf);
        my $entry;
        if ($r->{route} == 0) {
            my $handle = $self->{by_id}{ $r->{name} // '' };
            $entry = $handle ? $self->{by_handle}{$handle} : undef;
        }
        else {
            $entry = $self->{by_handle}{ $r->{route} };
        }
        unless ($entry) { $self->{dropped}++; return }
        $self->{forwarded}++ if $self->deliver($entry, $r->{inner});
        # Address refresh is registration-driven (section 8.2); a forwarder must
        # not repoint a handle based on who happened to send it a frame.
        $self->emit({ kind => 'forward', route => $r->{route}, name => $r->{name},
                      dest => ($entry->{tcp} ? 'tcp' : $entry->{addr}),
                      transport => ($entry->{tcp} ? 'tcp' : 'udp'),
                      len => length $r->{inner} })
            if Cantus::Wire::kind($r->{inner}) == 0;
        return;
    }

    if ($kind == 0) {
        my ($type, $f) = Cantus::Wire::msg_decode($buf);
        return unless $type == 13;      # REGISTER
        my $id = $f->{11} ? $f->{11}[1] : $f->{1}[1];
        return unless defined $id;
        my $handle = $self->{by_id}{$id};
        unless ($handle) {
            $handle = $self->{next_handle}++;
            $self->{by_id}{$id} = $handle;
        }
        $self->{by_handle}{$handle} = {
            addr    => $src,
            # Which binding it arrived on is the difference between an address
            # that can be sent to and a connection that must be written to.
            tcp     => $conn,
            id      => $id,
            expires => time + $self->{ttl},
            limits  => $f->{10} ? $f->{10}[1] : '',
        };
        my ($ip, $port) = split /:/, $src, 2;
        my $observed = Cantus::Wire::varint_encode(4)
                     . Cantus::Wire::varint_encode(length $ip) . $ip
                     . Cantus::Wire::varint_encode($port);
        my $grant = Cantus::Wire::varint_encode($handle)
                  . Cantus::Wire::varint_encode(300_000)
                  . Cantus::Wire::varint_encode(4096)
                  . Cantus::Wire::varint_encode(length $self->{addr}) . $self->{addr};
        my $reply = {
            19 => Cantus::Wire::B($observed),
            15 => Cantus::Wire::V($handle),
            20 => Cantus::Wire::B($grant),
            11 => Cantus::Wire::S('relay@' . $self->{addr}),
            4  => Cantus::Wire::V(int(time * 1000) & 0x7fffffff),
        };
        $reply->{5} = Cantus::Wire::B($self->{ident}->sign(14, $reply));
        my $ack = Cantus::Wire::msg_encode(14, $reply);
        if ($conn) { $self->_tcp_send($conn, $ack) } else { $self->sendto($src, $ack) }
        $self->emit({ kind => 'registered', id => $id, handle => $handle, addr => $src,
                      transport => ($conn ? 'tcp' : 'udp') });
        return;
    }
}

1;
