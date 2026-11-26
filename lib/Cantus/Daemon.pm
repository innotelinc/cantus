package Cantus::Daemon;
# Long-lived modes: a node and a relay that stay up.
#
# Everything the protocol needs was already here — Cantus::Node and
# Cantus::Relay each own a socket, a pump and a state machine — but the only
# way to run them was `cantus demo`, which builds a scenario, places one call
# and exits. A deployment needs the opposite: bind once, stay reachable, and
# keep answering for as long as the process lives.
#
# This module is that supervisor and nothing more. It reads a JSON config,
# builds the one component the role names, serves it in a loop that sleeps once
# per iteration (see Cantus::Pump §15 for why the waiting belongs here and not
# inside each pump), refreshes relay registration and re-registers on a timer,
# and reports every event as one JSON line so a log collector can read it.
#
# Secrets never belong in the config file: CANTUS_SECRET overrides whatever the
# file says, so a node config can be committed and the key handed to the process
# by the environment (Cerulean Vault in the estatedeployment).
use strict;
use warnings;
use Time::HiRes qw(time sleep);
use JSON::PP ();

use Cantus::Node ();
use Cantus::Relay ();
use Cantus::Router ();

use constant {
    REFRESH       => 20,     # re-register with the relay this often (§8.2)
    SWEEP         => 15,     # drop expired relay registrations
    DEFAULT_TICK  => 0.005,  # sleep between pump(0) iterations
    DEFAULT_BIND  => '0.0.0.0:7443',   # the one port the standard names
};

sub load_config {
    my ($path) = @_;
    die "cantus: --config <file> is required\n" unless defined $path && length $path;
    open my $fh, '<', $path or die "cantus: cannot read $path: $!\n";
    my $raw = do { local $/; <$fh> };
    close $fh;
    my $cfg = eval { JSON::PP->new->decode($raw // '') };
    die "cantus: $path is not valid JSON: $@" unless $cfg && ref $cfg eq 'HASH';
    if (defined $ENV{CANTUS_SECRET} && length $ENV{CANTUS_SECRET}) {
        $cfg->{secret} = $ENV{CANTUS_SECRET};
    }
    return $cfg;
}

sub new {
    my ($class, %a) = @_;
    my $role = $a{role} // 'node';
    die "cantus: unknown role '$role' (node or relay)\n"
        unless $role eq 'node' || $role eq 'relay';
    my $cfg = $a{config} // {};

    my $self = bless {
        role        => $role,
        cfg         => $cfg,
        quiet       => $a{quiet} ? 1 : 0,
        stats_every => $a{stats} // $cfg->{stats} // 0,
        tick        => $cfg->{tick} // DEFAULT_TICK,
        running     => 1,
        started     => time,
    }, $class;

    my $on_event = sub { $self->emit($_[0]) };
    my $bind = $cfg->{bind} // DEFAULT_BIND;
    my $secret = $cfg->{secret} // 'cantus-loopback';

    if ($role eq 'relay') {
        $self->{service} = Cantus::Relay->new(
            bind     => $bind,
            secret   => $secret,
            on_event => $on_event,
            ttl      => $cfg->{registration_ttl} // 60,
            # The same port, twice: UDP is the baseline and TCP is the fallback
            # an endpoint reaches for when its NAT drops UDP (§4.2, §8.8).
            udp      => $cfg->{udp} // 1,
            tcp      => $cfg->{tcp} // 1,
            tcp_bind => $cfg->{tcp_bind},
            debug    => $cfg->{debug} // 0,
        );
    } else {
        my $id = $cfg->{id};
        die "cantus: node config needs an \"id\" (the address of record)\n" unless defined $id && length $id;
        my $router;
        if (my $routes = $cfg->{routes}) {
            open my $rfh, '<', $routes or die "cantus: cannot read routes $routes: $!\n";
            my $doc = do { local $/; <$rfh> };
            close $rfh;
            $router = eval { Cantus::Router->new(name => $routes, doc => $doc) };
            die "cantus: routes $routes rejected: $@" if $@;
        }
        $self->{service} = Cantus::Node->new(
            id          => $id,
            bind        => $bind,
            secret      => $secret,
            relay       => $cfg->{relay},
            router      => $router,
            limits      => $cfg->{limits} // {},
            auto_answer => defined $cfg->{auto_answer} ? $cfg->{auto_answer} : 1,
            ring_delay  => $cfg->{ring_delay} // 0,
            tone_hz     => $cfg->{tone_hz} // 440,
            debug       => $cfg->{debug} // 0,
            relay_transport => $cfg->{relay_transport} // 'auto',
            on_event    => $on_event,
        );
    }

    return $self;
}

sub service { $_[0]{service} }
sub role    { $_[0]{role} }
sub stop    { $_[0]{running} = 0 }

# One JSON line per event, flushed immediately: a service that buffers its log
# is a service whose last second is lost when it is killed.
sub emit {
    my ($self, $ev) = @_;
    return if $self->{quiet};
    return unless ref $ev eq 'HASH';
    my %rec = (%$ev, role => $self->{role}, t => sprintf('%.3f', time - $self->{started}));
    local $| = 1;
    print JSON::PP->new->canonical->encode(\%rec), "\n";
    return;
}

# Run until SIGINT/SIGTERM. Returns 0 on a clean shutdown, so a supervisor
# reads a stopped process as success and not as a crash.
sub run {
    my ($self) = @_;
    my $svc = $self->{service};
    my $role = $self->{role};

    $SIG{INT} = $SIG{TERM} = sub { $self->{running} = 0 };

    my %ready = (kind => 'ready', addr => $svc->addr, bind => $self->{cfg}{bind} // DEFAULT_BIND);
    $ready{tcp} = $svc->tcp_port if $role eq 'relay' && $svc->can('tcp_port') && $svc->tcp_port;
    $ready{id} = $svc->id if $role eq 'node';
    $ready{relay} = $self->{cfg}{relay} if $role eq 'node' && $self->{cfg}{relay};
    $ready{routes} = $self->{cfg}{routes} if $role eq 'node' && $self->{cfg}{routes};
    $self->emit(\%ready);

    my $next_register = 0;
    my $next_sweep = time + SWEEP;
    my $next_stats = $self->{stats_every} ? time + $self->{stats_every} : 0;

    while ($self->{running}) {
        eval { $svc->pump(0) };
        $self->emit({ kind => 'error', error => $@ }) if $@;

        if ($role eq 'node' && $self->{cfg}{relay} && time >= $next_register) {
            $svc->register;
            $next_register = time + REFRESH;
        }
        if ($role eq 'relay' && time >= $next_sweep) {
            $svc->sweep;
            $next_sweep = time + SWEEP;
        }
        if ($next_stats && time >= $next_stats) {
            $self->emit({ kind => 'stats', %{ $svc->stats } });
            $next_stats = time + $self->{stats_every};
        }

        sleep($self->{tick});
    }

    $self->emit({
        kind     => 'stopped',
        uptime   => int(time - $self->{started}),
        received => ($role eq 'node' ? $svc->{received_frames} : $svc->{forwarded}),
    });
    return 0;
}

1;
