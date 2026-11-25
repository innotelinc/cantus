use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use IO::Select;
use Time::HiRes qw(time sleep);
use File::Temp qw(tempdir);
use JSON::PP ();

use Cantus::Daemon ();
use Cantus::Node ();
use Cantus::Relay ();

# The reference stack has to survive being a service, not just a demo.  These
# checks run `cantus relay` and `cantus node` as separate processes against each
# other: they must come up, announce themselves, register, answer a stop signal
# and exit cleanly — and a registration nobody refreshes must expire.
my $dir  = tempdir(CLEANUP => 1);
my $perl = $^X;
my $bin  = "$FindBin::Bin/../bin/cantus";
my $lib  = "$FindBin::Bin/../lib";

sub write_json {
    my ($path, $doc) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print {$fh} JSON::PP->new->canonical->encode($doc), "\n";
    close $fh;
    return $path;
}

sub spawn {
    my (@args) = @_;
    my $pid = open(my $fh, '-|');
    die "fork: $!" unless defined $pid;
    unless ($pid) {
        open STDERR, '>&', \*STDOUT or die "dup stderr: $!";
        exec($perl, "-I$lib", $bin, @args) or die "exec $bin: $!";
    }
    return ($pid, $fh);
}

# One line at a time, bounded: a service that never prints must not hang the
# suite.  This reads with sysread and keeps its own buffer — mixing select()
# with buffered readline() hides lines that readline already pulled out of the
# kernel into Perl's buffer, which looks exactly like a service that went quiet.
my %BUFFER;

sub read_line {
    my ($fh, $re, $timeout) = @_;
    my $key = fileno $fh;
    my $sel = IO::Select->new($fh);
    my $deadline = time + $timeout;
    while (1) {
        my $buf = $BUFFER{$key} // '';
        if ((my $at = index($buf, "\n")) >= 0) {
            my $line = substr($buf, 0, $at);
            $BUFFER{$key} = substr($buf, $at + 1);
            return $line if $line =~ $re;
            next;
        }
        last if time >= $deadline;
        my $left = $deadline - time;
        next unless $sel->can_read($left > 0.2 ? 0.2 : $left);
        my $n = sysread($fh, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $BUFFER{$key} .= $chunk;
    }
    return undef;
}

sub decode_line {
    my ($line) = @_;
    return undef unless defined $line;
    my $rec = eval { JSON::PP->new->decode($line) };
    return $rec;
}

# ------------------------------------------------------------------ the pair

my $relay_cfg = write_json("$dir/relay.json", { bind => '127.0.0.1:0', stats => 0.3 });
my ($relay_pid, $relay_fh) = spawn('relay', '--config', $relay_cfg);
die "relay did not start" unless defined $relay_pid;

my $relay_ready = decode_line(read_line($relay_fh, '"kind":"ready"', 10));
ok($relay_ready, 'the relay announces itself when it is up');
is($relay_ready->{role}, 'relay', 'the relay says what it is');
like($relay_ready->{addr}, qr/^127\.0\.0\.1:\d+$/, "the relay bound a real port ($relay_ready->{addr})");

my $node_cfg = write_json("$dir/node.json", {
    id    => 'node@daemon.test',
    bind  => '127.0.0.1:0',
    relay => $relay_ready->{addr},
    stats => 0.3,
});
my ($node_pid, $node_fh) = spawn('node', '--config', $node_cfg);
die "node did not start" unless defined $node_pid;

my $node_ready = decode_line(read_line($node_fh, '"kind":"ready"', 10));
ok($node_ready, 'the node announces itself when it is up');
is($node_ready->{id}, 'node@daemon.test', 'the node reports its address of record');
is($node_ready->{relay}, $relay_ready->{addr}, 'the node reports the relay it will use');

my $seen = decode_line(read_line($relay_fh, '"kind":"registered"', 10));
ok($seen, 'the relay received the node registration')
    or diag 'relay said nothing about a registration within 10 s';
is($seen->{id}, 'node@daemon.test', 'the registration names the node') if $seen;
ok(defined $seen->{handle}, 'the relay granted a handle') if $seen;

my $granted = decode_line(read_line($node_fh, '"kind":"registered"', 10));
ok($granted, 'the node was told its handle and observed address')
    or diag 'node never saw a REGISTERED reply';
is($granted->{observed}, $node_ready->{addr}, 'the observed address is the node itself, no NAT here')
    if $granted;

my $relay_stats = decode_line(read_line($relay_fh, '"kind":"stats"', 5));
ok($relay_stats, 'the relay reports stats on its interval');
cmp_ok($relay_stats->{endpoints} // 0, '>=', 1, 'the relay counts the endpoint it is holding')
    if $relay_stats;

my $node_stats = decode_line(read_line($node_fh, '"kind":"stats"', 5));
ok($node_stats, 'the node reports stats on its interval');

# --------------------------------------------------------------- clean stop

if ($^O eq 'MSWin32') {
    note 'native Windows kill() cannot deliver SIGTERM; shutdown is exercised on POSIX only';
    kill 'KILL', $node_pid, $relay_pid;
    close $node_fh;
    close $relay_fh;
}
else {
    # Wait before closing: closing the pipe first can hand the child SIGPIPE
    # while it is still printing its last event, which looks like a bad exit.
    kill 'TERM', $node_pid;
    waitpid($node_pid, 0);
    my $node_status = $?;
    close $node_fh;
    is($node_status, 0, 'the node exits 0 on SIGTERM');

    kill 'TERM', $relay_pid;
    waitpid($relay_pid, 0);
    my $relay_status = $?;
    close $relay_fh;
    is($relay_status, 0, 'the relay exits 0 on SIGTERM');
}

# ------------------------------------------------------- registration expiry

# A relay is a registry, and a registry that never forgets is a routing table
# full of addresses nobody answers.  In process, with a short ttl so the check
# costs a fraction of a second instead of a minute.
my $ttl_relay = Cantus::Relay->new(bind => '127.0.0.1:0', ttl => 0.6);
my $ttl_node  = Cantus::Node->new(
    id    => 'node@expiry.test',
    bind  => '127.0.0.1:0',
    relay => $ttl_relay->addr,
);
$ttl_node->register;
$ttl_relay->pump(0.2);
is(scalar keys %{ $ttl_relay->registry }, 1, 'a fresh registration is held');
is($ttl_relay->sweep, 0, 'a fresh registration is not swept');

sleep(0.5);
is($ttl_relay->sweep, 1, 'a registration past its ttl is swept');
is(scalar keys %{ $ttl_relay->registry }, 0, 'and it is gone from the registry');

# ------------------------------------------------------------------- bad input

eval { Cantus::Daemon::load_config("$dir/missing.json") };
like($@, qr/cannot read/, 'a missing config is a clear error, not a crash');

my $no_id = write_json("$dir/no-id.json", { bind => '127.0.0.1:0' });
eval { Cantus::Daemon->new(role => 'node', config => Cantus::Daemon::load_config($no_id)) };
like($@, qr/needs an "id"/, 'a node config without an address of record is refused');

done_testing();
