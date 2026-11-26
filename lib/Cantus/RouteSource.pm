package Cantus::RouteSource;
# Where a routing document comes from, and how it is kept current.
#
# The trunk's rules used to be a JSON file next to the gateway, which meant a
# second copy of the switch's own routing: move a DID in the console and the
# gateway kept sending the call to the old line. The document now comes from the
# control plane over HTTP, and this module is the part that has to stay honest
# about it:
#
#   * the first read is what the gateway starts with, and a restart while the
#     control plane is down starts from the last copy that worked (the cache);
#   * a poll that fails, times out or returns something that is not a valid
#     document changes nothing -- the last good rules keep carrying calls, and
#     the failure is reported instead of quietly rejecting every call;
#   * a document that has not changed is not reloaded, so the digest is also the
#     "did the rules change" signal an operator can watch in the log.
#
# HTTP is deliberately hand-written: this stack has no non-core dependencies, and
# one GET with a token header is not a reason to add one.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Digest::MD5 qw(md5_hex);
use JSON::PP ();
use Time::HiRes qw(time);
use File::Path qw(make_path);
use Cantus::Router;

sub new {
    my ($class, %a) = @_;
    my $self = bless {
        file       => $a{file},
        url        => $a{url},
        token      => $a{token},
        refresh    => $a{refresh} // 30,
        cache      => $a{cache},
        timeout    => $a{timeout} // 3,
        text       => undef,
        digest     => undef,
        loaded_at  => 0,
        next_fetch => 0,
        last_error => '',
        router     => undef,
    }, $class;
    $self->{desc} = $self->{url} ? $self->{url} : ($self->{file} // 'none');
    $self->_preload;
    return $self;
}

sub describe   { $_[0]{desc} }
sub digest     { $_[0]{digest} }
sub last_error { $_[0]{last_error} }
sub loaded_at  { $_[0]{loaded_at} }
sub text       { $_[0]{text} }

sub route_count {
    my ($self) = @_;
    my $r = $self->{router} or return 0;
    return $r->route_count;
}

# A restart during an outage of the control plane must not come up with no rules
# at all: that is a gateway that refuses every call for a reason nobody can see.
sub _preload {
    my ($self) = @_;
    my $text;
    if (defined $self->{file}) {
        $text = $self->_read_file;
        $self->{last_error} = "cannot read $self->{file}: $!" unless defined $text;
    }
    $text = $self->_read_cache if !defined $text && $self->{cache};
    return unless defined $text;
    $self->_accept($text);
}

sub _read_file {
    my ($self) = @_;
    open my $fh, '<', $self->{file} or return undef;
    local $/;
    my $text = <$fh>;
    close $fh;
    return $text;
}

sub _read_cache {
    my ($self) = @_;
    open my $fh, '<', $self->{cache} or return undef;
    local $/;
    my $text = <$fh>;
    close $fh;
    return $text;
}

sub _write_cache {
    my ($self, $text) = @_;
    return unless $self->{cache};
    my $dir = $self->{cache};
    $dir =~ s{/[^/]+$}{};
    eval { make_path($dir) if length $dir && !-d $dir };
    open my $fh, '>', $self->{cache} or return 0;
    print $fh $text;
    close $fh;
    return 1;
}

# One GET. A 200 with a body is the only success; anything else is reported and
# leaves the current rules alone.
sub _http_get {
    my ($self) = @_;
    my ($host, $port, $path) = $self->{url} =~ m{^http://([^/:]+)(?::(\d+))?(/.*)?$}
        or do { $self->{last_error} = 'not an http:// URL'; return undef };
    $port //= 80;
    $path //= '/';

    my $sock = IO::Socket::INET->new(
        PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => $self->{timeout},
    ) or do { $self->{last_error} = "connect $host:$port: $!"; return undef };

    my $req = "GET $path HTTP/1.1\r\n"
            . "Host: $host:$port\r\n"
            . "Accept: application/json\r\n"
            . "Connection: close\r\n"
            . "User-Agent: cantus-gateway\r\n";
    # The control plane accepts either name: the gateway names itself as
    # the caller it is, and a key-issued token still works as usual.
    if (defined $self->{token} && length $self->{token}) {
        $req .= "X-Routing-Token: $self->{token}\r\n";
        $req .= "X-Api-Key: $self->{token}\r\n";
    }
    $req .= "\r\n";
    unless (print $sock $req) {
        $self->{last_error} = "send: $!";
        close $sock;
        return undef;
    }

    # A control plane that accepts the connection and then says nothing is the
    # case a plain `<$sock>` cannot survive: the gateway's whole pump loop would
    # stop until TCP gave up, taking every call on the box with it. The deadline
    # is per read, so a slow but working document still gets through.
    my $raw = '';
    my $sel = IO::Select->new($sock);
    while (1) {
        unless ($sel->can_read($self->{timeout})) {
            $self->{last_error} = 'timed out reading the document';
            close $sock;
            return undef;
        }
        my $buf;
        my $n = sysread($sock, $buf, 65536);
        last unless defined $n && $n;
        $raw .= $buf;
    }
    close $sock;

    my ($head, $body) = split /\r\n\r\n/, $raw, 2;
    unless (defined $head) { $self->{last_error} = 'no HTTP response'; return undef }
    my ($status) = $head =~ m{^HTTP/\d\.\d\s+(\d{3})};
    my $code = $status // 0;
    if ($code != 200) {
        $self->{last_error} = "HTTP $code";
        return undef;
    }
    $body //= '';
    if ($head =~ /transfer-encoding:\s*chunked/i) {
        my $out = '';
        while ($body =~ s/^([0-9a-fA-F]+)\r\n//) {
            my $len = hex $1;
            last if $len == 0;
            $out .= substr($body, 0, $len, '');
            $body =~ s/^\r\n//;
        }
        $body = $out;
    }
    return $body;
}

# A stable digest of what the document says, without the parts that change on
# every read: the same rules read twice are the same rules.
sub _rules_digest {
    my ($text) = @_;
    return md5_hex('') if !defined $text || !length $text;
    my $doc = eval { JSON::PP->new->decode($text) };
    if (!$doc || ref $doc ne 'HASH') {
        return md5_hex($text);
    }
    my %rules = map { exists $doc->{$_} ? ($_ => $doc->{$_}) : () } qw(version default routes);
    return md5_hex(JSON::PP->new->canonical->encode(\%rules));
}

# Take a document only if it is one. A control plane that returns an error page
# and a `200` must not turn into a set of rules that reject every call.
sub _accept {
    my ($self, $text) = @_;
    # The digest is over the rules, not over the reading. A document that says
    # "generated at 10:00:01" is not a different set of rules from the same
    # document at 10:00:31, and a digest over the timestamp makes every poll
    # look like a change: the rules were being reloaded every 30 seconds while
    # nothing in them had moved.
    my $digest = _rules_digest($text);
    return 0 if defined $self->{digest} && $digest eq $self->{digest};

    my $router = eval { Cantus::Router->new(doc => $text, name => $self->{desc}) };
    if (!$router) {
        my $err = $@ || 'invalid document';
        $err =~ s/\s+$//;
        $self->{last_error} = $err;
        return 0;
    }
    $self->{router}     = $router;
    $self->{text}       = $text;
    $self->{digest}     = $digest;
    $self->{loaded_at}  = time;
    $self->{last_error} = '';
    $self->_write_cache($text);
    return 1;
}

# Fetch if the interval has passed. Returns true when the rules changed.
sub refresh {
    my ($self, $now) = @_;
    $now //= time;
    return 0 if $now < ($self->{next_fetch} // 0);
    $self->{next_fetch} = $now + $self->{refresh};

    my $text = $self->{url} ? $self->_http_get : $self->_read_file;
    unless (defined $text) {
        $self->{last_error} ||= 'no document' unless $self->{text};
        return 0;
    }
    return $self->_accept($text);
}

# The router the gateway evaluates. Refresh first, so a poll that changes the
# rules is visible on the very next decision.
sub router {
    my ($self, $now) = @_;
    $self->refresh($now);
    return $self->{router};
}

1;
