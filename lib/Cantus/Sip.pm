package Cantus::Sip;
# The SIP a gateway needs at the edge: enough to register, answer, and hang up.
#
# This is deliberately not a SIP stack. There is no transaction layer, no TCP,
# no TLS, no registration store beyond one account: a softphone on the LAN sends
# a request, the gateway answers it, and the call is carried by Cantus from
# there. Every message is parsed into one hash and every reply is built from the
# request's own headers, which is what makes it small enough to audit.
use strict;
use warnings;
use Digest::MD5 qw(md5_hex);

# ---------------------------------------------------------------- parsing

sub parse {
    my ($buf) = @_;
    return undef unless defined $buf && length $buf;
    my ($head, $body) = split /\r?\n\r?\n/, $buf, 2;
    return undef unless defined $head;
    my @lines = split /\r?\n/, $head;

    # A header may be folded across lines; unfold before reading any of them.
    my @flat;
    for my $line (@lines) {
        if ($line =~ /^[ \t]/ && @flat) {
            (my $cont = $line) =~ s/^[ \t]+//;
            $flat[-1] .= ' ' . $cont;
        }
        else { push @flat, $line }
    }
    my $start = shift @flat // return undef;

    my (%h, %all);
    for my $line (@flat) {
        next unless $line =~ /^([^:]+):\s*(.*)$/;
        my ($name, $value) = (lc $1, $2);
        $name =~ s/\s+$//;
        # Only the first of a repeated header is what the edge reads; Contact and
        # Via repeats are not used by the edge this serves. Every value is kept
        # as well, because a Record-Route chain is a list and one hop of it is a
        # dialog this end can never leave the way it arrived.
        $h{$name} = $value unless exists $h{$name};
        push @{ $all{$name} }, $value;
    }

    my $msg = { headers => \%h, all => \%all, body => ($body // ''), raw => $buf, start => $start };
    if ($start =~ m{^([A-Z]+)\s+(\S+)\s+SIP/(\d\.\d)$}) {
        @$msg{qw(method uri version)} = ($1, $2, $3);
        @$msg{qw(request)} = (1);
    }
    elsif ($start =~ m{^SIP/(\d\.\d)\s+(\d{3})\s*(.*)$}) {
        @$msg{qw(version status reason)} = ($1, $2, $3);
        @$msg{qw(request)} = (0);
    }
    else {
        return undef;
    }
    return $msg;
}

sub header { my ($msg, $name) = @_; return $msg->{headers}{ lc $name } }

# Every value of a header that may repeat, in the order it arrived. A dialog's
# route set is one of these, and taking only the first value is how a request
# ends up addressed to the proxy instead of through it.
sub headers_all {
    my ($msg, $name) = @_;
    return $msg->{all}{ lc $name } || [];
}

# "<sip:101@1.2.3.4:5060;transport=udp>" -> { uri, user, host, port }
sub parse_uri {
    my ($value) = @_;
    return undef unless defined $value;
    return undef unless $value =~ /<?sips?:([^@>;]+@)?([^>;:]+)(?::(\d+))?/;
    my ($user, $host, $port) = ($1, $2, $3);
    $user =~ s/\@\z// if defined $user;
    return { user => $user, host => $host, port => ($port || 5060), raw => $value };
}

# A tag from a From/To header.  The dialog lives on these two values.
sub tag {
    my ($msg, $name) = @_;
    my $h = header($msg, $name) // return undef;
    return $1 if $h =~ /;tag=([^;>\s]+)/;
    return undef;
}

# ---------------------------------------------------------------- building

my %REASON = (
    100 => 'Trying', 180 => 'Ringing', 200 => 'OK', 202 => 'Accepted',
    400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden',
    404 => 'Not Found', 405 => 'Method Not Allowed', 481 => 'Call/Transaction Does Not Exist',
    486 => 'Busy Here', 488 => 'Not Acceptable Here', 500 => 'Server Internal Error',
    503 => 'Service Unavailable', 504 => 'Server Time-out', 603 => 'Decline',
);

sub reason_for { my ($code) = @_; return $REASON{$code} // 'Unknown' }

# Reply to a request.  Via, From, Call-ID and CSeq are the caller's own; a
# reply that invents any of them is a reply the caller will discard.
sub response {
    my ($req, $code, %a) = @_;
    my $reason = $a{reason} // reason_for($code);
    my @out = ("SIP/2.0 $code $reason");
    my $via = header($req, 'via');
    push @out, "Via: $via" if defined $via;
    push @out, 'From: ' . header($req, 'from');
    my $to = header($req, 'to');
    if ($a{to_tag} && defined $to && $to !~ /;tag=/) {
        $to .= ';tag=' . $a{to_tag};
    }
    push @out, "To: $to";
    push @out, 'Call-ID: ' . header($req, 'call-id');
    push @out, 'CSeq: ' . header($req, 'cseq');
    push @out, "Contact: $a{contact}" if $a{contact};
    push @out, "Expires: $a{expires}" if defined $a{expires};
    for my $extra (@{ $a{headers} || [] }) { push @out, $extra }
    if (defined $a{sdp} && length $a{sdp}) {
        push @out, 'Content-Type: application/sdp';
        push @out, 'Content-Length: ' . length($a{sdp});
        return join("\r\n", @out) . "\r\n\r\n" . $a{sdp};
    }
    push @out, 'Content-Length: 0';
    return join("\r\n", @out) . "\r\n\r\n";
}

# A request the gateway originates: BYE, INVITE, REFER's NOTIFY.  The dialog's
# own identifiers are carried so the far end can match it to the call it thinks
# it has, and a body is included only when there is one -- an INVITE with a
# `Content-Length: 0` and a body is a message every stack rejects.
sub request {
    my (%a) = @_;
    my @out = ("$a{method} $a{uri} SIP/2.0");
    push @out, 'Via: SIP/2.0/UDP ' . $a{via};
    push @out, "From: $a{from}";
    push @out, "To: $a{to}";
    push @out, 'Call-ID: ' . $a{call_id};
    push @out, 'CSeq: ' . $a{cseq} . ' ' . $a{method};
    push @out, "Contact: $a{contact}" if $a{contact};
    push @out, 'Max-Forwards: 70';
    push @out, @{ $a{headers} || [] };
    my $body = $a{body} // '';
    if (length $body) {
        push @out, 'Content-Type: ' . ($a{content_type} // 'application/sdp');
        push @out, 'Content-Length: ' . length $body;
        return join("\r\n", @out) . "\r\n\r\n" . $body;
    }
    push @out, 'Content-Length: 0';
    return join("\r\n", @out) . "\r\n\r\n";
}

# ---------------------------------------------------------------- digest

sub nonce {
    return md5_hex(join(':', time, rand, $$, 'cantus-gateway'));
}

# Compute a Digest response.  Both sides of a SIP exchange need the same
# arithmetic, so it lives in one place: the gateway verifies with it, a client
# signs with it, and a test can check either against a hand-computed vector.
sub digest_response {
    my (%a) = @_;
    my $ha1 = md5_hex(join(':', $a{user} // '', $a{realm} // '', $a{password} // ''));
    my $ha2 = md5_hex(join(':', $a{method} // '', $a{uri} // ''));
    return md5_hex(join(':', $ha1, $a{nonce} // '', $ha2)) unless $a{qop};
    return md5_hex(join(':', $ha1, $a{nonce} // '', $a{nc} // '', $a{cnonce} // '', $a{qop}, $ha2));
}

sub digest_authorization {
    my (%a) = @_;
    my @parts = (
        qq{username="$a{user}"},
        qq{realm="$a{realm}"},
        qq{nonce="$a{nonce}"},
        qq{uri="$a{uri}"},
        qq{response="$a{response}"},
        'algorithm=MD5',
    );
    push @parts, qq{qop=$a{qop}}, qq{nc=$a{nc}}, qq{cnonce="$a{cnonce}"} if $a{qop};
    return 'Authorization: Digest ' . join(', ', @parts);
}

# Verify a Digest Authorization header against one account.
#
# MD5 only, because that is what softphones offer for SIP digest; the account is
# one shared secret on a LAN, not an identity system. Both the plain form and
# qop=auth are accepted, since which one arrives depends on the client.
sub verify_digest {
    my (%a) = @_;
    my ($msg, $method, $user, $password, $realm) = @a{qw(msg method user password realm)};
    my $auth = header($msg, 'authorization') // return (0, 'no credentials');
    $auth =~ s/^Digest\s+//i;
    my %p;
    while ($auth =~ /(\w+)\s*=\s*"([^"]*)"/g) { $p{ lc $1 } = $2 }
    while ($auth =~ /(\w+)\s*=\s*([^,"\s]+)/g) { $p{ lc $1 } //= $2 }
    return (0, 'no username') unless defined $p{username};
    return (0, 'wrong account') unless $p{username} eq $user;
    return (0, 'wrong realm') if defined $p{realm} && $p{realm} ne $realm;
    return (0, 'no response') unless defined $p{response};

    my $ha1 = md5_hex("$user:$realm:$password");
    my $uri = $p{uri} // $msg->{uri};
    my $want = digest_response(
        user => $user, password => $password, realm => $realm,
        method => $method, uri => $uri, nonce => $p{nonce}, response => undef,
        qop => $p{qop}, nc => $p{nc}, cnonce => $p{cnonce},
    );
    return (1, 'ok') if lc($want) eq lc($p{response});
    return (0, 'bad digest');
}

sub challenge_header {
    my ($realm, $nonce) = @_;
    return qq{WWW-Authenticate: Digest realm="$realm", nonce="$nonce", algorithm=MD5};
}

# ---------------------------------------------------------------- SDP

# Read the first audio stream out of an offer: the codec it wants and where to
# send RTP.  Only PCMU and PCMA are understood, because those are the only
# codecs a Cantus edge needs to translate; an offer without either is refused.
sub sdp_parse {
    my ($body) = @_;
    return undef unless defined $body && length $body;
    my %s = (media => [], connection => undef, ptime => 20);
    for my $line (split /\r?\n/, $body) {
        $s{connection} = $1 if $line =~ /^c=IN IP4 (\S+)/;
        $s{ptime} = $1 if $line =~ /^a=ptime:(\d+)/;
        if ($line =~ /^m=audio (\d+) RTP\/AVP (\S+)/) {
            my ($port, $pts) = ($1, $2);
            my %payloads = map { $_ => 1 } split /\s+/, $pts;
            push @{ $s{media} }, { port => $port, payloads => \%payloads };
        }
        if ($line =~ /^a=rtpmap:(\d+) (\S+)\/(\d+)/) {
            $s{rtpmap}{$1} = { name => uc $2, clock => $3 };
        }
        # RFC 4733: the payload type the phone will send key presses on.  It is
        # negotiated, not assumed: a phone that offered 101 and is answered
        # without it keeps its digits to itself.
        if ($line =~ /^a=rtpmap:(\d+) telephone-event\/8000/i) {
            $s{event_pt} = $1;
        }
        if ($line =~ /^a=(sendrecv|sendonly|recvonly|inactive)/) {
            $s{direction} = $1;
        }
    }
    my $m = $s{media}[0] or return undef;
    my $codec;
    if ($m->{payloads}{0}) { $codec = 'PCMU' }
    elsif ($m->{payloads}{8}) { $codec = 'PCMA' }
    else {
        # Some clients omit rtpmap for the static payload types; the payload
        # number is the definition, so 0 and 8 above are already enough.
        return undef;
    }
    return {
        codec => $codec, port => $m->{port}, ip => $s{connection},
        ptime => $s{ptime}, direction => $s{direction} // 'sendrecv',
        event_pt => $s{event_pt},
    };
}

# An answer (or an offer, which is the same shape here).  `direction` is how a
# hold is expressed: the party that holds sends `sendonly` and is answered
# `recvonly`, so neither side mistakes a held line for a dead one.
sub sdp_answer {
    my (%a) = @_;
    my $codec = $a{codec} // 'PCMU';
    my $pt    = $codec eq 'PCMA' ? 8 : 0;
    my $name  = $codec;
    my $ip    = $a{ip};
    my $port  = $a{port};
    my $dir   = $a{direction} // 'sendrecv';
    my @payloads = $pt;
    my @rtpmap = "a=rtpmap:$pt $name/8000";
    if (defined $a{event_pt}) {
        push @payloads, $a{event_pt};
        push @rtpmap, "a=rtpmap:$a{event_pt} telephone-event/8000";
    }
    return join("\r\n",
        'v=0',
        "o=cantus-gateway 0 0 IN IP4 $ip",
        's=cantus gateway',
        "c=IN IP4 $ip",
        't=0 0',
        'm=audio ' . $port . ' RTP/AVP ' . join(' ', @payloads),
        @rtpmap,
        'a=ptime:20',
        "a=$dir",
    ) . "\r\n";
}

# The target of a REFER: who the call is being handed to.
sub refer_to {
    my ($msg) = @_;
    my $h = header($msg, 'refer-to') // return undef;
    return parse_uri($h);
}

# ---------------------------------------------------------------- DTMF

my @EVENT_DIGITS = ('0' .. '9', '*', '#', 'A', 'B', 'C', 'D');

sub dtmf_event_id {
    my ($digit) = @_;
    return undef unless defined $digit;
    for my $i (0 .. $#EVENT_DIGITS) { return $i if $EVENT_DIGITS[$i] eq $digit }
    return undef;
}

sub dtmf_digit {
    my ($id) = @_;
    return undef unless defined $id && $id >= 0 && $id <= $#EVENT_DIGITS;
    return $EVENT_DIGITS[$id];
}

# RFC 4733 payload: event id, end bit and volume, duration in samples.
sub rtp_event_parse {
    my ($payload) = @_;
    return undef unless defined $payload && length $payload >= 4;
    my ($event, $flags, $duration) = unpack('CCn', substr($payload, 0, 4));
    return { event => $event, end => ($flags & 0x80) ? 1 : 0,
             volume => $flags & 0x3F, duration => $duration };
}

sub rtp_event_build {
    my (%a) = @_;
    return pack('CCn', $a{event} & 0xFF,
        ($a{end} ? 0x80 : 0) | (($a{volume} // 10) & 0x3F),
        $a{duration} // 160);
}

# ---------------------------------------------------------------- RTP

sub rtp_parse {
    my ($buf) = @_;
    return undef unless defined $buf && length $buf >= 12;
    # RTP: version/flags, payload type, sequence (16), timestamp (32), SSRC (32).
    my ($b0, $b1, $seq, $ts, $ssrc) = unpack('CCnNN', $buf);
    my $version = $b0 >> 6;
    return undef unless $version == 2;
    my $cc     = $b0 & 0x0F;
    my $padding = ($b0 & 0x20) ? 1 : 0;
    my $ext    = ($b0 & 0x10) ? 1 : 0;
    my $marker = ($b1 & 0x80) ? 1 : 0;
    my $pt     = $b1 & 0x7F;
    my $off    = 12 + 4 * $cc;
    return undef if $off > length $buf;
    if ($ext) {
        return undef if $off + 4 > length $buf;
        my $words = unpack('n', substr($buf, $off + 2, 2));
        $off += 4 + 4 * $words;
        return undef if $off > length $buf;
    }
    my $payload = substr($buf, $off);
    if ($padding && length $payload) {
        my $pad = ord(substr($payload, -1));
        $payload = substr($payload, 0, length($payload) - $pad) if $pad <= length $payload;
    }
    return { pt => $pt, seq => $seq, ts => $ts, ssrc => $ssrc,
             marker => $marker, payload => $payload };
}

sub rtp_build {
    my (%a) = @_;
    my $pt = $a{pt} // 0;
    my $b1 = ($a{marker} ? 0x80 : 0) | ($pt & 0x7F);
    return pack('CCnNN', 0x80, $b1, $a{seq} & 0xFFFF, $a{ts} & 0xFFFFFFFF, $a{ssrc} // 0)
        . ($a{payload} // '');
}

1;
