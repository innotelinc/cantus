#!/usr/bin/perl
# The gateway's routing document, read from the control plane.
#
# The point of reading Telno's document instead of shipping a copy is that an
# edit there changes what the gateway does on the next call. This test serves a
# document over HTTP, makes decisions through it, edits the document the way
# Telno would, and asks the same questions again.
use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use JSON::PP ();
use POSIX qw(_exit);
# Core `sleep` truncates its argument to whole seconds, so a poll interval
# shorter than one would never come due and every assertion here would pass on
# the first document it ever read.
use Time::HiRes qw(sleep);

use lib 'lib';
use Cantus::RouteSource;

my $TOKEN = 'test-routing-token';
my $doc_path = "/tmp/cantus-routes-$$.json";
my $cache    = "/tmp/cantus-routes-cache-$$.json";

# ---------------------------------------------------------------- fake Telno

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp', Listen => 8, ReuseAddr => 1,
) or die "listen: $!";
my $port = $server->sockport;

my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    $SIG{TERM} = sub { unlink $doc_path; _exit(0) };
    while (my $client = $server->accept) {
        my $req = '';
        while (my $line = <$client>) {
            $req .= $line;
            last if $line =~ /^\r?\n$/;
        }
        my ($key) = $req =~ /^X-Api-Key:\s*(\S+)/mi;
        my ($status, $body) = (401, '{"error":"unauthorized"}');
        if (defined $key && $key eq $TOKEN) {
            open my $fh, '<', $doc_path;
            if ($fh) {
                local $/;
                $body = <$fh>;
                close $fh;
                $status = 200;
            }
        }
        print $client "HTTP/1.1 $status X\r\n"
                    . "Content-Type: application/json\r\n"
                    . 'Content-Length: ' . length($body) . "\r\n"
                    . "Connection: close\r\n\r\n"
                    . $body;
        close $client;
    }
    _exit(0);
}

# The parent does not accept connections; holding the listener open here would
# make a dead server look alive for connect's purposes and test nothing.
close $server;

my $write_doc = sub {
    my ($doc) = @_;
    open my $fh, '>', $doc_path or die "write $doc_path: $!";
    print $fh ref $doc ? JSON::PP->new->canonical->encode($doc) : $doc;
    close $fh;
};

# ---------------------------------------------------- the document Telno serves

my $doc = {
    version => 1,
    generator => 'telno',
    default => { reject => 3 },
    routes => [
        { name => 'did-14132642700', when => { to => '14132642700' },
          then => [ { answer => {} }, { forward => { to => 'ext:101' } } ] },
        { name => 'outbound-4443', when => { to => '4443' },
          then => [ { forward => { to => 'pstn:4443' } } ] },
        { name => 'outbound-1*', when => { to => '1*' },
          then => [ { forward => { to => 'pstn:' } } ] },
    ],
};
$write_doc->($doc);

my $url = "http://127.0.0.1:$port/api/routing/document";
my $src = Cantus::RouteSource->new(url => $url, token => $TOKEN, refresh => 0.2, cache => $cache);

# ------------------------------------------------------------------- the reads

my $router = $src->router;
ok($router, 'the gateway reads the document from the control plane');
is($src->route_count, 3, 'and sees the three rules it was sent');
is($src->last_error, '', 'with nothing to report');
like($src->digest // '', qr/^[0-9a-f]{32}$/, 'the rules carry a digest, so a reload can be told from a poll');

# A reading is not an edit. The control plane stamps every document with the
# time it was made, and a digest over the whole body therefore changes on every
# poll: in production that reloaded the rules every 30 seconds without a single
# rule having moved.
{
    my $clock = Cantus::RouteSource->new(url => $url, token => $TOKEN);
    is($clock->_accept('{"version":1,"generated_at":"2026-01-01T00:00:00Z","default":{"reject":3},"routes":[]}'),
        1, 'a document loads');
    my $first = $clock->digest;
    is($clock->_accept('{"version":1,"generated_at":"2026-01-01T00:00:30Z","default":{"reject":3},"routes":[]}'),
        0, 'the same rules, read again, are not a reload');
    is($clock->digest, $first, 'and the digest did not move with the clock');
}

my $dec = $router->decide({ to => '4443', from => '101' });
ok($dec->{matched}, '4443 is allowed to leave, because the document says so');
is($dec->{route}, 'outbound-4443', 'and the rule that allowed it is named in the decision');

$dec = $router->decide({ to => '14132642700', from => '14150000000' });
is($dec->{route}, 'did-14132642700', 'a DID we own lands on its line, not on the carrier');

$dec = $router->decide({ to => '4132642700', from => 'x' });
ok(!$dec->{matched}, 'the ten-digit form has no rule yet, so it falls to the default');

# ------------------------------- a route edited in Telno, the same question again

# Telno rewrote the DID pattern (the rule is named after the number it
# matches) and moved the line behind it.
$doc->{routes}[0] = {
    name => 'did-4132642700',
    when => { to => '4132642700' },
    then => [ { answer => {} }, { forward => { to => 'ext:102' } } ],
};
$write_doc->($doc);
sleep 0.4;

$dec = $src->router->decide({ to => '4132642700', from => 'x' });
is($dec->{route}, 'did-4132642700', 'the edited pattern is the rule that answers now');
is($dec->{actions}[1]{forward}{to}, 'ext:102', 'and it goes to the line Telno now names');

$dec = $src->router->decide({ to => '14132642700', from => 'x' });
isnt($dec->{route} // '', 'did-14132642700', 'the DID rule Telno replaced no longer answers it');
is($dec->{route}, 'outbound-1*', 'so it is only matched by the outbound pattern, not by a line');

# ------------------------------------------------ outbound taken away in Telno

$doc->{routes} = [ grep { $_->{name} !~ /^outbound-/ } @{ $doc->{routes} } ];
$write_doc->($doc);
sleep 0.4;
$dec = $src->router->decide({ to => '4443', from => '101' });
ok(!$dec->{matched}, 'a number Telno no longer allows is refused without a restart');
is($dec->{actions}[0]{reject}, 3, 'with the document default, not a special case in the gateway');

# --------------------------- a document that is not a document changes nothing

$write_doc->('{"version":1,"routes":[{"name":"x","when":{"totally":"wrong"},"then":[{"nope":1}]}]}');
sleep 0.4;
my $after_bad = $src->router;
is($after_bad->route_count, 1, 'a malformed document is refused, and the last good rules stay in force');
like($src->last_error, qr/invalid|unknown/i, 'and it says why it was refused');
$dec = $after_bad->decide({ to => '4132642700', from => 'x' });
is($dec->{actions}[1]{forward}{to}, 'ext:102', 'decisions still work on the old rules');

# ------------------------------------------- an outage keeps the last good rules

kill 'KILL', $pid;
waitpid($pid, 0);
sleep 0.4;
my $outage = $src->router;
ok($outage, 'the control plane going away does not take the rules away');
is($outage->route_count, 1, 'the last document that worked is still the one in force');
like($src->last_error, qr/connect|refused|timed|HTTP/i, 'and the failure is reported rather than hidden');

# ------------------------------------------- a restart during the outage

my $restarted = Cantus::RouteSource->new(url => $url, token => $TOKEN, refresh => 0.2, cache => $cache);
ok($restarted->router, 'a gateway restarted during the outage starts from the cached document');
is($restarted->route_count, 1, 'with the rules that were last in force');

# ----------------------------------------- a file source is still a source

my $file = "${cache}.file";
open my $fh, '>', $file or die;
print $fh JSON::PP->new->canonical->encode($doc);
close $fh;
my $from_file = Cantus::RouteSource->new(file => $file);
is($from_file->route_count, 1, 'a document on disk loads the same way an HTTP one does');

# ------------------------------------------- the token is not optional

my $anonymous = Cantus::RouteSource->new(url => $url, refresh => 0.2);
ok(!$anonymous->router, 'without the key the control plane refuses, and no rules are invented');
like($anonymous->last_error, qr/HTTP 401|connect/i, 'and the refusal is what gets reported');

done_testing();
unlink $cache, $file, $doc_path;
