package Cantus::Health;
use strict;
use warnings;

# What "healthy" means for a node, expressed against a finished scenario.
#
# A direct path is the preferred result, but it is not always reachable: behind a
# symmetric NAT the mapping is per-destination, so the two ends can never talk
# directly and the relay is the design rather than the fallback. A verdict that
# demands a direct path therefore fails every healthy symmetric deployment — and
# symmetric NAT is the case this stack exists for, so that verdict would be
# exactly wrong where it matters.
#
#   no rebind           audio has to arrive, and it has to be audible.
#   cone + rebind       the call falls back to the relay and then returns to a
#                       direct path; that recovery is the property being sold.
#   symmetric + rebind  the relay carries the call, the flush does not end it, and
#                       it finishes on its own rather than being dropped.
sub verdict {
    my ($r, %a) = @_;
    my $nat    = $a{nat} // 'none';
    my $rebind = $a{rebind} ? 1 : 0;

    return { ok => 0, error => $r->{error} // 'the call did not complete' } unless $r && $r->{ok};
    return { ok => 0, error => 'no audio arrived' } unless ($r->{frames} // 0) > 0;
    return { ok => 0, error => 'the audio was silent' } unless ($r->{peak} // 0) > 0;

    return { ok => 1 } unless $rebind;

    if ($nat eq 'symmetric') {
        return { ok => 0, error => 'the relay did not carry the call' }
            unless ($r->{relay_frames} // 0) > 0;
        return { ok => 0, error => 'the call dropped when the mapping was flushed' }
            if $r->{premature_end};
        return { ok => 1 };
    }

    # A cone middlebox keeps the mapping, so the direct path must come back.
    return { ok => 0, error => 'the call never returned to a direct path' }
        unless defined $r->{recovered_at};
    return { ok => 1 };
}

1;
