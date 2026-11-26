package Cantus::G711;
# G.711 companding, the codec a SIP edge actually speaks.
#
# The Cantus conformance codec is pcm-s16 at 8 kHz mono; a PSTN/softphone edge
# speaks G.711 at the same rate. The two are the same audio, so a gateway is a
# table lookup in each direction and nothing else -- no resampling, no framing
# change: 20 ms is 160 samples is 160 octets of mu-law.
#
# mu-law (PCMU, payload type 0) is the default because it is what every carrier
# and every softphone offers first. A-law is here because the edge may offer it
# and refusing it would be an avoidable failure.
use strict;
use warnings;

my (@DECODE_MU, @DECODE_A);

# Build the decode tables once.  A table is a 256-entry array of signed 16-bit
# samples, which is both faster and easier to verify than bit twiddling per
# sample on every frame.
sub _init_mu {
    for my $u (0 .. 255) {
        my $x = ~$u & 0xFF;
        my $sign = $x & 0x80;
        my $exp  = ($x >> 4) & 0x07;
        my $mant = $x & 0x0F;
        my $mag  = ((($mant << 3) + 0x84) << $exp) - 0x84;
        $DECODE_MU[$u] = $sign ? -$mag : $mag;
    }
}

sub _init_a {
    for my $a (0 .. 255) {
        my $x = $a ^ 0x55;
        my $sign = $x & 0x80;
        my $exp  = ($x >> 4) & 0x07;
        my $mant = $x & 0x0F;
        my $mag  = $exp == 0
            ? (($mant << 1) + 1) << 3
            : ((($mant << 1) + 0x21) << ($exp + 2)) - 0x21;
        $DECODE_A[$a] = $sign ? -$mag : $mag;
    }
}

_init_mu();
_init_a();

sub mu_decode_table { \@DECODE_MU }
sub a_decode_table  { \@DECODE_A }

# bytes -> pcm-s16 little-endian, the frame format Cantus carries.
sub mu_to_pcm {
    my ($bytes) = @_;
    return '' unless defined $bytes && length $bytes;
    my @s = map { $DECODE_MU[$_] } unpack('C*', $bytes);
    return pack('s<*', @s);
}

sub a_to_pcm {
    my ($bytes) = @_;
    return '' unless defined $bytes && length $bytes;
    my @s = map { $DECODE_A[$_] } unpack('C*', $bytes);
    return pack('s<*', @s);
}

# pcm-s16 little-endian -> mu-law bytes.  The canonical G.711 encoder: clip,
# then segment + mantissa in the companded domain.
sub pcm_to_mu {
    my ($pcm) = @_;
    return '' unless defined $pcm && length $pcm;
    my @s = unpack('s<*', $pcm);
    my $out = '';
    for my $sample (@s) {
        my $sign = $sample < 0 ? 0x80 : 0;
        my $mag  = $sample < 0 ? -$sample : $sample;
        $mag = 32635 if $mag > 32635;
        $mag += 0x84;
        my $exp = 7;
        for (my $mask = 0x4000; $exp > 0 && !($mag & $mask); $exp--, $mask >>= 1) { }
        my $mant = ($mag >> ($exp + 3)) & 0x0F;
        $out .= pack('C', ~($sign | ($exp << 4) | $mant) & 0xFF);
    }
    return $out;
}

sub pcm_to_a {
    my ($pcm) = @_;
    return '' unless defined $pcm && length $pcm;
    my @s = unpack('s<*', $pcm);
    my $out = '';
    for my $sample (@s) {
        my $sign = $sample >= 0 ? 0x80 : 0;
        my $mag  = $sample < 0 ? -$sample : $sample;
        $mag = 32635 if $mag > 32635;
        my ($exp, $mant);
        if ($mag < 256) {
            $exp  = 0;
            $mant = $mag >> 4;
        } else {
            $exp = 7;
            for (my $mask = 0x4000; $exp > 0 && !($mag & $mask); $exp--, $mask >>= 1) { }
            $mant = ($mag >> ($exp + 3)) & 0x0F;
        }
        $out .= pack('C', (($sign | ($exp << 4) | $mant)) ^ 0x55);
    }
    return $out;
}

# 160 samples of silence in each wire format: a call with nothing to say must
# still send packets, or the far end reads the gap as a dead path.
sub mu_silence { return "\xFF" x 160 }
sub a_silence  { return "\xD5" x 160 }

1;
