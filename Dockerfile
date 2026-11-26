# cantus-node — the reference stack as a service.
#
# Perl core only: Cantus has no CPAN dependencies, so the image is the
# interpreter plus this repository. Nothing is compiled, which is why it can be
# built in CI on every push and pulled by a host that has no working builder.
FROM perl:5.40-slim

LABEL org.opencontainers.image.title="cantus-node"
LABEL org.opencontainers.image.description="Cantus 1.0 node and relay: one UDP socket on 7443"
LABEL org.opencontainers.image.source="https://github.com/innotelinc/cantus"

WORKDIR /opt/cantus
COPY bin/ bin/
COPY lib/ lib/
COPY examples/ examples/
COPY deploy/ deploy/
RUN chmod +x bin/cantus

# The node and the relay are the same binary with different config, so one image
# carries both roles and the compose file picks with the command.
ENTRYPOINT ["perl", "-Ilib", "bin/cantus"]
CMD ["help"]
