# The binary, and nothing else.
#
# This image is not meant to be RUN. It exists so another image's build can say
#
#     COPY --from=registry.internal.astradx.com/baoist-monk:v0.2.0 /bm /usr/local/bin/bm
#
# and get the released binary without a token, a release API call, or a
# `wget` that has to know this repo is private.
#
# ── Why scratch ────────────────────────────────────────────────────────────
# There is no shell, no libc and no package manager in here, because a
# `COPY --from` needs none of those — it reads a path out of the image's
# filesystem and never starts it. A distro base would add ~30 MB of layers that
# exist only to be discarded, and would give the thing a plausible-looking
# `docker run` that immediately fails in a confusing way. `FROM scratch` makes
# the intent unmistakable: this is a file, packaged.
#
# ★ The binary is the RELEASED artifact, not a rebuild. The workflow downloads
# it from the same job that publishes the GitHub release, so the bytes in this
# image and the bytes on the releases page are the same bytes. Rebuilding here
# would be one line shorter and would quietly break that property — Go is
# reproducible in principle, but a different toolchain patch level is enough to
# make "the same" mean "we assume so".
FROM scratch

# Explicit, NOT the automatic TARGETARCH. Buildah does populate TARGETARCH from
# --platform, but a scratch base has no metadata to fall back on if that ever
# changes, and the failure mode is a COPY of a path that does not exist — which
# reads as "the release is missing an asset" rather than "the build arg was
# empty". One --build-arg at the call site costs nothing and cannot be ambiguous.
ARG BMARCH

COPY dist/bm-linux-${BMARCH} /bm
