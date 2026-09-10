// No dependencies, deliberately: the OpenBao HTTP API this needs is three
// endpoints, and a static binary with no module graph is easier to ship inside
// an image and to reason about when it holds credentials.
module github.com/astradxma/baoist-monk

go 1.23
