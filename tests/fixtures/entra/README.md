# Entra fixtures

Shapes taken from Microsoft's published reference, with the source of each in `sources.json`. The simulator (`startMockOidc({ profile: "entra" })` in `tests/harness/oidc.mjs`) is checked against them by `tests/entra-simulator.test.mjs`, so it cannot drift from what Microsoft documents. The gateway is tested against the simulator in `tests/gateway-entra.test.mjs`, and against an independent open-source OIDC server in the optional job described in `tests/entra-crosscheck.test.mjs`.

Not captured from a live tenant. When a real Entra tenant is available, record a real discovery document and id_token claim set here and compare.
