# Ioguard Naming Options

## Goal

Define a consistent replacement scheme for the remaining `ioguard`-era prefixes,
utilities, and operational artifacts.

## Naming Rules

1. Avoid collisions with existing Unix and Linux names.
2. Stay consistent with the `io*` family already used in adjacent projects.
3. Keep the public C prefix short enough for daily use.
4. Keep daemon, CLI, config, and container names predictable.

## C Prefix Options

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| `iog_` / `IOG_` | Short, unique enough, matches `ioguard`, aligns with `ioh_` and `ihtp_` | Slightly less obvious than full project name | Recommended |
| `iogd_` / `IOGD_` | Very explicit, low collision risk | Longer, noisier in API and file names | Acceptable fallback |
| `ig_` / `IG_` | Very short | Too generic, more collision risk | Reject |
| `guard_` / `GUARD_` | Readable | Too long and too generic | Reject |

## CLI Utility Name Options

`rwctl` needs a new name that does not collide with `ioctl(2)`.

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| `iogctl` | Short, consistent with `iog_`, distinct from `ioctl` | Slightly less obvious than full project name | Recommended |
| `ioguardctl` | Explicit and clear | Long | Acceptable fallback |
| `igctl` | Short | Too visually close to `ioctl` | Reject |
| `guardctl` | Readable | Generic and likely to collide conceptually | Reject |

## Recommended Artifact Names

| Current | Recommended | Notes |
|---|---|---|
| daemon binary `ioguard` | `ioguard` | External identity should match repo and product name |
| CLI `rwctl` | `iogctl` | Best short control-plane utility name |
| C prefix `iog_` | `iog_` | Public and internal C symbol family |
| macro prefix `IOG_` | `IOG_` | Pair with `iog_` |
| include guards `IOGUARD_...` | `IOGUARD_...` | Full project name is fine here |
| CMake project `ioguard` | `ioguard` | Human-facing build identity |
| include dir `include/ioguard/` | `include/ioguard/` | Match package identity |
| config file `ioguard.toml` | `ioguard.toml` | Predictable with daemon name |
| config dir `/etc/ioguard/` | `/etc/ioguard/` | Predictable with daemon name |
| state dir `/var/lib/ioguard/` | `/var/lib/ioguard/` | Predictable with daemon name |
| images `ioguard-dev/test/build/ci` | `ioguard-dev/test/build/ci` | Match repo/product name |
| OCI labels `io.ioguard.*` | `io.ioguard.*` | Match repo/product name |
| logger target `ioguard` | `ioguard` | Human-facing operational identity |
| nft table `ioguard` | `ioguard` | Operational identity |
| PAM service `ioguard` | `ioguard` | Consistent admin-facing naming |
| TOTP issuer `ioguard` | `ioguard` | End-user visible |
| docs repo `ioguard-docs` | `ioguard-docs` | If that repo is renamed too |
| client `ioguard-connect` | `ioguard-connect` | Explicit and predictable |

## Recommendation

Use this final naming scheme:

- daemon: `ioguard`
- CLI: `iogctl`
- C/API prefix: `iog_`
- macros: `IOG_`
- include guards: `IOGUARD_*`
- config file: `ioguard.toml`
- config path: `/etc/ioguard/`
- state path: `/var/lib/ioguard/`
- images: `ioguard-dev`, `ioguard-test`, `ioguard-build`, `ioguard-ci`
- OCI labels: `io.ioguard.*`
- client: `ioguard-connect`

## Migration Order

1. External and operator-facing artifacts
   - daemon name
   - CLI name
   - config and state paths
   - container image names
2. Build and packaging surface
   - CMake project name
   - include directory
   - package metadata
3. Public API and code prefixes
   - `iog_` -> `iog_`
   - `IOG_` -> `IOG_`
   - `IOGUARD_` -> `IOGUARD_`
4. Adjacent repositories and clients
   - `ioguard-docs`
   - `ioguard-connect`

This order minimizes user-visible confusion first, while postponing the highest-churn ABI and source-wide symbol rename until the project is ready for it.
