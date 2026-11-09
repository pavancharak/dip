# 17. Protocol Versioning

Status: draft.

## 17.1 Version

The protocol version is a string, currently `"1.0"`. Every authority declaration, request, decision, evidence entry and bundle carries it.

## 17.2 Rules

- A component MUST reject a version it does not support (`UNSUPPORTED_PROTOCOL_VERSION`).
- A change that alters the meaning of an existing field, a digest input, a signature input or a reason code is a new major version.
- A compatible addition (a new optional reason code, a new read-only endpoint) is a minor version.
- Domain separators carry their own version (`DIP-*-V1`). A new separator version does not change the protocol version by itself.

## 17.3 Current state

Only `1.0` exists. No mechanism for negotiating between versions is defined yet.

## 17.4 Software versions

Software releases follow semantic versioning from `0.0.0` and are tagged `vMAJOR.MINOR.PATCH`. Packages are private and not published to a registry. A release notes entry in `CHANGELOG.md` is required for each tag.
