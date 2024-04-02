<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

Extracted from `trussed-auth` v0.3.0.

### Breaking Changes

- Use serde(rename) to save space on on the size of stored credentials ([#38][])
- Remove the `dat` intermediary directory in file storage ([#39][])
- Use `trussed-core` and remove default features for `trussed`

[#38]: https://github.com/trussed-dev/trussed-auth/pull/38
[#39]: https://github.com/trussed-dev/trussed-auth/pull/39
