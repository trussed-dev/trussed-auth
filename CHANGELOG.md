<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

- Use `CoreContext::new` to fix compilation with recent Trussed changes.

[Unreleased]: https://github.com/trussed-dev/trussed-auth/compare/v0.2.1...HEAD

## [0.2.1][] - 2023-04-05

- Fix salt path location ([#25][])

[#25]: https://github.com/trussed-dev/trussed-auth/pull/25
[0.2.1]: https://github.com/trussed-dev/trussed-auth/releases/tag/v0.2.1

## [0.2.0][] (yanked) - 2023-04-05

- Fix data location ([#23][])
- Add pin counter reset mechanism ([#17][])

[#23]: https://github.com/trussed-dev/trussed-auth/pull/23
[#17]: https://github.com/trussed-dev/trussed-auth/pull/17
[0.2.0]: https://github.com/trussed-dev/trussed-auth/releases/tag/v0.2.0

## [0.1.1][] - 2023-03-06

- Add support for "missing" hw key ([#16][])

[#16]: https://github.com/trussed-dev/trussed-auth/pull/16
[0.1.1]: https://github.com/trussed-dev/trussed-auth/releases/tag/v0.1.1

## [0.1.0][] - 2023-03-03

Initial release with PIN handling and key derivation from PINs.

[0.1.0]: https://github.com/trussed-dev/trussed-auth/releases/tag/v0.1.0

