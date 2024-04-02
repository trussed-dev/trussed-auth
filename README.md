<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# trussed-auth

`trussed-auth` is an extension for [Trussed][] that provides basic PIN
handling.  `trussed-auth-backend` is a Trussed backend implementing that
extension using the filesystem.  Other implementations are provided by these
backends:
- [`trussed-se050-backend`][]

[Trussed]: https://github.com/trussed-dev/trussed
[`trussed-se050-backend`]: https://github.com/Nitrokey/trussed-se050-backend

## License

This project is dual-licensed under the [Apache-2.0][] and [MIT][] licenses.
Configuration files and examples are licensed under the [CC0 1.0
license][CC0-1.0].  For more information, see the license header in each file.
You can find a copy of the license texts in the [`LICENSES`](./LICENSES)
directory.

[Apache-2.0]: https://opensource.org/licenses/Apache-2.0
[MIT]: https://opensource.org/licenses/MIT
[CC0-1.0]: https://creativecommons.org/publicdomain/zero/1.0/

This project complies with [version 3.0 of the REUSE specification][reuse].

[reuse]: https://reuse.software/practices/3.0/
