# Copyright (C) Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

.PHONY: check
check:
	RUSTLFAGS='-Dwarnings' cargo check --all-features --all-targets --workspace

.PHONY: lint
lint:
	cargo clippy --all-features --all-targets --workspace -- --deny warnings
	cargo fmt --all -- --check
	RUSTDOCFLAGS='-Dwarnings' cargo doc --no-deps --workspace
	reuse lint

.PHONY: test
test:
	cargo test --all-features --workspace

.PHONY: ci
ci: check lint test
