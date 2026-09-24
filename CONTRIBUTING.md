# Contributing

Contributions that improve correctness, portability, tests, documentation, and defensive network-auditing features are welcome.

1. Fork the repository and create a focused branch.
2. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test`.
3. Keep network tests deterministic and local; CI must not scan public third-party hosts.
4. Do not commit secrets, captured private traffic, credentials, or unauthorized target data.
5. Open a pull request explaining the behavior change and validation performed.

By contributing, you agree that your contribution is licensed under the MIT License.
