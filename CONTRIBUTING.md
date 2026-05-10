# Contributing to Seamless

Thank you for your interest in contributing to Seamless.

## Contributor License Agreement

Before your contribution can be accepted, you must sign the **North9 Contributor License Agreement (CLA)**. The CLA grants North9 LLC the right to include your contribution in both the open-source (AGPL v3) and commercial releases of Seamless.

The CLA is managed automatically via [CLA Assistant](https://cla-assistant.io/). When you open a pull request, a bot will check your CLA status and prompt you to sign if you haven't already.

## Development

Clone both repos side by side (Seam is a path dependency):

```sh
git clone https://github.com/North9LLC/Seam
git clone https://github.com/North9LLC/Seamless
cd Seamless
cargo test --workspace --all-targets
cargo clippy -p seamless-common -p seamless-relay -p seamless-client --all-targets -- -D warnings
```

## Guidelines

- Zero clippy warnings (`-D warnings`) required before merge
- Add integration tests for new tunnel functionality
- Protocol changes (wire format, frame types) require discussion in an issue first
- Security-relevant changes require review from a North9 maintainer

## Security

For security vulnerabilities, open a [private advisory](https://github.com/North9LLC/Seamless/security/advisories/new) — not a public issue.

## License

By contributing, you agree that your contributions will be licensed under both AGPL v3 and North9's commercial license per the CLA.
