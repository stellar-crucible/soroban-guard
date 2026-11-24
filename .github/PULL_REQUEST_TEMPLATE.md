## Description

What does this pull request change, and why? Link the issue it resolves.

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature (crate API or rule)
- [ ] Documentation
- [ ] Refactor / internal cleanup
- [ ] CI or security tooling

## Stellar Wave

- [ ] This PR resolves an issue labeled `Stellar Wave` with a `complexity:` tag
- [ ] I raised the issue first and a maintainer approved the scope

## Acceptance criteria check

Re-read the linked issue and confirm each box in its Acceptance Criteria section:

- [ ] All acceptance criteria are met
- [ ] Example usage from the issue compiles and passes
- [ ] Public API additions are documented with doc comments
- [ ] The matching page under `docs/src/` is updated in this PR
- [ ] A test proves the new behaviour, and it fails without the change

## Verification

Run these locally before requesting review — CI treats warnings as errors:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mdbook build docs
cargo deny check all
```

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets` passes with `-D warnings`
- [ ] `cargo test --workspace` passes
- [ ] Docs build (`mdbook build docs`) passes
- [ ] `cargo deny check all` passes against the committed `Cargo.lock`
