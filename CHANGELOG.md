# Changelog

The format is based on [Common Changelog](https://common-changelog.org/) and [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-05-05

### Changed

- **Breaking:** Update `cipher` to 0.5.1 and `aes` examples / tests to 0.9.0.
- **Breaking:** The cipher block size is now enforced at the type level.
  - This also removes the possibility of methods panicking due to an incorrect block size.
- **Breaking:** Tweak inputs and examples now use `hybrid_array::Array` instead of the array primitive, following upstream.
- Increase MSRV to 1.85 and update to edition 2024.
- Improve and simplify core logic

### Removed

- **Breaking:** Remove unused `std` feature.
- Remove `byteorder` dependency.
- Remove trait bounds from the Xts128 struct, applying them only to implementations.
