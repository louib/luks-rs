# luks-rs

[![Crates.io](https://img.shields.io/crates/v/luks.svg)](https://crates.io/crates/luks)
[![Documentation](https://docs.rs/luks/badge.svg)](https://docs.rs/luks/)
[![Build Status](https://github.com/louib/luks-rs/actions/workflows/on-merge.yaml/badge.svg?branch=main)](https://github.com/louib/luks-rs/actions/workflows/on-merge.yaml)

Pure-Rust Library for the Linux Unified Key Setup

## Examples

Check the [examples](examples/) directory for usage. You can run them with:

```bash
cargo run --example read_header -- /dev/sda1
```

## References

- [LUKS2 On-Disk Format Specification](https://gitlab.com/cryptsetup/LUKS2-docs/blob/main/luks2_doc_wip.pdf)
- [LUKS1 On-Disk Format Specification](https://cdn.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf)
- [New Methods in Hard Disk Encryption](https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf)
- [TKS1 - An anti-forensic, two level, and iterated key setup scheme](https://www.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/TKS1-draft.pdf)
