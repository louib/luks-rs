# luks-rs

Pure-Rust Library for the Linux Unified Key Setup

## Examples

Check the [examples](examples/) directory for usage. You can run them with:

```bash
cargo run --example read_header -- /dev/sda1
```

## References

- [LUKS1 On-Disk Format Specification](https://gitlab.com/cryptsetup/LUKS-specification/-/blob/master/luks1/specification/luks1_spec.pdf)
- [LUKS2 On-Disk Format Specification](https://gitlab.com/cryptsetup/LUKS2-docs/raw/branch/master/luks2_spec.pdf)
- [New Methods in Hard Disk Encryption](https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf)
