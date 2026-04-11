# Integrations

This section explains how KOVIL MAP connects to external tools and remote devices.

## Available Integrations

### [Pwnagotchi](pwnagotchi.md)

- SSH sync
- handshake sharing
- map refresh after sync

### [M5Evil Cardputer](m5evil-cardputer.md)

- Admin WebUI auto-sync
- handshake import
- Wardrive CSV import
- Cardputer-only in the current version

### [Hashcat](hashcat.md)

- GPU cracking
- device detection
- progress tracking

### [Aircrack-ng](aircrack-ng.md)

- CPU fallback cracking
- direct PCAP validation

### [HCXTools](hcxtools.md)

- PMKID extraction
- `.pcap` to `.22000` conversion

### [SSH/SFTP Remote](ssh-sftp-remote.md)

- secure file transfer
- host key verification
- remote capture browsing

---

## Typical Flow

```text
Remote device -> remote sync -> KOVIL MAP -> HCXTools -> Hashcat -> Results
```

---

## Compatibility

| Tool | Linux | macOS | Windows |
|---|---|---|---|
| Hashcat | yes | yes | yes |
| Aircrack-ng | yes | yes | partial |
| HCXTools | yes | yes | partial |
| Pwnagotchi | yes | yes | yes |
| M5Evil Cardputer | yes | yes | yes |
| SSH/SFTP | yes | yes | yes |
| Admin WebUI | yes | yes | yes |

---

## Next Steps

1. Read the tool-specific page.
2. Check the code examples.
3. Test locally in the development docs.
