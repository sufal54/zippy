# Zippy – File Encryption & Decryption Tool

Zippy is a simple command-line tool to **encrypt** and **decrypt** files using a custom key. It supports single or multiple files with wildcard patterns.

---

## 🔹 Getting Started

Make sure the executable `zippy` has **execute permissions**:

```bash
chmod +x ./zippy
```

## 🔹 Encrypt Files

To encrypt files, use the -m e mode and specify input files and output file:

```bash
./zippy -m e -i example/*.txt -o output.enc
```

-m e → Encryption mode

-i → Input files (supports wildcards like \*.txt)

-o → Output encrypted file

## Decrypt Files

To decrypt a file, use the -m d mode:

```bash
./zippy -m d -i zippy_enc/output.enc
```

If your key is in a different location, specify it using -k:

```bash
./zippy -m d -i zippy_enc/output.enc -k ./key.bin
```

-m d → Decryption mode

-i → Input encrypted file

-k → Optional key file (if not in default location)
