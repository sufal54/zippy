- For encrypt
  ./zippy -m e -i example/\*.txt -o output.enc

- For derypt
  ./zippy -m d i zippy_enc/output.enc

- or if key live in diffrent dir
  ./zippy -m d i zippy_enc/output.enc -k ./key.bin
