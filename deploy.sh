#!/bin/bash
cp encrypt.c pi-cipher.c pi-cipher.h new_ref/
for i in  pi*cipher*v1; do cp -rv new_ref $i/; done
for j in 16 32 64; do for i in  pi${j}cipher*v1; do sed -i "s./\* # define PI_SIZE 16 \*/.#define PI_SIZE ${j}.g" $i/new_ref/pi-cipher.h ; done; done
cp -rv pi*cipher*v1 ../supercop-20141124/crypto_aead/


