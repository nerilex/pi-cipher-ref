#!/bin/bash
cp encrypt.c pi-cipher.c pi-cipher.h pi*_parameter.h ref/
for i in  pi*cipher*v2; do cp -rv ref $i/; done
for j in 16 32 64; do for i in  pi${j}cipher*v2; do sed -i "s./\* # define PI_SIZE 16 \*/.#define PI_SIZE ${j}.g" $i/ref/pi-cipher.h ; done; done
cp -rv pi*cipher*v2 ../supercop-20141124/crypto_aead/


