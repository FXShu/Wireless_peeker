## Wirelss peeker
[![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
### Introduction
In the wireless generation, traffic was transmited via air, it mask more easy to capture those packet.<br>
However, according to `IEEE802.11i`, data type packet was encrypted by `WPA`/ `WPA2` encryption.<br>
If we want to peek the plaintext of those encrypted traffic, we should capture 4-way handshake and calculate the correct `PTK`.<br>

Currently there are the following methods can crack `WPA2` encryption<br>
* Dictionary attack
* KRACK<br>
　key reinstall loophole was fixed after hostaps2.8 or abvoe.
* [Using `PMKID`](https://hashcat.net/forum/thread-7717.html)

For simplicity, wireless peeker used `Dictionary attack` to get the PTK between AP and victim.<br>
However, Simplicity means stupid, this attack should take a lot of time to test all password in dictionary.<br>

All decrypted taffic will be storaged on `pcapng` format file by sprcify file name with `-w` flag.<br> 
### How to Build
* Modify `cross` item in `Makefile` to cross-compile if you need. 
* Just type `Make`

### Binary
* `MITM`: <br>
The main process which can crash wpa2 password, calculate ptk, decrypte wireless packet and store those packet.<br>
* `MITM_cil`: <br>
The process which can interaction with `MITM` process, like set ap and victim you want to hack, report some information of network...<br>

[![](http://img.youtube.com/vi/3YKJ2sgBjhw/0.jpg)](http://www.youtube.com/watch?v=3YKJ2sgBjhw "wireless peeker usage")

This project just used to show how attack work, please do not use it to do anything illegel.<br>
