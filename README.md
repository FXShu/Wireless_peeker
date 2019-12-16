## Man-in-the-middle attack
### Introduction
`Man-in-the-middle` attack is a useful cyber attack to get the traffic between victim and router.<br>
In the wireless generation, traffic was transmited via air, it make more easy to capute those packet.<br> 
However, according to IEEE802.11, each packet was encrypted by `WPA2` encryption. 
If we want to peek the inormation of those encrypted traffice, we should calculate the `PTK` of ap and station.

### How to Build
* Modify `cross` item in `Makefile` to cross-compile if you need. 
* Just type `Make`

### Binary
* `MITM`: <br>
The main process which can crash wpa2 password, calculate ptk, decrypte wireless packet and store those packet.<br>
* `MITM_cil`: <br>
The process which can interaction with `MITM` process, like set ap and victim you want to hack, report some indormation of network...<br>

### TODO
* `Interaction` :
* `Crash`:  
  * `KRACK` attack implement.
  * `PMKID` attack implement.
  * `Evil twins` attack implement.
