# Exploit Blackbird on A8 Devices and Achieve Untethered Downgrade with Blobs

**WARNING: THIS IS ONLY A PROOF OF CONCEPT. IF YOU BUILD AND RUN THE PAYLOAD ON YOUR DEVICE, YOU'RE AWARE OF THE RISK OF PERMANENT LOSS OF YOUR DATA AND PERMANENT BOOTLOOP OF YOUR DEVICE! USE AT YOUR OWN RISK!**

However, I've tried to restore to iOS 11.4 from iOS 15.8.8 on my iPad mini 4 Wi-Fi, and confirmed everything works fine, including password, Touch ID, and sleep. If you followed this instruction properly, you should also be able to restore arbitrary version that you have a valid SHSH (also, a generator).

And, everything before overwriting ART should be read only and won't compromise your data and device.

## Part I Exploit SEP and Obtain ART Key
1. Put your device in DFU mode, and use palera1n or checkra1n to start [this](https://github.com/pwnerblu/atera1n-PongoOS) PongoOS image. You can build yourself, or use the image build by Github Action.

2. Type `sep shc` in pongoterm. Something like this will appear on pongoterm: 
```
0xe3463238a41605c
0xffabba5ecee9e59a
0x55f7ce58d7f5f74a
0x1aba653c2d5a107a
0xf3bf3ad3bc25ede8
0x6ec68f684695b09
0x0
0x0
0xc28e487fa55a3b62
0xa511f6acc89162df
0xd94d49cb06b1db1f
0x63faeeb7467bbfce
0x3f4dd5d77a8ae024
0xd757387664aa9abb
0x0
0x0
```
Save these bytes as a binary file. `scripts/hex_to_bin.py` should help you. The file should have 448 bytes.

3. Reboot your device into DFU and boot PongoOS once again. Enter pongoterm on your computer.

4. Type `/send /absolute/path/to/previously/saved/binary.bin`, then type `sep replay 470000`. The argument is the number of tick that the first race overwrite starts. Empirically 470000 works on my iPad mini 4. If this doesn't work, SEP will panic. You can also run `sep observe` to see when does the `observed_value` change. Take this as an example:
```
#==================
#
# pongoOS 2.6.3-3d40bea0
#
# https://checkra.in
#
#==================
Booted by: iBoot-7459.140.15
Built with: Clang 21.0.0 (clang-2100.1.1.101)
Running on: Apple A8 (T7000)
pongoOS> sep observe
use_fake_img4 = 0, disable_key_pinning = 0
got seprom message 65
start to boot tz0
finished writing key pinning area
seprom booted tz0: 1
got seprom message 65
Using art read from device tree
NVRAM encoded: PA=0x803770e3d, len=0x138
Decoded ART: VA=0x47c2b0000, PA=0x87c2b0000, len=0x129
seprom loaded art: 1
sepos booted: 1
number_of_change = 5
0th observed_value=61436c656e72654b, at tick=0
1th observed_value=7a39fd778fbeda38, at tick=57
2th observed_value=ddb990936ff1918c, at tick=117245
3th observed_value=fa61c6851427bfb2, at tick=1012264
4th observed_value=fa377039b592b43c, at tick=1533324
5th observed_value=5b977279f8931ff0, at tick=1573422
```

You should choose a tick between the 2rd and the 3rd.
If that works, `sep pwned with opcode ab` will appear in pongoterm. Now you have code execution on SEP.
![alt text](images/image.png)

On some old device such as iOS 11.4 that I restored to, PongoOS cannot automatically detect your onboard SEPOS firmware. This is because iBEC before iOS 13 only allocates the SEP firmware buffer, but they doesn't copy the image to this area. You may need to enter the Ramdisk to extract your on board SEPOS firmware.

**Devices that never got iOS 13 (e.g. iPhone 6 on iOS 12):** On these devices, `gSEPFW` is always empty. You must boot an SSHRD, get the SEP firmware img4 from the root filesystem, and load it manually before running `sep observe` or `sep replay`:
```
/send /path/to/sep-firmware.img4
sep fwsend
```
This copies the sent firmware into `gSEPFW` so that SEPROM can load it. You must do this on **every fresh boot** of PongoOS, before both `sep observe` and `sep replay`. You must also reboot the device back into PongoOS (via checkm8) between `sep observe` and `sep replay`, since observe boots SEPOS and SEP cannot be re-initialized without a reboot.

5. Send SEP payload. Type `/send /absolute/path/to/payload.bin`, then `sep load`. 

6. Jump to the entrypoint of payload. Run `sep jump 1000`. 

7. You should recieve sepmessage ad. At that time you can run `sep peek`, from address `0x10140000` to `0x1014001c`. Keep these 32 bytes in mind. 
![alt text](images/image2.png)

## Part II Modify ART Stored in Device NVRAM
1. Clone SSHRD, create a ramdisk for iOS 15.8.8 (make a 12.5.8 ramdisk if your A8 device never got iOS 13+), and ask your agent to remove the permission bits `p.Bits.KernelOnly` of NVRAM key `com.apple.System.sep.art` and `com.apple.System.boot-nonce` in your kernelcache.

2. Boot into Ramdisk with SSHRD, and start a ssh connection.

3. Type `nvram com.apple.System.boot-nonce=0x1111111111111111` (Change 0x1111111111111111 to the generator in your SHSH)

4. Type `/usr/libexex/seputil --art get` to see your current ART. You should get something like this:
```
308201250201003081fd0203077edf0414904b6ec3ccb67cd7247c37cd29c085ab543067b4041452e2b2fd0f62a6de88253d3c25ce39ec02fd9ad204140341dd2599d16700c11758b6934402b78b51bb1e3181b3c00305725dc103057002c203056fe4c30305703bc403056fe7c703056fedc8060080684960e7c9060098fa2ba607ca0563b5181d6acb0569f9254143cc06008f61a2101ccd0600ced9445c3fce055925e4e3c2cf0600af36b6f282d0054b5371ef94d10600c55288ba42d2053adc85c552d30600eb9111dcdbd40600cedea96cead50600b19bba4c32d605680ec2e73ed70571d05b345dd80600d27b0fddb0d90600dd5dbbdde0da0600a8bb0220ffdb02070c04207a702a127b6f73bf3377e4de55d2cf2c6b6db9eed3de9a6ec660770638b800ba
Successfully parsed ART:
counter: 491231
manifest hash (20 bytes): 904b6ec3ccb67cd7247c37cd29c085ab543067b4
sleep hash (20 bytes): 52e2b2fd0f62a6de88253d3c25ce39ec02fd9ad2
restore nonce (20 bytes): 0341dd2599d16700c11758b6934402b78b51bb1e
subcounters[27]: 1804
subcounters[26]: 724691984639
subcounters[25]: 950760365536
subcounters[24]: 904007769520
subcounters[23]: 488826942557
subcounters[22]: 446924252990
subcounters[21]: 762821889074
subcounters[20]: 888498908394
subcounters[19]: 1011751181531
subcounters[18]: 252807857490
subcounters[17]: 847493249602
subcounters[16]: 323522523028
subcounters[15]: 752537236098
subcounters[14]: 382887846850
subcounters[13]: 888408398911
subcounters[12]: 615818334236
subcounters[11]: 455151534403
subcounters[10]: 428240018794
subcounters[9]: 657032193543
subcounters[8]: 551505453287
subcounters[7]: 356333
subcounters[4]: 356327
subcounters[3]: 356411
subcounters[2]: 356324
subcounters[1]: 356354
subcounters[0]: 356957
```
Create a backup for it in the case of failing.

5. This is your art in hex format, which is encoded in ASN.1 DER. You can use `python scripts/patch_art.py --shsh path/to/shsh --art-hex 123456 --art-key abcdef` to patch it. However this only tested with my ARTs, so if this doesn't work for you, please change it manually. You should only change the manifest hash to your digest hash, and the restore nonce to the SNON in you SHSH. There is a MAC in the back of ART. You should recalculate it with format `mac32 = HMAC-SHA256(Key_ART, body_DER)`. For both way you should verify that the patched DER is legal using `openssl`.

6. Set `com.apple.System.sep.art` to the patched version. Use `nvram "com.apple.System.sep.art=%11%22%33%ef"`. Don't forget the first `%`!
   
7. Save your change with `nvram -s`.

8. Reboot your device into DFU. Run `irecovery -q` to confirm if your APNonce is correct.

## Part III Restore Your Device
1. Build [this](https://github.com/feiyehua/idevicerestore.git) version of idevicerestore. It's only a simple modification that prevent idevice restore from trying to reboot the device before restoring, and request new APTicket from TSS. And provide your ssh. You should have something like `src/idevicerestore --erase -T "shsh_a142d549489ffeab9a38d3fe285decdf63e6e1e9.der" /path/to/ipsw.ipsw`. 
Note that for my iPad mini 4 Wi-Fi, there is no baseband. If you're using something with a baseband, you may need to use a patched version of futurerestore.

2. Wait for the restore to complete and enjoy your legacy system!

## How It Works
I'm planning to release a writeup to explain how it works.
See the [How It Works](How_it_works.md) file.

## Credits

- **checkm8**, created by [axi0mX](https://github.com/axi0mX).
- **blackbird**, discovered independently by Hao Xu (windknown, Pangu Team) and littlelailo.
- **PongoOS** was developed by the checkra1n team ([upstream project](https://github.com/checkra1n/PongoOS)).
- **Apple ROM Collection**, for providing BootROM binaries. ([Apple ROMs](https://securerom.fun))
- **The Apple Wiki**, for providing firmware keys. ([The Apple Wiki](https://theapplewiki.com/wiki/Main_Page))
- **SSHRD_Script** was created by Nathan ([verygenericname](https://github.com/verygenericname)).
- **turdus_merula**, developed by Clarity, kok3shidoll, and Mineek ([official credits](https://sep.lol/#credits)).
- **idevicerestore**, developed by Joshua Hill, Martin Szulecki, and Nikias Bassen ([upstream authors](https://github.com/libimobiledevice/idevicerestore/blob/master/AUTHORS)).
- **bb33bb**, providing snippets for A8 blackbird exploit ([Gist](https://gist.github.com/bb33bb/856f56d4d4d0cad57f03a035034a9e7a)).
- **ChatGPT**, for reverse enginnering SEPROM, SEPOS and the restore process for me.
- **DeepSeek**, for writing exploits when ChatGPT rejects me.
- **ByteDance**, for sponsoring (part of) the tokens as "AI Research and Study".
- **Apple**, for giving people wonderful tools for us to do wonderful things.

## Sponsor
Please use Binance Smart Chain:

USDT or USDC
```
0x0257b6c939f9dd8db61a92e8d54ff26870cf9ca3
```

## License

Copyright (C) 2026 feiyehua

This repository, including its shell code, exploit code, README files, documentation, configuration files, and other original materials, is licensed under the GNU General Public License, version 2.0 only (GPL-2.0-only), unless otherwise explicitly stated.

See the [LICENSE](LICENSE) file for the full license text.
