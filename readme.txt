
/*
   libemu / Unicorn compatibility shim layer 
   Contributed by FireEye FLARE team
   Author: David Zimmer <david.zimmer@fireeye.com> <dzzie@yahoo.com>
   License: GPL

   Files: emu_cpu.h, emu_shim.h, emu_shim.cpp
*/


This is a sample of using the libemu win32 environment
with Unicorn engine. 

Project also includes a shim layer so that you can easily
port existing libemu code over to run on Unicorn.

Please see the following article for more details:

  https://www.fireeye.com/blog/threat-research/2017/04/libemu-unicorn-compatability-layer.html


Notes:
---------------------------------------------------------------------------------

The libemu environment was taken from scdbg and includes support for 15 dlls.

  kernel32, ntdll, ws2_32, iphlpapi, user32, shell32, 
  msvcrt, urlmon, wininet, shlwapi, advapi32, shdocvw,
  psapi, imagehlp, winhttp

The sample.exe contains a hardcoded shellcode buffer. A compiled binary
is available in the /bin folder.

Project files were built with VS2008. If you compiler does not come with 
stdint.h and inttypes.h compatible versions can be found here:

  https://github.com/dzzie/VS_LIBEMU/tree/master/libemu/include



Credits:
---------------------------------------------------------------------------------

	Libemu   Copyright (C) Paul Baecher & Markus Koetter
	License: GPL

	Unicorn  Copyright (C) Nguyen Anh Quynh and Dang Hoang Vu
        Site:    http://www.unicorn-engine.org/
	License: GPL

	QEMU
	Site:    http://qemu.org
	License: GPL

	scdbg    Copyright (C) David Zimmer
	Site:    http://sandsprite.com
	License: GPL




