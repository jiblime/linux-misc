=====================================================
gcc link time optimization (LTO) for the Linux kernel
=====================================================

Link Time Optimization allows the compiler to optimize the complete program
instead of just each file.

The compiler can inline functions between files and do various other global
optimizations, like specializing functions for common parameters,
determing when global variables are clobbered, making functions pure/const,
propagating constants globally, removing unneeded data and others.

It will also drop unused functions which can make the kernel
image smaller in some circumstances, in particular for small kernel
configurations.

For small monolithic kernels it can throw away unused code very effectively
(especially when modules are disabled) and usually shrinks
the code size.

Build time and memory consumption at build time will increase, depending
on the size of the largest binary. Modular kernels are less affected.
With LTO incremental builds are less incremental, as always the whole
binary needs to be re-optimized (but not re-parsed)

Oops can be somewhat more difficult to read, due to the more aggressive
inlining: it helps to use scripts/faddr2line.

Normal "reasonable" builds work with less than 4GB of RAM, but very large
configurations like allyesconfig typically need more memory. The actual
memory needed depends on the available memory (gcc sizes its garbage
collector pools based on that or on the ulimit -m limits) and
the compiler version.

Configuration:
--------------
- Enable CONFIG_LTO_MENU and then disable CONFIG_LTO_DISABLE.
This is mainly to not have allyesconfig default to LTO.

Requirements:
-------------
- Enough memory: 4GB for a standard build, more for allyesconfig
The peak memory usage happens single threaded (when lto-wpa merges types),
so dialing back -j options will not help much.

A 32bit compiler is unlikely to work due to the memory requirements.
You can however build a kernel targeted at 32bit on a 64bit host.

FAQs:
-----
Q: I get a section type attribute conflict
A: Usually because of someone doing
const __initdata (should be const __initconst) or const __read_mostly
(should be just const). Check both symbols reported by gcc.

References:
-----------

Presentation on Kernel LTO
(note, performance numbers/details outdated.  In particular gcc 4.9 fixed
most of the build time problems):
http://halobates.de/kernel-lto.pdf

Generic gcc LTO:
http://www.ucw.cz/~hubicka/slides/labs2013.pdf
http://www.hipeac.net/system/files/barcelona.pdf

Somewhat outdated too:
http://gcc.gnu.org/projects/lto/lto.pdf
http://gcc.gnu.org/projects/lto/whopr.pdf

Happy Link-Time-Optimizing!

Andi Kleen
