/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Shared library for the cross-.so DWARF/CFI workload. deep_lib_entry lives
 * here (separate ELF, own .eh_frame); it calls back into the main exe's
 * do_capture, so the unwind must cross exe -> libdeep.so -> exe. */
__attribute__((noinline, noipa))
void deep_lib_entry(void (*cb)(void))
{
	cb();
	__asm__ volatile("" ::: "memory");
}
