"""Regression from fresh Debian bookworm ARM64 binutils 2.40 observations."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_symbol_audit", ROOT / "contrib/ml-dsa-integration/run_native_tests.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

NM = '0000000000002140 T pqbtc_mldsa44_node_verify\n'

DYNSYM = "\nSymbol table '.dynsym' contains 10 entries:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n     1: 00000000000004d8     0 SECTION LOCAL  DEFAULT    9 .init\n     2: 0000000000020020     0 SECTION LOCAL  DEFAULT   21 .data\n     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.17 (2)\n     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable\n     5: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.17 (2)\n     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memset@GLIBC_2.17 (2)\n     7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__\n     8: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable\n     9: 0000000000002140    88 FUNC    GLOBAL DEFAULT   11 pqbtc_mldsa44_node_verify\n"

SECTIONS = 'There are 35 section headers, starting at offset 0x1eba8:\n\nSection Headers:\n  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0\n  [ 1] .note.gnu.build-id NOTE            00000000000001c8 0001c8 000024 00   A  0   0  4\n  [ 2] .gnu.hash         GNU_HASH        00000000000001f0 0001f0 000024 00   A  3   0  8\n  [ 3] .dynsym           DYNSYM          0000000000000218 000218 0000f0 18   A  4   3  8\n  [ 4] .dynstr           STRTAB          0000000000000308 000308 000092 00   A  0   0  1\n  [ 5] .gnu.version      VERSYM          000000000000039a 00039a 000014 02   A  3   0  2\n  [ 6] .gnu.version_r    VERNEED         00000000000003b0 0003b0 000020 00   A  4   1  8\n  [ 7] .rela.dyn         RELA            00000000000003d0 0003d0 0000a8 18   A  3   0  8\n  [ 8] .rela.plt         RELA            0000000000000478 000478 000060 18  AI  3  20  8\n  [ 9] .init             PROGBITS        00000000000004d8 0004d8 000018 00  AX  0   0  4\n  [10] .plt              PROGBITS        00000000000004f0 0004f0 000060 00  AX  0   0 16\n  [11] .text             PROGBITS        0000000000000550 000550 001c48 00  AX  0   0 16\n  [12] .fini             PROGBITS        0000000000002198 002198 000014 00  AX  0   0  4\n  [13] .rodata           PROGBITS        00000000000021b0 0021b0 000504 00   A  0   0 16\n  [14] .eh_frame_hdr     PROGBITS        00000000000026b4 0026b4 00007c 00   A  0   0  4\n  [15] .eh_frame         PROGBITS        0000000000002730 002730 000270 00   A  0   0  8\n  [16] .init_array       INIT_ARRAY      000000000001fdf0 00fdf0 000008 08  WA  0   0  8\n  [17] .fini_array       FINI_ARRAY      000000000001fdf8 00fdf8 000008 08  WA  0   0  8\n  [18] .dynamic          DYNAMIC         000000000001fe00 00fe00 0001c0 10  WA  4   0  8\n  [19] .got              PROGBITS        000000000001ffc0 00ffc0 000028 08  WA  0   0  8\n  [20] .got.plt          PROGBITS        000000000001ffe8 00ffe8 000038 08  WA  0   0  8\n  [21] .data             PROGBITS        0000000000020020 010020 000008 00  WA  0   0  8\n  [22] .bss              NOBITS          0000000000020028 010028 000010 00  WA  0   0  8\n  [23] .comment          PROGBITS        0000000000000000 010028 000027 01  MS  0   0  1\n  [24] .debug_aranges    PROGBITS        0000000000000000 01004f 000030 00      0   0  1\n  [25] .debug_info       PROGBITS        0000000000000000 01007f 0059cc 00      0   0  1\n  [26] .debug_abbrev     PROGBITS        0000000000000000 015a4b 000676 00      0   0  1\n  [27] .debug_line       PROGBITS        0000000000000000 0160c1 002968 00      0   0  1\n  [28] .debug_str        PROGBITS        0000000000000000 018a29 0010f9 01  MS  0   0  1\n  [29] .debug_line_str   PROGBITS        0000000000000000 019b22 000267 01  MS  0   0  1\n  [30] .debug_loclists   PROGBITS        0000000000000000 019d89 003891 00      0   0  1\n  [31] .debug_rnglists   PROGBITS        0000000000000000 01d61a 000843 00      0   0  1\n  [32] .symtab           SYMTAB          0000000000000000 01de60 0008a0 18     33  85  8\n  [33] .strtab           STRTAB          0000000000000000 01e700 00034b 00      0   0  1\n  [34] .shstrtab         STRTAB          0000000000000000 01ea4b 00015d 00      0   0  1\nKey to Flags:\n  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n  L (link order), O (extra OS processing required), G (group), T (TLS),\n  C (compressed), x (unknown), o (OS specific), E (exclude),\n  D (mbind), p (processor specific)\n'


class NativeSymbolTests(unittest.TestCase):
    def validate(self, dynamic=DYNSYM, sections=SECTIONS, nm=NM):
        return audit.validate_verifier_exports(nm, compiler="gcc", sanitized=False,
                                               elf_dynamic_symbols=dynamic, elf_sections=sections)

    def test_actual_local_section_metadata_is_not_a_public_export(self):
        self.assertEqual(self.validate(), ["pqbtc_mldsa44_node_verify"])

    def test_local_section_metadata_must_match_real_allocated_section(self):
        mutations = (
            DYNSYM.replace("00000000000004d8     0 SECTION", "00000000000004d9     0 SECTION"),
            DYNSYM.replace("0 SECTION LOCAL  DEFAULT    9 .init", "1 SECTION LOCAL  DEFAULT    9 .init"),
            DYNSYM.replace("0 SECTION LOCAL  DEFAULT    9 .init", "0 SECTION LOCAL  HIDDEN     9 .init"),
            DYNSYM.replace("9 .init", "9 .unexpected"),
            DYNSYM.replace("9 .init", "23 .init"),
        )
        for dynamic in mutations:
            with self.subTest(dynamic=dynamic), self.assertRaises(RuntimeError):
                self.validate(dynamic=dynamic)

    def test_global_or_function_symbols_are_not_excused_as_local_metadata(self):
        for dynamic in (DYNSYM.replace("SECTION LOCAL", "SECTION GLOBAL", 1),
                        DYNSYM.replace("SECTION LOCAL", "FUNC    LOCAL", 1)):
            with self.subTest(dynamic=dynamic), self.assertRaises(RuntimeError):
                self.validate(dynamic=dynamic)

    def test_real_extra_public_export_remains_refused(self):
        dynamic = DYNSYM.replace("contains 10 entries", "contains 11 entries")
        dynamic += "    10: 0000000000002140    88 FUNC    GLOBAL DEFAULT   11 private_signer_export\n"
        with self.assertRaises(RuntimeError):
            self.validate(dynamic=dynamic, nm=NM+"0000000000002140 T private_signer_export\n")


if __name__ == "__main__":
    unittest.main()
