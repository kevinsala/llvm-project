// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sme2 < %s \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST
// RUN: not llvm-mc -triple=aarch64 -show-encoding < %s 2>&1 \
// RUN:        | FileCheck %s --check-prefix=CHECK-ERROR
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sme2 < %s \
// RUN:        | llvm-objdump -d --mattr=+sme2 - | FileCheck %s --check-prefix=CHECK-INST
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sme2 < %s \
// RUN:        | llvm-objdump -d --mattr=-sme2 - | FileCheck %s --check-prefix=CHECK-UNKNOWN
// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sme2 < %s \
// RUN:        | sed '/.text/d' | sed 's/.*encoding: //g' \
// RUN:        | llvm-mc -triple=aarch64 -mattr=+sme2 -disassemble -show-encoding \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST


ucvtf   {z0.s, z1.s}, {z0.s, z1.s}  // 11000001-00100010-11100000-00100000
// CHECK-INST: ucvtf   { z0.s, z1.s }, { z0.s, z1.s }
// CHECK-ENCODING: [0x20,0xe0,0x22,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c122e020 <unknown>

ucvtf   {z20.s, z21.s}, {z10.s, z11.s}  // 11000001-00100010-11100001-01110100
// CHECK-INST: ucvtf   { z20.s, z21.s }, { z10.s, z11.s }
// CHECK-ENCODING: [0x74,0xe1,0x22,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c122e174 <unknown>

ucvtf   {z22.s, z23.s}, {z12.s, z13.s}  // 11000001-00100010-11100001-10110110
// CHECK-INST: ucvtf   { z22.s, z23.s }, { z12.s, z13.s }
// CHECK-ENCODING: [0xb6,0xe1,0x22,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c122e1b6 <unknown>

ucvtf   {z30.s, z31.s}, {z30.s, z31.s}  // 11000001-00100010-11100011-11111110
// CHECK-INST: ucvtf   { z30.s, z31.s }, { z30.s, z31.s }
// CHECK-ENCODING: [0xfe,0xe3,0x22,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c122e3fe <unknown>


ucvtf   {z0.s - z3.s}, {z0.s - z3.s}  // 11000001-00110010-11100000-00100000
// CHECK-INST: ucvtf   { z0.s - z3.s }, { z0.s - z3.s }
// CHECK-ENCODING: [0x20,0xe0,0x32,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c132e020 <unknown>

ucvtf   {z20.s - z23.s}, {z8.s - z11.s}  // 11000001-00110010-11100001-00110100
// CHECK-INST: ucvtf   { z20.s - z23.s }, { z8.s - z11.s }
// CHECK-ENCODING: [0x34,0xe1,0x32,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c132e134 <unknown>

ucvtf   {z20.s - z23.s}, {z12.s - z15.s}  // 11000001-00110010-11100001-10110100
// CHECK-INST: ucvtf   { z20.s - z23.s }, { z12.s - z15.s }
// CHECK-ENCODING: [0xb4,0xe1,0x32,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c132e1b4 <unknown>

ucvtf   {z28.s - z31.s}, {z28.s - z31.s}  // 11000001-00110010-11100011-10111100
// CHECK-INST: ucvtf   { z28.s - z31.s }, { z28.s - z31.s }
// CHECK-ENCODING: [0xbc,0xe3,0x32,0xc1]
// CHECK-ERROR: instruction requires: sme2
// CHECK-UNKNOWN: c132e3bc <unknown>

