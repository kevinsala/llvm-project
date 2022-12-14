# NOTE: Assertions have been autogenerated by utils/update_mca_test_checks.py
# RUN: llvm-mca -mtriple=x86_64-unknown-unknown -mcpu=x86-64 -instruction-tables < %s | FileCheck %s

vcvtne2ps2bf16   %xmm16, %xmm17, %xmm19
vcvtne2ps2bf16   (%rax), %xmm17, %xmm19
vcvtne2ps2bf16   (%rax){1to4}, %xmm17, %xmm19
vcvtne2ps2bf16   %xmm16, %xmm17, %xmm19 {k1}
vcvtne2ps2bf16   (%rax), %xmm17, %xmm19 {k1}
vcvtne2ps2bf16   (%rax){1to4}, %xmm17, %xmm19 {k1}
vcvtne2ps2bf16   %xmm16, %xmm17, %xmm19 {k1}{z}
vcvtne2ps2bf16   (%rax), %xmm17, %xmm19 {k1}{z}
vcvtne2ps2bf16   (%rax){1to4}, %xmm17, %xmm19 {k1}{z}

vcvtne2ps2bf16   %ymm16, %ymm17, %ymm19
vcvtne2ps2bf16   (%rax), %ymm17, %ymm19
vcvtne2ps2bf16   (%rax){1to8}, %ymm17, %ymm19
vcvtne2ps2bf16   %ymm16, %ymm17, %ymm19 {k1}
vcvtne2ps2bf16   (%rax), %ymm17, %ymm19 {k1}
vcvtne2ps2bf16   (%rax){1to8}, %ymm17, %ymm19 {k1}
vcvtne2ps2bf16   %ymm16, %ymm17, %ymm19 {k1}{z}
vcvtne2ps2bf16   (%rax), %ymm17, %ymm19 {k1}{z}
vcvtne2ps2bf16   (%rax){1to8}, %ymm17, %ymm19 {k1}{z}

vcvtneps2bf16x   %xmm16, %xmm19
vcvtneps2bf16x   (%rax), %xmm19
vcvtneps2bf16    (%rax){1to4}, %xmm19
vcvtneps2bf16    %xmm16, %xmm19 {k1}
vcvtneps2bf16x   (%rax), %xmm19 {k1}
vcvtneps2bf16    (%rax){1to4}, %xmm19 {k1}
vcvtneps2bf16    %xmm16, %xmm19 {k1}{z}
vcvtneps2bf16x   (%rax), %xmm19 {k1}{z}
vcvtneps2bf16    (%rax){1to4}, %xmm19 {k1}{z}

vcvtneps2bf16    %ymm16, %xmm19
vcvtneps2bf16y   (%rax), %xmm19
vcvtneps2bf16    (%rax){1to8}, %xmm19
vcvtneps2bf16    %ymm16, %xmm19 {k1}
vcvtneps2bf16y   (%rax), %xmm19 {k1}
vcvtneps2bf16    (%rax){1to8}, %xmm19 {k1}
vcvtneps2bf16    %ymm16, %xmm19 {k1}{z}
vcvtneps2bf16y   (%rax), %xmm19 {k1}{z}
vcvtneps2bf16    (%rax){1to8}, %xmm19 {k1}{z}

vdpbf16ps        %xmm16, %xmm17, %xmm19
vdpbf16ps        (%rax), %xmm17, %xmm19
vdpbf16ps        (%rax){1to4}, %xmm17, %xmm19
vdpbf16ps        %xmm16, %xmm17, %xmm19 {k1}
vdpbf16ps        (%rax), %xmm17, %xmm19 {k1}
vdpbf16ps        (%rax){1to4}, %xmm17, %xmm19 {k1}
vdpbf16ps        %xmm16, %xmm17, %xmm19 {k1}{z}
vdpbf16ps        (%rax), %xmm17, %xmm19 {k1}{z}
vdpbf16ps        (%rax){1to4}, %xmm17, %xmm19 {k1}{z}

vdpbf16ps        %ymm16, %ymm17, %ymm19
vdpbf16ps        (%rax), %ymm17, %ymm19
vdpbf16ps        (%rax){1to8}, %ymm17, %ymm19
vdpbf16ps        %ymm16, %ymm17, %ymm19 {k1}
vdpbf16ps        (%rax), %ymm17, %ymm19 {k1}
vdpbf16ps        (%rax){1to8}, %ymm17, %ymm19 {k1}
vdpbf16ps        %ymm16, %ymm17, %ymm19 {k1}{z}
vdpbf16ps        (%rax), %ymm17, %ymm19 {k1}{z}
vdpbf16ps        (%rax){1to8}, %ymm17, %ymm19 {k1}{z}

# CHECK:      Instruction Info:
# CHECK-NEXT: [1]: #uOps
# CHECK-NEXT: [2]: Latency
# CHECK-NEXT: [3]: RThroughput
# CHECK-NEXT: [4]: MayLoad
# CHECK-NEXT: [5]: MayStore
# CHECK-NEXT: [6]: HasSideEffects (U)

# CHECK:      [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  3      10    1.00    *                   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  2      4     1.00                        vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  3      11    1.00    *                   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%xmm16, %xmm19
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16x	(%rax), %xmm19
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16	(%rax){1to4}, %xmm19
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%xmm16, %xmm19 {%k1}
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16x	(%rax), %xmm19 {%k1}
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16	(%rax){1to4}, %xmm19 {%k1}
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%xmm16, %xmm19 {%k1} {z}
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16x	(%rax), %xmm19 {%k1} {z}
# CHECK-NEXT:  3      10    1.00    *                   vcvtneps2bf16	(%rax){1to4}, %xmm19 {%k1} {z}
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%ymm16, %xmm19
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16y	(%rax), %xmm19
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16	(%rax){1to8}, %xmm19
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%ymm16, %xmm19 {%k1}
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16y	(%rax), %xmm19 {%k1}
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16	(%rax){1to8}, %xmm19 {%k1}
# CHECK-NEXT:  2      4     1.00                        vcvtneps2bf16	%ymm16, %xmm19 {%k1} {z}
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16y	(%rax), %xmm19 {%k1} {z}
# CHECK-NEXT:  3      11    1.00    *                   vcvtneps2bf16	(%rax){1to8}, %xmm19 {%k1} {z}
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%xmm16, %xmm17, %xmm19
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %xmm17, %xmm19
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%xmm16, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%xmm16, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%ymm16, %ymm17, %ymm19
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %ymm17, %ymm19
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%ymm16, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  1      5     0.50                        vdpbf16ps	%ymm16, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax), %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  2      10    0.50    *                   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19 {%k1} {z}

# CHECK:      Resources:
# CHECK-NEXT: [0]   - SBDivider
# CHECK-NEXT: [1]   - SBFPDivider
# CHECK-NEXT: [2]   - SBPort0
# CHECK-NEXT: [3]   - SBPort1
# CHECK-NEXT: [4]   - SBPort4
# CHECK-NEXT: [5]   - SBPort5
# CHECK-NEXT: [6.0] - SBPort23
# CHECK-NEXT: [6.1] - SBPort23

# CHECK:      Resource pressure per iteration:
# CHECK-NEXT: [0]    [1]    [2]    [3]    [4]    [5]    [6.0]  [6.1]
# CHECK-NEXT:  -      -     9.00   45.00   -     36.00  18.00  18.00

# CHECK:      Resource pressure by instruction:
# CHECK-NEXT: [0]    [1]    [2]    [3]    [4]    [5]    [6.0]  [6.1]  Instructions:
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%xmm16, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to4}, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtne2ps2bf16	%ymm16, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax), %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtne2ps2bf16	(%rax){1to8}, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%xmm16, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16x	(%rax), %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to4}, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%xmm16, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16x	(%rax), %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to4}, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%xmm16, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16x	(%rax), %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to4}, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%ymm16, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16y	(%rax), %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to8}, %xmm19
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%ymm16, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16y	(%rax), %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to8}, %xmm19 {%k1}
# CHECK-NEXT:  -      -      -     1.00    -     1.00    -      -     vcvtneps2bf16	%ymm16, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16y	(%rax), %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -      -     1.00    -     1.00   0.50   0.50   vcvtneps2bf16	(%rax){1to8}, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%xmm16, %xmm17, %xmm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %xmm17, %xmm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%xmm16, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%xmm16, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to4}, %xmm17, %xmm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%ymm16, %ymm17, %ymm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %ymm17, %ymm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%ymm16, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19 {%k1}
# CHECK-NEXT:  -      -     0.50   0.50    -      -      -      -     vdpbf16ps	%ymm16, %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax), %ymm17, %ymm19 {%k1} {z}
# CHECK-NEXT:  -      -     0.50   0.50    -      -     0.50   0.50   vdpbf16ps	(%rax){1to8}, %ymm17, %ymm19 {%k1} {z}
