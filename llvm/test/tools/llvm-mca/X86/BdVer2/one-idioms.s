# NOTE: Assertions have been autogenerated by utils/update_mca_test_checks.py
# RUN: llvm-mca -mtriple=x86_64-unknown-unknown -mcpu=bdver2 -timeline -timeline-max-iterations=1 -register-file-stats < %s | FileCheck %s

# These are dependency-breaking one-idioms.
# Much like zero-idioms, but they produce ones, and do consume resources.

# perf stats reports a throughput of 2.00 IPC.

pcmpeqb   %mm2, %mm2
pcmpeqd   %mm2, %mm2
pcmpeqw   %mm2, %mm2

pcmpeqb   %xmm2, %xmm2
pcmpeqd   %xmm2, %xmm2
pcmpeqq   %xmm2, %xmm2
pcmpeqw   %xmm2, %xmm2

vpcmpeqb  %xmm3, %xmm3, %xmm3
vpcmpeqd  %xmm3, %xmm3, %xmm3
vpcmpeqq  %xmm3, %xmm3, %xmm3
vpcmpeqw  %xmm3, %xmm3, %xmm3

vpcmpeqb  %xmm3, %xmm3, %xmm5
vpcmpeqd  %xmm3, %xmm3, %xmm5
vpcmpeqq  %xmm3, %xmm3, %xmm5
vpcmpeqw  %xmm3, %xmm3, %xmm5

# FIXME: their handling is broken in llvm-mca.

# CHECK:      Iterations:        100
# CHECK-NEXT: Instructions:      1500
# CHECK-NEXT: Total Cycles:      754
# CHECK-NEXT: Total uOps:        1500

# CHECK:      Dispatch Width:    4
# CHECK-NEXT: uOps Per Cycle:    1.99
# CHECK-NEXT: IPC:               1.99
# CHECK-NEXT: Block RThroughput: 7.5

# CHECK:      Instruction Info:
# CHECK-NEXT: [1]: #uOps
# CHECK-NEXT: [2]: Latency
# CHECK-NEXT: [3]: RThroughput
# CHECK-NEXT: [4]: MayLoad
# CHECK-NEXT: [5]: MayStore
# CHECK-NEXT: [6]: HasSideEffects (U)

# CHECK:      [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
# CHECK-NEXT:  1      2     0.50                        pcmpeqb	%mm2, %mm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqd	%mm2, %mm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqw	%mm2, %mm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqb	%xmm2, %xmm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqd	%xmm2, %xmm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqq	%xmm2, %xmm2
# CHECK-NEXT:  1      2     0.50                        pcmpeqw	%xmm2, %xmm2
# CHECK-NEXT:  1      2     0.50                        vpcmpeqb	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  1      2     0.50                        vpcmpeqd	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  1      2     0.50                        vpcmpeqq	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  1      2     0.50                        vpcmpeqw	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  1      2     0.50                        vpcmpeqb	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  1      2     0.50                        vpcmpeqd	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  1      2     0.50                        vpcmpeqq	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  1      2     0.50                        vpcmpeqw	%xmm3, %xmm3, %xmm5

# CHECK:      Register File statistics:
# CHECK-NEXT: Total number of mappings created:    1500
# CHECK-NEXT: Max number of mappings used:         72

# CHECK:      *  Register File #1 -- PdFpuPRF:
# CHECK-NEXT:    Number of physical registers:     160
# CHECK-NEXT:    Total number of mappings created: 1500
# CHECK-NEXT:    Max number of mappings used:      72

# CHECK:      *  Register File #2 -- PdIntegerPRF:
# CHECK-NEXT:    Number of physical registers:     96
# CHECK-NEXT:    Total number of mappings created: 0
# CHECK-NEXT:    Max number of mappings used:      0

# CHECK:      Resources:
# CHECK-NEXT: [0.0] - PdAGLU01
# CHECK-NEXT: [0.1] - PdAGLU01
# CHECK-NEXT: [1]   - PdBranch
# CHECK-NEXT: [2]   - PdCount
# CHECK-NEXT: [3]   - PdDiv
# CHECK-NEXT: [4]   - PdEX0
# CHECK-NEXT: [5]   - PdEX1
# CHECK-NEXT: [6]   - PdFPCVT
# CHECK-NEXT: [7.0] - PdFPFMA
# CHECK-NEXT: [7.1] - PdFPFMA
# CHECK-NEXT: [8.0] - PdFPMAL
# CHECK-NEXT: [8.1] - PdFPMAL
# CHECK-NEXT: [9]   - PdFPMMA
# CHECK-NEXT: [10]  - PdFPSTO
# CHECK-NEXT: [11]  - PdFPU0
# CHECK-NEXT: [12]  - PdFPU1
# CHECK-NEXT: [13]  - PdFPU2
# CHECK-NEXT: [14]  - PdFPU3
# CHECK-NEXT: [15]  - PdFPXBR
# CHECK-NEXT: [16.0] - PdLoad
# CHECK-NEXT: [16.1] - PdLoad
# CHECK-NEXT: [17]  - PdMul
# CHECK-NEXT: [18]  - PdStore

# CHECK:      Resource pressure per iteration:
# CHECK-NEXT: [0.0]  [0.1]  [1]    [2]    [3]    [4]    [5]    [6]    [7.0]  [7.1]  [8.0]  [8.1]  [9]    [10]   [11]   [12]   [13]   [14]   [15]   [16.0] [16.1] [17]   [18]
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     7.50   7.50    -      -      -      -     7.50   7.50    -      -      -      -      -

# CHECK:      Resource pressure by instruction:
# CHECK-NEXT: [0.0]  [0.1]  [1]    [2]    [3]    [4]    [5]    [6]    [7.0]  [7.1]  [8.0]  [8.1]  [9]    [10]   [11]   [12]   [13]   [14]   [15]   [16.0] [16.1] [17]   [18]   Instructions:
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqb	%mm2, %mm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqd	%mm2, %mm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqw	%mm2, %mm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqb	%xmm2, %xmm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqd	%xmm2, %xmm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -      -     1.00    -      -      -      -      -     1.00    -      -      -      -      -     pcmpeqq	%xmm2, %xmm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     pcmpeqw	%xmm2, %xmm2
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqb	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     1.00    -      -      -      -      -     1.00    -      -      -      -      -      -     vpcmpeqd	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqq	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqw	%xmm3, %xmm3, %xmm3
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqb	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqd	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqq	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -      -     0.50   0.50    -      -      -      -     0.50   0.50    -      -      -      -      -     vpcmpeqw	%xmm3, %xmm3, %xmm5

# CHECK:      Timeline view:
# CHECK-NEXT:                     01
# CHECK-NEXT: Index     0123456789

# CHECK:      [0,0]     DeeER.    ..   pcmpeqb	%mm2, %mm2
# CHECK-NEXT: [0,1]     DeeER.    ..   pcmpeqd	%mm2, %mm2
# CHECK-NEXT: [0,2]     D=eeER    ..   pcmpeqw	%mm2, %mm2
# CHECK-NEXT: [0,3]     D==eeER   ..   pcmpeqb	%xmm2, %xmm2
# CHECK-NEXT: [0,4]     .DeeE-R   ..   pcmpeqd	%xmm2, %xmm2
# CHECK-NEXT: [0,5]     .D==eeER  ..   pcmpeqq	%xmm2, %xmm2
# CHECK-NEXT: [0,6]     .D=eeE-R  ..   pcmpeqw	%xmm2, %xmm2
# CHECK-NEXT: [0,7]     .D===eeER ..   vpcmpeqb	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: [0,8]     . D=eeE-R ..   vpcmpeqd	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: [0,9]     . D===eeER..   vpcmpeqq	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: [0,10]    . D==eeE-R..   vpcmpeqw	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: [0,11]    . D===eeER..   vpcmpeqb	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: [0,12]    .  D===eeER.   vpcmpeqd	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: [0,13]    .  D===eeER.   vpcmpeqq	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: [0,14]    .  D====eeER   vpcmpeqw	%xmm3, %xmm3, %xmm5

# CHECK:      Average Wait times (based on the timeline view):
# CHECK-NEXT: [0]: Executions
# CHECK-NEXT: [1]: Average time spent waiting in a scheduler's queue
# CHECK-NEXT: [2]: Average time spent waiting in a scheduler's queue while ready
# CHECK-NEXT: [3]: Average time elapsed from WB until retire stage

# CHECK:            [0]    [1]    [2]    [3]
# CHECK-NEXT: 0.     1     1.0    1.0    0.0       pcmpeqb	%mm2, %mm2
# CHECK-NEXT: 1.     1     1.0    1.0    0.0       pcmpeqd	%mm2, %mm2
# CHECK-NEXT: 2.     1     2.0    2.0    0.0       pcmpeqw	%mm2, %mm2
# CHECK-NEXT: 3.     1     3.0    3.0    0.0       pcmpeqb	%xmm2, %xmm2
# CHECK-NEXT: 4.     1     1.0    1.0    1.0       pcmpeqd	%xmm2, %xmm2
# CHECK-NEXT: 5.     1     3.0    0.0    0.0       pcmpeqq	%xmm2, %xmm2
# CHECK-NEXT: 6.     1     2.0    2.0    1.0       pcmpeqw	%xmm2, %xmm2
# CHECK-NEXT: 7.     1     4.0    4.0    0.0       vpcmpeqb	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: 8.     1     2.0    2.0    1.0       vpcmpeqd	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: 9.     1     4.0    0.0    0.0       vpcmpeqq	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: 10.    1     3.0    3.0    1.0       vpcmpeqw	%xmm3, %xmm3, %xmm3
# CHECK-NEXT: 11.    1     4.0    4.0    0.0       vpcmpeqb	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: 12.    1     4.0    4.0    0.0       vpcmpeqd	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: 13.    1     4.0    0.0    0.0       vpcmpeqq	%xmm3, %xmm3, %xmm5
# CHECK-NEXT: 14.    1     5.0    5.0    0.0       vpcmpeqw	%xmm3, %xmm3, %xmm5
# CHECK-NEXT:        1     2.9    2.1    0.3       <total>
