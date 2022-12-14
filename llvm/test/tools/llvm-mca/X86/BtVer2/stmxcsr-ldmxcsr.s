# NOTE: Assertions have been autogenerated by utils/update_mca_test_checks.py
# RUN: llvm-mca -mtriple=x86_64-unknown-unknown -mcpu=btver2 -timeline -timeline-max-iterations=3 < %s | FileCheck %s

# Code snippet taken from PR48024.

stmxcsr -4(%rsp)
movl    $-24577, %eax    # imm = 0x9FFF
andl    -4(%rsp), %eax
movl    %eax, -8(%rsp)
ldmxcsr -8(%rsp)
retq

# CHECK:      Iterations:        100
# CHECK-NEXT: Instructions:      600
# CHECK-NEXT: Total Cycles:      407
# CHECK-NEXT: Total uOps:        600

# CHECK:      Dispatch Width:    2
# CHECK-NEXT: uOps Per Cycle:    1.47
# CHECK-NEXT: IPC:               1.47
# CHECK-NEXT: Block RThroughput: 3.0

# CHECK:      Instruction Info:
# CHECK-NEXT: [1]: #uOps
# CHECK-NEXT: [2]: Latency
# CHECK-NEXT: [3]: RThroughput
# CHECK-NEXT: [4]: MayLoad
# CHECK-NEXT: [5]: MayStore
# CHECK-NEXT: [6]: HasSideEffects (U)

# CHECK:      [1]    [2]    [3]    [4]    [5]    [6]    Instructions:
# CHECK-NEXT:  1      1     1.00           *      U     stmxcsr	-4(%rsp)
# CHECK-NEXT:  1      1     0.50                        movl	$-24577, %eax
# CHECK-NEXT:  1      4     1.00    *                   andl	-4(%rsp), %eax
# CHECK-NEXT:  1      1     1.00           *            movl	%eax, -8(%rsp)
# CHECK-NEXT:  1      3     1.00    *      *      U     ldmxcsr	-8(%rsp)
# CHECK-NEXT:  1      4     1.00                  U     retq

# CHECK:      Resources:
# CHECK-NEXT: [0]   - JALU0
# CHECK-NEXT: [1]   - JALU1
# CHECK-NEXT: [2]   - JDiv
# CHECK-NEXT: [3]   - JFPA
# CHECK-NEXT: [4]   - JFPM
# CHECK-NEXT: [5]   - JFPU0
# CHECK-NEXT: [6]   - JFPU1
# CHECK-NEXT: [7]   - JLAGU
# CHECK-NEXT: [8]   - JMul
# CHECK-NEXT: [9]   - JSAGU
# CHECK-NEXT: [10]  - JSTC
# CHECK-NEXT: [11]  - JVALU0
# CHECK-NEXT: [12]  - JVALU1
# CHECK-NEXT: [13]  - JVIMUL

# CHECK:      Resource pressure per iteration:
# CHECK-NEXT: [0]    [1]    [2]    [3]    [4]    [5]    [6]    [7]    [8]    [9]    [10]   [11]   [12]   [13]
# CHECK-NEXT: 1.50   1.50    -      -      -      -      -     3.00    -     2.00    -      -      -      -

# CHECK:      Resource pressure by instruction:
# CHECK-NEXT: [0]    [1]    [2]    [3]    [4]    [5]    [6]    [7]    [8]    [9]    [10]   [11]   [12]   [13]   Instructions:
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -     1.00    -      -      -      -     stmxcsr	-4(%rsp)
# CHECK-NEXT: 0.50   0.50    -      -      -      -      -      -      -      -      -      -      -      -     movl	$-24577, %eax
# CHECK-NEXT: 0.50   0.50    -      -      -      -      -     1.00    -      -      -      -      -      -     andl	-4(%rsp), %eax
# CHECK-NEXT:  -      -      -      -      -      -      -      -      -     1.00    -      -      -      -     movl	%eax, -8(%rsp)
# CHECK-NEXT:  -      -      -      -      -      -      -     1.00    -      -      -      -      -      -     ldmxcsr	-8(%rsp)
# CHECK-NEXT: 0.50   0.50    -      -      -      -      -     1.00    -      -      -      -      -      -     retq

# CHECK:      Timeline view:
# CHECK-NEXT:                     012345678
# CHECK-NEXT: Index     0123456789

# CHECK:      [0,0]     DeER .    .    .  .   stmxcsr	-4(%rsp)
# CHECK-NEXT: [0,1]     DeER .    .    .  .   movl	$-24577, %eax
# CHECK-NEXT: [0,2]     .DeeeeER  .    .  .   andl	-4(%rsp), %eax
# CHECK-NEXT: [0,3]     .D====eER .    .  .   movl	%eax, -8(%rsp)
# CHECK-NEXT: [0,4]     . D===eeeER    .  .   ldmxcsr	-8(%rsp)
# CHECK-NEXT: [0,5]     . DeeeeE--R    .  .   retq
# CHECK-NEXT: [1,0]     .  D=====eER   .  .   stmxcsr	-4(%rsp)
# CHECK-NEXT: [1,1]     .  DeE-----R   .  .   movl	$-24577, %eax
# CHECK-NEXT: [1,2]     .   DeeeeE--R  .  .   andl	-4(%rsp), %eax
# CHECK-NEXT: [1,3]     .   D=====eER  .  .   movl	%eax, -8(%rsp)
# CHECK-NEXT: [1,4]     .    D====eeeER.  .   ldmxcsr	-8(%rsp)
# CHECK-NEXT: [1,5]     .    D=eeeeE--R.  .   retq
# CHECK-NEXT: [2,0]     .    .D======eER  .   stmxcsr	-4(%rsp)
# CHECK-NEXT: [2,1]     .    .DeE------R  .   movl	$-24577, %eax
# CHECK-NEXT: [2,2]     .    . DeeeeE---R .   andl	-4(%rsp), %eax
# CHECK-NEXT: [2,3]     .    . D======eER .   movl	%eax, -8(%rsp)
# CHECK-NEXT: [2,4]     .    .  D=====eeeER   ldmxcsr	-8(%rsp)
# CHECK-NEXT: [2,5]     .    .  DeeeeE----R   retq

# CHECK:      Average Wait times (based on the timeline view):
# CHECK-NEXT: [0]: Executions
# CHECK-NEXT: [1]: Average time spent waiting in a scheduler's queue
# CHECK-NEXT: [2]: Average time spent waiting in a scheduler's queue while ready
# CHECK-NEXT: [3]: Average time elapsed from WB until retire stage

# CHECK:            [0]    [1]    [2]    [3]
# CHECK-NEXT: 0.     3     4.7    0.3    0.0       stmxcsr	-4(%rsp)
# CHECK-NEXT: 1.     3     1.0    1.0    3.7       movl	$-24577, %eax
# CHECK-NEXT: 2.     3     1.0    1.0    1.7       andl	-4(%rsp), %eax
# CHECK-NEXT: 3.     3     6.0    0.7    0.0       movl	%eax, -8(%rsp)
# CHECK-NEXT: 4.     3     5.0    0.0    0.0       ldmxcsr	-8(%rsp)
# CHECK-NEXT: 5.     3     1.3    1.3    2.7       retq
# CHECK-NEXT:        3     3.2    0.7    1.3       <total>
