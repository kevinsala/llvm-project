; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=i686-unknown-linux-gnu < %s | FileCheck %s --check-prefix=X86
; RUN: llc -mtriple=x86_64-unknown-linux-gnu < %s | FileCheck %s --check-prefix=X64

define i1 @t32_3_1(i32 %X) nounwind {
; X86-LABEL: t32_3_1:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $1431655765, %eax # imm = 0x55555555
; X86-NEXT:    cmpl $1431655765, %eax # imm = 0x55555555
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_3_1:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $1431655765, %eax # imm = 0x55555555
; X64-NEXT:    cmpl $1431655765, %eax # imm = 0x55555555
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 3
  %cmp = icmp eq i32 %urem, 1
  ret i1 %cmp
}

define i1 @t32_3_2(i32 %X) nounwind {
; X86-LABEL: t32_3_2:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $-1431655766, %eax # imm = 0xAAAAAAAA
; X86-NEXT:    cmpl $1431655765, %eax # imm = 0x55555555
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_3_2:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $-1431655766, %eax # imm = 0xAAAAAAAA
; X64-NEXT:    cmpl $1431655765, %eax # imm = 0x55555555
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 3
  %cmp = icmp eq i32 %urem, 2
  ret i1 %cmp
}


define i1 @t32_5_1(i32 %X) nounwind {
; X86-LABEL: t32_5_1:
; X86:       # %bb.0:
; X86-NEXT:    imull $-858993459, {{[0-9]+}}(%esp), %eax # imm = 0xCCCCCCCD
; X86-NEXT:    addl $858993459, %eax # imm = 0x33333333
; X86-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_5_1:
; X64:       # %bb.0:
; X64-NEXT:    imull $-858993459, %edi, %eax # imm = 0xCCCCCCCD
; X64-NEXT:    addl $858993459, %eax # imm = 0x33333333
; X64-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 5
  %cmp = icmp eq i32 %urem, 1
  ret i1 %cmp
}

define i1 @t32_5_2(i32 %X) nounwind {
; X86-LABEL: t32_5_2:
; X86:       # %bb.0:
; X86-NEXT:    imull $-858993459, {{[0-9]+}}(%esp), %eax # imm = 0xCCCCCCCD
; X86-NEXT:    addl $1717986918, %eax # imm = 0x66666666
; X86-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_5_2:
; X64:       # %bb.0:
; X64-NEXT:    imull $-858993459, %edi, %eax # imm = 0xCCCCCCCD
; X64-NEXT:    addl $1717986918, %eax # imm = 0x66666666
; X64-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 5
  %cmp = icmp eq i32 %urem, 2
  ret i1 %cmp
}

define i1 @t32_5_3(i32 %X) nounwind {
; X86-LABEL: t32_5_3:
; X86:       # %bb.0:
; X86-NEXT:    imull $-858993459, {{[0-9]+}}(%esp), %eax # imm = 0xCCCCCCCD
; X86-NEXT:    addl $-1717986919, %eax # imm = 0x99999999
; X86-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_5_3:
; X64:       # %bb.0:
; X64-NEXT:    imull $-858993459, %edi, %eax # imm = 0xCCCCCCCD
; X64-NEXT:    addl $-1717986919, %eax # imm = 0x99999999
; X64-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 5
  %cmp = icmp eq i32 %urem, 3
  ret i1 %cmp
}

define i1 @t32_5_4(i32 %X) nounwind {
; X86-LABEL: t32_5_4:
; X86:       # %bb.0:
; X86-NEXT:    imull $-858993459, {{[0-9]+}}(%esp), %eax # imm = 0xCCCCCCCD
; X86-NEXT:    addl $-858993460, %eax # imm = 0xCCCCCCCC
; X86-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_5_4:
; X64:       # %bb.0:
; X64-NEXT:    imull $-858993459, %edi, %eax # imm = 0xCCCCCCCD
; X64-NEXT:    addl $-858993460, %eax # imm = 0xCCCCCCCC
; X64-NEXT:    cmpl $858993459, %eax # imm = 0x33333333
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 5
  %cmp = icmp eq i32 %urem, 4
  ret i1 %cmp
}


define i1 @t32_6_1(i32 %X) nounwind {
; X86-LABEL: t32_6_1:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $1431655765, %eax # imm = 0x55555555
; X86-NEXT:    rorl %eax
; X86-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_6_1:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $1431655765, %eax # imm = 0x55555555
; X64-NEXT:    rorl %eax
; X64-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 6
  %cmp = icmp eq i32 %urem, 1
  ret i1 %cmp
}

define i1 @t32_6_2(i32 %X) nounwind {
; X86-LABEL: t32_6_2:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $-1431655766, %eax # imm = 0xAAAAAAAA
; X86-NEXT:    rorl %eax
; X86-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_6_2:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $-1431655766, %eax # imm = 0xAAAAAAAA
; X64-NEXT:    rorl %eax
; X64-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 6
  %cmp = icmp eq i32 %urem, 2
  ret i1 %cmp
}

define i1 @t32_6_3(i32 %X) nounwind {
; X86-LABEL: t32_6_3:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    decl %eax
; X86-NEXT:    rorl %eax
; X86-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_6_3:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    decl %eax
; X64-NEXT:    rorl %eax
; X64-NEXT:    cmpl $715827883, %eax # imm = 0x2AAAAAAB
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 6
  %cmp = icmp eq i32 %urem, 3
  ret i1 %cmp
}

define i1 @t32_6_4(i32 %X) nounwind {
; X86-LABEL: t32_6_4:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $1431655764, %eax # imm = 0x55555554
; X86-NEXT:    rorl %eax
; X86-NEXT:    cmpl $715827882, %eax # imm = 0x2AAAAAAA
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_6_4:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $1431655764, %eax # imm = 0x55555554
; X64-NEXT:    rorl %eax
; X64-NEXT:    cmpl $715827882, %eax # imm = 0x2AAAAAAA
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 6
  %cmp = icmp eq i32 %urem, 4
  ret i1 %cmp
}

define i1 @t32_6_5(i32 %X) nounwind {
; X86-LABEL: t32_6_5:
; X86:       # %bb.0:
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %eax # imm = 0xAAAAAAAB
; X86-NEXT:    addl $-1431655767, %eax # imm = 0xAAAAAAA9
; X86-NEXT:    rorl %eax
; X86-NEXT:    cmpl $715827882, %eax # imm = 0x2AAAAAAA
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t32_6_5:
; X64:       # %bb.0:
; X64-NEXT:    imull $-1431655765, %edi, %eax # imm = 0xAAAAAAAB
; X64-NEXT:    addl $-1431655767, %eax # imm = 0xAAAAAAA9
; X64-NEXT:    rorl %eax
; X64-NEXT:    cmpl $715827882, %eax # imm = 0x2AAAAAAA
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i32 %X, 6
  %cmp = icmp eq i32 %urem, 5
  ret i1 %cmp
}

;-------------------------------------------------------------------------------
; Other widths.

define i1 @t16_3_2(i16 %X) nounwind {
; X86-LABEL: t16_3_2:
; X86:       # %bb.0:
; X86-NEXT:    imull $-21845, {{[0-9]+}}(%esp), %eax # imm = 0xAAAB
; X86-NEXT:    addl $-21846, %eax # imm = 0xAAAA
; X86-NEXT:    movzwl %ax, %eax
; X86-NEXT:    cmpl $21845, %eax # imm = 0x5555
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t16_3_2:
; X64:       # %bb.0:
; X64-NEXT:    imull $-21845, %edi, %eax # imm = 0xAAAB
; X64-NEXT:    addl $-21846, %eax # imm = 0xAAAA
; X64-NEXT:    movzwl %ax, %eax
; X64-NEXT:    cmpl $21845, %eax # imm = 0x5555
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i16 %X, 3
  %cmp = icmp eq i16 %urem, 2
  ret i1 %cmp
}

define i1 @t8_3_2(i8 %X) nounwind {
; X86-LABEL: t8_3_2:
; X86:       # %bb.0:
; X86-NEXT:    imull $-85, {{[0-9]+}}(%esp), %eax
; X86-NEXT:    addb $-86, %al
; X86-NEXT:    cmpb $85, %al
; X86-NEXT:    setb %al
; X86-NEXT:    retl
;
; X64-LABEL: t8_3_2:
; X64:       # %bb.0:
; X64-NEXT:    imull $-85, %edi, %eax
; X64-NEXT:    addb $-86, %al
; X64-NEXT:    cmpb $85, %al
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i8 %X, 3
  %cmp = icmp eq i8 %urem, 2
  ret i1 %cmp
}

define i1 @t64_3_2(i64 %X) nounwind {
; X86-LABEL: t64_3_2:
; X86:       # %bb.0:
; X86-NEXT:    pushl %esi
; X86-NEXT:    movl {{[0-9]+}}(%esp), %ecx
; X86-NEXT:    movl $-1431655765, %edx # imm = 0xAAAAAAAB
; X86-NEXT:    movl %ecx, %eax
; X86-NEXT:    mull %edx
; X86-NEXT:    imull $-1431655766, %ecx, %ecx # imm = 0xAAAAAAAA
; X86-NEXT:    imull $-1431655765, {{[0-9]+}}(%esp), %esi # imm = 0xAAAAAAAB
; X86-NEXT:    addl %ecx, %esi
; X86-NEXT:    addl %edx, %esi
; X86-NEXT:    addl $-1431655766, %eax # imm = 0xAAAAAAAA
; X86-NEXT:    adcl $-1431655766, %esi # imm = 0xAAAAAAAA
; X86-NEXT:    cmpl $1431655765, %eax # imm = 0x55555555
; X86-NEXT:    sbbl $1431655765, %esi # imm = 0x55555555
; X86-NEXT:    setb %al
; X86-NEXT:    popl %esi
; X86-NEXT:    retl
;
; X64-LABEL: t64_3_2:
; X64:       # %bb.0:
; X64-NEXT:    movabsq $-6148914691236517205, %rax # imm = 0xAAAAAAAAAAAAAAAB
; X64-NEXT:    imulq %rdi, %rax
; X64-NEXT:    movabsq $-6148914691236517206, %rcx # imm = 0xAAAAAAAAAAAAAAAA
; X64-NEXT:    addq %rax, %rcx
; X64-NEXT:    movabsq $6148914691236517205, %rax # imm = 0x5555555555555555
; X64-NEXT:    cmpq %rax, %rcx
; X64-NEXT:    setb %al
; X64-NEXT:    retq
  %urem = urem i64 %X, 3
  %cmp = icmp eq i64 %urem, 2
  ret i1 %cmp
}
