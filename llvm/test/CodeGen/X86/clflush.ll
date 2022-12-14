; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i386-unknown-unknown -mattr=+sse2 | FileCheck %s --check-prefix=X86
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+sse2 | FileCheck %s --check-prefix=X64
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=-sse2 | FileCheck %s --check-prefix=X64

; It doesn't matter if an x86-64 target has specified "no-sse2"; we still can use clflush.

define void @clflush(ptr %p) nounwind {
; X86-LABEL: clflush:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    clflush (%eax)
; X86-NEXT:    retl
;
; X64-LABEL: clflush:
; X64:       # %bb.0:
; X64-NEXT:    clflush (%rdi)
; X64-NEXT:    retq
  tail call void @llvm.x86.sse2.clflush(ptr %p)
  ret void
}
declare void @llvm.x86.sse2.clflush(ptr) nounwind
