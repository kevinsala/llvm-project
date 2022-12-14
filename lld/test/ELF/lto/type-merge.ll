; REQUIRES: x86
; RUN: llvm-as %s -o %t.o
; RUN: llvm-as %p/Inputs/type-merge.ll -o %t2.o
; RUN: ld.lld %t.o %t2.o -o %t -shared -save-temps
; RUN: llvm-dis < %t.0.0.preopt.bc | FileCheck %s

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define void @foo()  {
  call void @bar(ptr null)
  ret void
}
declare void @bar(ptr)

; CHECK:      define void @foo() {
; CHECK-NEXT:   call void @bar(ptr null)
; CHECK-NEXT:   ret void
; CHECK-NEXT: }

; CHECK: declare void @bar(ptr)

; CHECK:      define void @zed() {
; CHECK-NEXT:   call void @bar()
; CHECK-NEXT:   ret void
; CHECK-NEXT: }
