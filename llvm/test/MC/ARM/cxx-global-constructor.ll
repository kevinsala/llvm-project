; RUN: llc %s -mtriple=armv7-linux-gnueabi -relocation-model=pic \
; RUN: -filetype=obj -o - | llvm-readobj -r - | FileCheck %s


@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 65535, ptr @f, ptr null }]

define void @f() {
  ret void
}

; Check for a relocation of type R_ARM_TARGET1.
; CHECK: Relocations [
; CHECK:   0x{{[0-9,A-F]+}} R_ARM_TARGET1
