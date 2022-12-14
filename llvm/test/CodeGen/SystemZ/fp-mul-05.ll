; Test multiplication of two f128s.
;
; RUN: llc < %s -mtriple=s390x-linux-gnu | FileCheck %s

; There is no memory form of 128-bit multiplication.
define void @f1(ptr %ptr, float %f2) {
; CHECK-LABEL: f1:
; CHECK-DAG: lxebr %f0, %f0
; CHECK-DAG: ld %f1, 0(%r2)
; CHECK-DAG: ld %f3, 8(%r2)
; CHECK: mxbr %f0, %f1
; CHECK: std %f0, 0(%r2)
; CHECK: std %f2, 8(%r2)
; CHECK: br %r14
  %f1 = load fp128, ptr %ptr
  %f2x = fpext float %f2 to fp128
  %diff = fmul fp128 %f1, %f2x
  store fp128 %diff, ptr %ptr
  ret void
}
