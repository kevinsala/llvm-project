; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=powerpc64le-unknown-linux-gnu -global-isel -o - \
; RUN:   -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names -verify-machineinstrs < %s | FileCheck %s

define signext i32 @load_signext_i32(ptr %ptr) {
; CHECK-LABEL: load_signext_i32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lwa r3, 0(r3)
; CHECK-NEXT:    blr
entry:
  %ret = load i32, ptr %ptr, align 4
  ret i32 %ret
}

define zeroext i32 @load_zeroext_i32(ptr %ptr) {
; CHECK-LABEL: load_zeroext_i32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lwz r3, 0(r3)
; CHECK-NEXT:    blr
entry:
  %ret = load i32, ptr %ptr, align 4
  ret i32 %ret
}

define float @load_float(ptr %ptr) {
; CHECK-LABEL: load_float:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lfs f1, 0(r3)
; CHECK-NEXT:    blr
entry:
  %ret = load float, ptr %ptr, align 4
  ret float %ret
}

define void @store_i32(ptr %p) {
; CHECK-LABEL: store_i32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    li r4, 100
; CHECK-NEXT:    stw r4, 0(r3)
; CHECK-NEXT:    blr
entry:
  store i32 100, ptr %p, align 4
  ret void
}

define void @store_float(ptr %ptr, float %a) {
; CHECK-LABEL: store_float:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stfs f1, 0(r3)
; CHECK-NEXT:    blr
entry:
  store float %a, ptr %ptr, align 4
  ret void
}
