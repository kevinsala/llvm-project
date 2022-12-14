; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -passes=instcombine %s | FileCheck %s

declare void @add_byval_callee(ptr)

declare void @add_byval_callee_2(ptr byval(double))

define void @add_byval(ptr %in) {
; CHECK-LABEL: @add_byval(
; CHECK-NEXT:    call void @add_byval_callee(ptr byval(i64) [[IN:%.*]])
; CHECK-NEXT:    ret void
;
  call void @add_byval_callee(ptr byval(i64) %in)
  ret void
}

define void @add_byval_2(ptr %in) {
; CHECK-LABEL: @add_byval_2(
; CHECK-NEXT:    call void @add_byval_callee_2(ptr byval(i64) [[IN:%.*]])
; CHECK-NEXT:    ret void
;
  call void @add_byval_callee_2(ptr byval(i64) %in)
  ret void
}

%t2 = type { i8 }

define void @vararg_byval(ptr %p) {
; CHECK-LABEL: @vararg_byval(
; CHECK-NEXT:    call void (i8, ...) @vararg_callee(i8 undef, ptr byval([[T2:%.*]]) [[P:%.*]])
; CHECK-NEXT:    ret void
;
  call void (i8, ...) @vararg_callee(i8 undef, ptr byval(%t2) %p)
  ret void
}

declare void @vararg_callee(i8, ...)
