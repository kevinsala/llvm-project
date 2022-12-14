; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=memcpyopt -S -verify-memoryssa | FileCheck %s

%struct = type { i16 }

declare i16 @g(ptr) readnone

define void @f() {
; CHECK-LABEL: @f(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CALL:%.*]] = call i16 @g(ptr byval(%struct) align 1 undef)
; CHECK-NEXT:    ret void
;
entry:
  %call = call i16 @g(ptr byval(%struct) align 1 undef)
  ret void
}
