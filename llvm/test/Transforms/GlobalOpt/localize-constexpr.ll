; RUN: opt -S < %s -passes=globalopt | FileCheck %s

@G = internal global i32 42

define i8 @f() norecurse {
; CHECK-LABEL: @f
; CHECK: alloca
; CHECK-NOT: @G
; CHECK: }
  store i32 42, ptr @G
  %a = load i8, ptr @G
  ret i8 %a
}

@H = internal global i32 42
@Halias = alias i32, ptr @H

; @H can't be localized because @Halias uses it, and @Halias can't be converted to an instruction.
define i8 @g() norecurse {
; CHECK-LABEL: @g
; CHECK-NOT: alloca
; CHECK: @H
; CHECK: }
  store i32 42, ptr @H
  %a = load i8, ptr @H
  ret i8 %a
}

