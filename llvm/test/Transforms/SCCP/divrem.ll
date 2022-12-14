; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=ipsccp -S < %s | FileCheck %s

define i8 @sdiv_nonneg0_nonneg1(i8 %x, i8 %y) {
; CHECK-LABEL: @sdiv_nonneg0_nonneg1(
; CHECK-NEXT:    [[PX:%.*]] = and i8 [[X:%.*]], 127
; CHECK-NEXT:    [[PY:%.*]] = lshr i8 [[Y:%.*]], 1
; CHECK-NEXT:    [[R:%.*]] = udiv i8 [[PX]], [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %px = and i8 %x, 127
  %py = lshr i8 %y, 1
  %r = sdiv i8 %px, %py
  ret i8 %r
}

define i8 @sdiv_nonnegconst0_nonneg1(i7 %y) {
; CHECK-LABEL: @sdiv_nonnegconst0_nonneg1(
; CHECK-NEXT:    [[PY:%.*]] = zext i7 [[Y:%.*]] to i8
; CHECK-NEXT:    [[R:%.*]] = udiv i8 42, [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %py = zext i7 %y to i8
  %r = sdiv i8 42, %py
  ret i8 %r
}

; TODO: This can be converted to udiv.

define i8 @sdiv_nonneg0_nonnegconst1(i8 %x) {
; CHECK-LABEL: @sdiv_nonneg0_nonnegconst1(
; CHECK-NEXT:    [[PX:%.*]] = mul nsw i8 [[X:%.*]], [[X]]
; CHECK-NEXT:    [[R:%.*]] = sdiv i8 [[PX]], 42
; CHECK-NEXT:    ret i8 [[R]]
;
  %px = mul nsw i8 %x, %x
  %r = sdiv i8 %px, 42
  ret i8 %r
}

; negative test

define i8 @sdiv_unknown0_nonneg1(i8 %x, i8 %y) {
; CHECK-LABEL: @sdiv_unknown0_nonneg1(
; CHECK-NEXT:    [[PY:%.*]] = lshr i8 [[Y:%.*]], 1
; CHECK-NEXT:    [[R:%.*]] = sdiv i8 [[X:%.*]], [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %py = lshr i8 %y, 1
  %r = sdiv i8 %x, %py
  ret i8 %r
}

; negative test

define i8 @sdiv_nonnegconst0_unknown1(i7 %y) {
; CHECK-LABEL: @sdiv_nonnegconst0_unknown1(
; CHECK-NEXT:    [[SY:%.*]] = sext i7 [[Y:%.*]] to i8
; CHECK-NEXT:    [[R:%.*]] = sdiv i8 42, [[SY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %sy = sext i7 %y to i8
  %r = sdiv i8 42, %sy
  ret i8 %r
}

; negative test - mul must be 'nsw' to be known non-negative

define i8 @sdiv_unknown0_nonnegconst1(i8 %x) {
; CHECK-LABEL: @sdiv_unknown0_nonnegconst1(
; CHECK-NEXT:    [[SX:%.*]] = mul i8 [[X:%.*]], [[X]]
; CHECK-NEXT:    [[R:%.*]] = sdiv i8 [[SX]], 42
; CHECK-NEXT:    ret i8 [[R]]
;
  %sx = mul i8 %x, %x
  %r = sdiv i8 %sx, 42
  ret i8 %r
}

define i8 @srem_nonneg0_nonneg1(i8 %x, i8 %y) {
; CHECK-LABEL: @srem_nonneg0_nonneg1(
; CHECK-NEXT:    [[PX:%.*]] = and i8 [[X:%.*]], 127
; CHECK-NEXT:    [[PY:%.*]] = lshr i8 [[Y:%.*]], 1
; CHECK-NEXT:    [[R:%.*]] = urem i8 [[PX]], [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %px = and i8 %x, 127
  %py = lshr i8 %y, 1
  %r = srem i8 %px, %py
  ret i8 %r
}

define i8 @srem_nonnegconst0_nonneg1(i8 %y) {
; CHECK-LABEL: @srem_nonnegconst0_nonneg1(
; CHECK-NEXT:    [[PY:%.*]] = and i8 [[Y:%.*]], 127
; CHECK-NEXT:    [[R:%.*]] = urem i8 42, [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %py = and i8 %y, 127
  %r = srem i8 42, %py
  ret i8 %r
}

define i8 @srem_nonneg0_nonnegconst1(i7 %x) {
; CHECK-LABEL: @srem_nonneg0_nonnegconst1(
; CHECK-NEXT:    [[PX:%.*]] = zext i7 [[X:%.*]] to i8
; CHECK-NEXT:    [[R:%.*]] = urem i8 [[PX]], 42
; CHECK-NEXT:    ret i8 [[R]]
;
  %px = zext i7 %x to i8
  %r = srem i8 %px, 42
  ret i8 %r
}

; negative test

define i8 @srem_unknown0_nonneg1(i8 %x, i8 %y) {
; CHECK-LABEL: @srem_unknown0_nonneg1(
; CHECK-NEXT:    [[PY:%.*]] = lshr i8 [[Y:%.*]], 1
; CHECK-NEXT:    [[R:%.*]] = srem i8 [[X:%.*]], [[PY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %py = lshr i8 %y, 1
  %r = srem i8 %x, %py
  ret i8 %r
}

; negative test

define i8 @srem_nonnegconst0_unknown1(i7 %y) {
; CHECK-LABEL: @srem_nonnegconst0_unknown1(
; CHECK-NEXT:    [[SY:%.*]] = sext i7 [[Y:%.*]] to i8
; CHECK-NEXT:    [[R:%.*]] = srem i8 42, [[SY]]
; CHECK-NEXT:    ret i8 [[R]]
;
  %sy = sext i7 %y to i8
  %r = srem i8 42, %sy
  ret i8 %r
}

; negative test - mul must be 'nsw' to be known non-negative

define i8 @srem_unknown0_nonnegconst1(i8 %x) {
; CHECK-LABEL: @srem_unknown0_nonnegconst1(
; CHECK-NEXT:    [[SX:%.*]] = mul i8 [[X:%.*]], [[X]]
; CHECK-NEXT:    [[R:%.*]] = srem i8 [[SX]], 42
; CHECK-NEXT:    ret i8 [[R]]
;
  %sx = mul i8 %x, %x
  %r = srem i8 %sx, 42
  ret i8 %r
}

; x is known non-negative in t block

define i32 @PR57472(i32 %x) {
; CHECK-LABEL: @PR57472(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP:%.*]] = icmp sge i32 [[X:%.*]], 0
; CHECK-NEXT:    br i1 [[CMP]], label [[T:%.*]], label [[F:%.*]]
; CHECK:       t:
; CHECK-NEXT:    [[REM:%.*]] = urem i32 [[X]], 16
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       f:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    [[COND:%.*]] = phi i32 [ [[REM]], [[T]] ], [ 42, [[F]] ]
; CHECK-NEXT:    ret i32 [[COND]]
;
entry:
  %cmp = icmp sge i32 %x, 0
  br i1 %cmp, label %t, label %f

t:
  %rem = srem i32 %x, 16
  br label %exit

f:
  br label %exit

exit:
  %cond = phi i32 [ %rem, %t ], [ 42, %f ]
  ret i32 %cond
}

; x is known non-negative in f block

define i32 @PR57472_alt(i32 %x) {
; CHECK-LABEL: @PR57472_alt(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[X:%.*]], 2000000000
; CHECK-NEXT:    br i1 [[CMP]], label [[T:%.*]], label [[F:%.*]]
; CHECK:       t:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       f:
; CHECK-NEXT:    [[DIV:%.*]] = udiv i32 16, [[X]]
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    [[COND:%.*]] = phi i32 [ -42, [[T]] ], [ [[DIV]], [[F]] ]
; CHECK-NEXT:    ret i32 [[COND]]
;
entry:
  %cmp = icmp ugt i32 %x, 2000000000
  br i1 %cmp, label %t, label %f

t:
  br label %exit

f:
  %div = sdiv i32 16, %x
  br label %exit

exit:
  %cond = phi i32 [ -42, %t ], [ %div, %f ]
  ret i32 %cond
}
