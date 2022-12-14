; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -S -passes=loop-unroll -mtriple aarch64 | FileCheck %s

; Below loop's trip count is not constant and it blocks to unroll the loop.
; After setting up `UP.UpperBound = true` in `getUnrollingPreferences`,
; the loop should be unrolled.

define void @test(i1 %cond) {
; CHECK-LABEL: @test(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    switch i32 0, label [[SW_DEFAULT:%.*]] [
; CHECK-NEXT:    i32 2, label [[LATCH:%.*]]
; CHECK-NEXT:    ]
; CHECK:       sw.default:
; CHECK-NEXT:    tail call void @foo()
; CHECK-NEXT:    br label [[LATCH]]
; CHECK:       latch:
; CHECK-NEXT:    br i1 false, label [[FOR_END:%.*]], label [[FOR_BODY_1:%.*]]
; CHECK:       for.body.1:
; CHECK-NEXT:    switch i32 1, label [[SW_DEFAULT_1:%.*]] [
; CHECK-NEXT:    i32 2, label [[LATCH_1:%.*]]
; CHECK-NEXT:    ]
; CHECK:       sw.default.1:
; CHECK-NEXT:    tail call void @foo()
; CHECK-NEXT:    br label [[LATCH_1]]
; CHECK:       latch.1:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[FOR_END]], label [[FOR_BODY_2:%.*]]
; CHECK:       for.body.2:
; CHECK-NEXT:    switch i32 2, label [[SW_DEFAULT_2:%.*]] [
; CHECK-NEXT:    i32 2, label [[LATCH_2:%.*]]
; CHECK-NEXT:    ]
; CHECK:       sw.default.2:
; CHECK-NEXT:    tail call void @foo()
; CHECK-NEXT:    br label [[LATCH_2]]
; CHECK:       latch.2:
; CHECK-NEXT:    br label [[FOR_END]]
; CHECK:       for.end:
; CHECK-NEXT:    ret void
;
entry:
  %0 = select i1 %cond, i32 2, i32 3
  br label %for.body

for.body:
  %i.017 = phi i32 [ 0, %entry ], [ %inc, %latch ]
  switch i32 %i.017, label %sw.default [
  i32 2, label %latch
  ]

sw.default:
  tail call void @foo()
  br label %latch

latch:
  %inc = add nuw nsw i32 %i.017, 1
  %exitcond.not = icmp eq i32 %inc, %0
  br i1 %exitcond.not, label %for.end, label %for.body

for.end:
  ret void
}

declare void @foo()
