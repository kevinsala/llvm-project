; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:   -mcpu=pwr9 < %s | FileCheck %s
define dso_local i64 @test1(ptr nocapture readonly %p, i32 signext %count) local_unnamed_addr #0 {
; CHECK-LABEL: test1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    li 5, -13
; CHECK-NEXT:    li 6, 7
; CHECK-NEXT:    li 7, 11
; CHECK-NEXT:    li 8, 15
; CHECK-NEXT:    lxvx 0, 3, 5
; CHECK-NEXT:    li 5, 19
; CHECK-NEXT:    ldx 6, 3, 6
; CHECK-NEXT:    ldx 7, 3, 7
; CHECK-NEXT:    lxvx 1, 3, 5
; CHECK-NEXT:    li 5, 3
; CHECK-NEXT:    ldx 5, 3, 5
; CHECK-NEXT:    ldx 3, 3, 8
; CHECK-NEXT:    mfvsrld 9, 0
; CHECK-NEXT:    mffprd 8, 0
; CHECK-NEXT:    mfvsrld 10, 1
; CHECK-NEXT:    mffprd 11, 1
; CHECK-NEXT:    mulld 8, 9, 8
; CHECK-NEXT:    mulld 5, 8, 5
; CHECK-NEXT:    mulld 5, 5, 10
; CHECK-NEXT:    mulld 5, 5, 11
; CHECK-NEXT:    mulld 5, 5, 6
; CHECK-NEXT:    mulld 5, 5, 7
; CHECK-NEXT:    maddld 3, 5, 3, 4
; CHECK-NEXT:    blr
entry:
  %add.ptr = getelementptr inbounds i8, ptr %p, i64 -13
  %0 = load <2 x i64>, ptr %add.ptr, align 16
  %add.ptr1 = getelementptr inbounds i8, ptr %p, i64 19
  %1 = load <2 x i64>, ptr %add.ptr1, align 16
  %add.ptr3 = getelementptr inbounds i8, ptr %p, i64 3
  %2 = load i64, ptr %add.ptr3, align 8
  %add.ptr5 = getelementptr inbounds i8, ptr %p, i64 7
  %3 = load i64, ptr %add.ptr5, align 8
  %add.ptr7 = getelementptr inbounds i8, ptr %p, i64 11
  %4 = load i64, ptr %add.ptr7, align 8
  %add.ptr9 = getelementptr inbounds i8, ptr %p, i64 15
  %5 = load i64, ptr %add.ptr9, align 8
  %vecext = extractelement <2 x i64> %0, i32 1
  %vecext13 = extractelement <2 x i64> %0, i32 0
  %vecext15 = extractelement <2 x i64> %1, i32 0
  %vecext17 = extractelement <2 x i64> %1, i32 1
  %mul = mul i64 %vecext13, %vecext
  %mul10 = mul i64 %mul, %2
  %mul11 = mul i64 %mul10, %vecext15
  %mul12 = mul i64 %mul11, %vecext17
  %mul14 = mul i64 %mul12, %3
  %mul16 = mul i64 %mul14, %4
  %mul18 = mul i64 %mul16, %5
  %conv = sext i32 %count to i64
  %add19 = add i64 %mul18, %conv
  ret i64 %add19
}

define dso_local i64 @test2(ptr nocapture readonly %p, i32 signext %count) local_unnamed_addr #0 {
; CHECK-LABEL: test2:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    li 5, 0
; CHECK-NEXT:    ori 6, 5, 40009
; CHECK-NEXT:    ori 7, 5, 40001
; CHECK-NEXT:    ori 5, 5, 40005
; CHECK-NEXT:    ldx 6, 3, 6
; CHECK-NEXT:    ldx 7, 3, 7
; CHECK-NEXT:    ldx 3, 3, 5
; CHECK-NEXT:    mulld 5, 7, 6
; CHECK-NEXT:    maddld 3, 5, 3, 4
; CHECK-NEXT:    blr
entry:
  %add.ptr = getelementptr inbounds i8, ptr %p, i64 40009
  %0 = load i64, ptr %add.ptr, align 8
  %add.ptr2 = getelementptr inbounds i8, ptr %p, i64 40001
  %1 = load i64, ptr %add.ptr2, align 8
  %add.ptr4 = getelementptr inbounds i8, ptr %p, i64 40005
  %2 = load i64, ptr %add.ptr4, align 8
  %mul = mul i64 %1, %0
  %mul5 = mul i64 %mul, %2
  %conv = sext i32 %count to i64
  %add6 = add i64 %mul5, %conv
  ret i64 %add6
}

define dso_local i64 @test3(ptr nocapture readonly %p, i32 signext %count) local_unnamed_addr {
; CHECK-LABEL: test3:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lis 5, 1
; CHECK-NEXT:    ori 6, 5, 14497
; CHECK-NEXT:    ori 7, 5, 14465
; CHECK-NEXT:    ori 5, 5, 14481
; CHECK-NEXT:    ldx 6, 3, 6
; CHECK-NEXT:    ldx 7, 3, 7
; CHECK-NEXT:    ldx 3, 3, 5
; CHECK-NEXT:    mulld 5, 7, 6
; CHECK-NEXT:    maddld 3, 5, 3, 4
; CHECK-NEXT:    blr
entry:
  %add.ptr = getelementptr inbounds i8, ptr %p, i64 80033
  %0 = load i64, ptr %add.ptr, align 8
  %add.ptr2 = getelementptr inbounds i8, ptr %p, i64 80001
  %1 = load i64, ptr %add.ptr2, align 8
  %add.ptr4 = getelementptr inbounds i8, ptr %p, i64 80017
  %2 = load i64, ptr %add.ptr4, align 8
  %mul = mul i64 %1, %0
  %mul5 = mul i64 %mul, %2
  %conv = sext i32 %count to i64
  %add6 = add i64 %mul5, %conv
  ret i64 %add6
}

