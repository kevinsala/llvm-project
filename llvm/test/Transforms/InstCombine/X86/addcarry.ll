; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -mtriple=x86_64-unknown-unknown -S | FileCheck %s

declare { i8, i32 } @llvm.x86.addcarry.32(i8, i32, i32)
declare { i8, i64 } @llvm.x86.addcarry.64(i8, i64, i64)

define i32 @no_carryin_i32(i32 %x, i32 %y, ptr %p) {
; CHECK-LABEL: @no_carryin_i32(
; CHECK-NEXT:    [[TMP1:%.*]] = call { i32, i1 } @llvm.uadd.with.overflow.i32(i32 [[X:%.*]], i32 [[Y:%.*]])
; CHECK-NEXT:    [[TMP2:%.*]] = extractvalue { i32, i1 } [[TMP1]], 0
; CHECK-NEXT:    [[TMP3:%.*]] = extractvalue { i32, i1 } [[TMP1]], 1
; CHECK-NEXT:    [[TMP4:%.*]] = zext i1 [[TMP3]] to i8
; CHECK-NEXT:    store i8 [[TMP4]], ptr [[P:%.*]], align 1
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %s = call { i8, i32 } @llvm.x86.addcarry.32(i8 0, i32 %x, i32 %y)
  %ov = extractvalue { i8, i32 } %s, 0
  store i8 %ov, ptr %p
  %r = extractvalue { i8, i32 } %s, 1
  ret i32 %r
}

define i64 @no_carryin_i64(i64 %x, i64 %y, ptr %p) {
; CHECK-LABEL: @no_carryin_i64(
; CHECK-NEXT:    [[TMP1:%.*]] = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 [[X:%.*]], i64 [[Y:%.*]])
; CHECK-NEXT:    [[TMP2:%.*]] = extractvalue { i64, i1 } [[TMP1]], 0
; CHECK-NEXT:    [[TMP3:%.*]] = extractvalue { i64, i1 } [[TMP1]], 1
; CHECK-NEXT:    [[TMP4:%.*]] = zext i1 [[TMP3]] to i8
; CHECK-NEXT:    store i8 [[TMP4]], ptr [[P:%.*]], align 1
; CHECK-NEXT:    ret i64 [[TMP2]]
;
  %s = call { i8, i64 } @llvm.x86.addcarry.64(i8 0, i64 %x, i64 %y)
  %ov = extractvalue { i8, i64 } %s, 0
  store i8 %ov, ptr %p
  %r = extractvalue { i8, i64 } %s, 1
  ret i64 %r
}
