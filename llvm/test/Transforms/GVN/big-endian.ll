; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=gvn -S < %s | FileCheck %s

target datalayout = "E-m:e-i64:64-n32:64"
target triple = "powerpc64-unknown-linux-gnu"

;; Make sure we use correct bit shift based on storage size for
;; loads reusing a load value.
define i64 @test1({ i1, i8 }* %predA, { i1, i8 }* %predB) {
; CHECK-LABEL: @test1(
; CHECK-NEXT:    [[VALUELOADA_FCA_0_GEP:%.*]] = getelementptr inbounds { i1, i8 }, { i1, i8 }* [[PREDA:%.*]], i64 0, i32 0
; CHECK-NEXT:    [[VALUELOADA_FCA_0_LOAD:%.*]] = load i1, i1* [[VALUELOADA_FCA_0_GEP]], align 8
; CHECK-NEXT:    [[VALUELOADB_FCA_0_GEP:%.*]] = getelementptr inbounds { i1, i8 }, { i1, i8 }* [[PREDB:%.*]], i64 0, i32 0
; CHECK-NEXT:    [[VALUELOADB_FCA_0_LOAD:%.*]] = load i1, i1* [[VALUELOADB_FCA_0_GEP]], align 8
; CHECK-NEXT:    [[ISTRUE:%.*]] = and i1 [[VALUELOADA_FCA_0_LOAD]], [[VALUELOADB_FCA_0_LOAD]]
; CHECK-NEXT:    [[VALUELOADA_FCA_1_GEP:%.*]] = getelementptr inbounds { i1, i8 }, { i1, i8 }* [[PREDA]], i64 0, i32 1
; CHECK-NEXT:    [[VALUELOADA_FCA_1_LOAD:%.*]] = load i8, i8* [[VALUELOADA_FCA_1_GEP]], align 1
; CHECK-NEXT:    [[ISNOTNULLA:%.*]] = icmp ne i8 [[VALUELOADA_FCA_1_LOAD]], 0
; CHECK-NEXT:    [[VALUELOADB_FCA_1_GEP:%.*]] = getelementptr inbounds { i1, i8 }, { i1, i8 }* [[PREDB]], i64 0, i32 1
; CHECK-NEXT:    [[VALUELOADB_FCA_1_LOAD:%.*]] = load i8, i8* [[VALUELOADB_FCA_1_GEP]], align 1
; CHECK-NEXT:    [[ISNOTNULLB:%.*]] = icmp ne i8 [[VALUELOADB_FCA_1_LOAD]], 0
; CHECK-NEXT:    [[ISNOTNULL:%.*]] = and i1 [[ISNOTNULLA]], [[ISNOTNULLB]]
; CHECK-NEXT:    [[ISTRUEANDNOTNULL:%.*]] = and i1 [[ISTRUE]], [[ISNOTNULL]]
; CHECK-NEXT:    [[RET:%.*]] = zext i1 [[ISTRUEANDNOTNULL]] to i64
; CHECK-NEXT:    ret i64 [[RET]]
;

  %valueLoadA.fca.0.gep = getelementptr inbounds { i1, i8 }, { i1, i8 }* %predA, i64 0, i32 0
  %valueLoadA.fca.0.load = load i1, i1* %valueLoadA.fca.0.gep, align 8
  %valueLoadB.fca.0.gep = getelementptr inbounds { i1, i8 }, { i1, i8 }* %predB, i64 0, i32 0
  %valueLoadB.fca.0.load = load i1, i1* %valueLoadB.fca.0.gep, align 8
  %isTrue = and i1 %valueLoadA.fca.0.load, %valueLoadB.fca.0.load
  %valueLoadA.fca.1.gep = getelementptr inbounds { i1, i8 }, { i1, i8 }* %predA, i64 0, i32 1
  %valueLoadA.fca.1.load = load i8, i8* %valueLoadA.fca.1.gep, align 1
  %isNotNullA = icmp ne i8 %valueLoadA.fca.1.load, 0
  %valueLoadB.fca.1.gep = getelementptr inbounds { i1, i8 }, { i1, i8 }* %predB, i64 0, i32 1
  %valueLoadB.fca.1.load = load i8, i8* %valueLoadB.fca.1.gep, align 1
  %isNotNullB = icmp ne i8 %valueLoadB.fca.1.load, 0
  %isNotNull = and i1 %isNotNullA, %isNotNullB
  %isTrueAndNotNull = and i1 %isTrue, %isNotNull
  %ret = zext i1 %isTrueAndNotNull to i64
  ret i64 %ret
}

;; And likewise for loads reusing a store value.
define i1 @test2(i8 %V, i8* %P) {
; CHECK-LABEL: @test2(
; CHECK-NEXT:    store i8 [[V:%.*]], i8* [[P:%.*]], align 1
; CHECK-NEXT:    [[P2:%.*]] = bitcast i8* [[P]] to i1*
; CHECK-NEXT:    [[TMP1:%.*]] = trunc i8 [[V]] to i1
; CHECK-NEXT:    ret i1 [[TMP1]]
;
  store i8 %V, i8* %P
  %P2 = bitcast i8* %P to i1*
  %A = load i1, i1* %P2
  ret i1 %A
}

