; RUN: llc -verify-machineinstrs -mcpu=ppc64 -O0 < %s | FileCheck %s

target datalayout = "E-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f128:128:128-v128:128:128-n32:64"
target triple = "powerpc64-unknown-linux-gnu"

define { ppc_fp128, ppc_fp128 } @foo() nounwind {
entry:
  %retval = alloca { ppc_fp128, ppc_fp128 }, align 16
  %x = alloca { ppc_fp128, ppc_fp128 }, align 16
  %real = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %x, i32 0, i32 0
  %imag = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %x, i32 0, i32 1
  store ppc_fp128 0xM400C0000000000300000000010000000, ptr %real
  store ppc_fp128 0xMC00547AE147AE1483CA47AE147AE147A, ptr %imag
  %x.realp = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %x, i32 0, i32 0
  %x.real = load ppc_fp128, ptr %x.realp
  %x.imagp = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %x, i32 0, i32 1
  %x.imag = load ppc_fp128, ptr %x.imagp
  %real1 = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %retval, i32 0, i32 0
  %imag2 = getelementptr inbounds { ppc_fp128, ppc_fp128 }, ptr %retval, i32 0, i32 1
  store ppc_fp128 %x.real, ptr %real1
  store ppc_fp128 %x.imag, ptr %imag2
  %0 = load { ppc_fp128, ppc_fp128 }, ptr %retval
  ret { ppc_fp128, ppc_fp128 } %0
}

; CHECK-LABEL: foo:
; CHECK-DAG: lfd 1
; CHECK-DAG: lfd 2
; CHECK-DAG: lfd 3
; CHECK-DAG: lfd 4

define { float, float } @oof() nounwind {
entry:
  %retval = alloca { float, float }, align 4
  %x = alloca { float, float }, align 4
  %real = getelementptr inbounds { float, float }, ptr %x, i32 0, i32 0
  %imag = getelementptr inbounds { float, float }, ptr %x, i32 0, i32 1
  store float 3.500000e+00, ptr %real
  store float 0xC00547AE20000000, ptr %imag
  %x.realp = getelementptr inbounds { float, float }, ptr %x, i32 0, i32 0
  %x.real = load float, ptr %x.realp
  %x.imagp = getelementptr inbounds { float, float }, ptr %x, i32 0, i32 1
  %x.imag = load float, ptr %x.imagp
  %real1 = getelementptr inbounds { float, float }, ptr %retval, i32 0, i32 0
  %imag2 = getelementptr inbounds { float, float }, ptr %retval, i32 0, i32 1
  store float %x.real, ptr %real1
  store float %x.imag, ptr %imag2
  %0 = load { float, float }, ptr %retval
  ret { float, float } %0
}

; CHECK-LABEL: oof:
; CHECK-DAG: lfs 2
; CHECK-DAG: lfs 1

