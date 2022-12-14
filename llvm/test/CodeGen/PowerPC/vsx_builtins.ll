; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -relocation-model=static -verify-machineinstrs -mcpu=pwr9 \
; RUN:     -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-P9UP
; RUN: llc -verify-machineinstrs -mcpu=pwr9 -mattr=-power9-vector \
; RUN:     -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-NOINTRIN
; RUN: llc -verify-machineinstrs -mcpu=pwr8 -mattr=+vsx \
; RUN:     -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-NOINTRIN
; RUN: llc -verify-machineinstrs -mcpu=pwr9 \
; RUN:     -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-P9UP
; RUN: llc -verify-machineinstrs -mcpu=pwr9 -mattr=-power9-vector \
; RUN:     -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-INTRIN
; RUN: llc -verify-machineinstrs -mcpu=pwr8 -mattr=+vsx \
; RUN:     -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-INTRIN
; RUN: llc -verify-machineinstrs -mcpu=pwr10 \
; RUN:     -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-P9UP
; RUN: llc -verify-machineinstrs -mcpu=pwr10 \
; RUN:     -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -ppc-vsr-nums-as-vr -ppc-asm-full-reg-names < %s | FileCheck %s \
; RUN:     --check-prefixes=CHECK,CHECK-P9UP

; Function Attrs: nounwind readnone
define <4 x i32> @test1(ptr %a) {
; CHECK-LABEL: test1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lxvw4x v2, 0, r3
; CHECK-NEXT:    blr
  entry:
    %0 = tail call <4 x i32> @llvm.ppc.vsx.lxvw4x.be(ptr %a)
      ret <4 x i32> %0
}
; Function Attrs: nounwind readnone
declare <4 x i32> @llvm.ppc.vsx.lxvw4x.be(ptr)

; Function Attrs: nounwind readnone
define <2 x double> @test2(ptr %a) {
; CHECK-LABEL: test2:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lxvd2x v2, 0, r3
; CHECK-NEXT:    blr
  entry:
    %0 = tail call <2 x double> @llvm.ppc.vsx.lxvd2x.be(ptr %a)
      ret <2 x double> %0
}
; Function Attrs: nounwind readnone
declare <2 x double> @llvm.ppc.vsx.lxvd2x.be(ptr)

; Function Attrs: nounwind readnone
define void @test3(<4 x i32> %a, ptr %b) {
; CHECK-LABEL: test3:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stxvw4x v2, 0, r5
; CHECK-NEXT:    blr
  entry:
    tail call void @llvm.ppc.vsx.stxvw4x.be(<4 x i32> %a, ptr %b)
    ret void
}
; Function Attrs: nounwind readnone
declare void @llvm.ppc.vsx.stxvw4x.be(<4 x i32>, ptr)

; Function Attrs: nounwind readnone
define void @test4(<2 x double> %a, ptr %b) {
; CHECK-LABEL: test4:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stxvd2x v2, 0, r5
; CHECK-NEXT:    blr
  entry:
    tail call void @llvm.ppc.vsx.stxvd2x.be(<2 x double> %a, ptr %b)
    ret void
}
; Function Attrs: nounwind readnone
declare void @llvm.ppc.vsx.stxvd2x.be(<2 x double>, ptr)

define i32 @test_vec_test_swdiv(<2 x double> %a, <2 x double> %b) {
; CHECK-LABEL: test_vec_test_swdiv:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtdivdp cr0, v2, v3
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    blr
  entry:
    %0 = tail call i32 @llvm.ppc.vsx.xvtdivdp(<2 x double> %a, <2 x double> %b)
    ret i32 %0
}
declare i32 @llvm.ppc.vsx.xvtdivdp(<2 x double>, <2 x double>)

define i32 @test_vec_test_swdivs(<4 x float> %a, <4 x float> %b) {
; CHECK-LABEL: test_vec_test_swdivs:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtdivsp cr0, v2, v3
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    blr
  entry:
    %0 = tail call i32 @llvm.ppc.vsx.xvtdivsp(<4 x float> %a, <4 x float> %b)
    ret i32 %0
}
declare i32 @llvm.ppc.vsx.xvtdivsp(<4 x float>, <4 x float>)

define i32 @test_vec_test_swsqrt(<2 x double> %a) {
; CHECK-LABEL: test_vec_test_swsqrt:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtsqrtdp cr0, v2
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    blr
  entry:
    %0 = tail call i32 @llvm.ppc.vsx.xvtsqrtdp(<2 x double> %a)
    ret i32 %0
}
declare i32 @llvm.ppc.vsx.xvtsqrtdp(<2 x double>)

define i32 @test_vec_test_swsqrts(<4 x float> %a) {
; CHECK-LABEL: test_vec_test_swsqrts:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtsqrtsp cr0, v2
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    blr
  entry:
    %0 = tail call i32 @llvm.ppc.vsx.xvtsqrtsp(<4 x float> %a)
    ret i32 %0
}
declare i32 @llvm.ppc.vsx.xvtsqrtsp(<4 x float>)

define i32 @xvtdivdp_andi(<2 x double> %a, <2 x double> %b) {
; CHECK-LABEL: xvtdivdp_andi:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtdivdp cr0, v2, v3
; CHECK-NEXT:    li r4, 222
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    andi. r3, r3, 2
; CHECK-NEXT:    li r3, 22
; CHECK-NEXT:    iseleq r3, r4, r3
; CHECK-NEXT:    blr
  entry:
    %0 = tail call i32 @llvm.ppc.vsx.xvtdivdp(<2 x double> %a, <2 x double> %b)
    %1 = and i32 %0, 2
    %cmp.not = icmp eq i32 %1, 0
    %retval.0 = select i1 %cmp.not, i32 222, i32 22
    ret i32 %retval.0
}

define i32 @xvtdivdp_shift(<2 x double> %a, <2 x double> %b) {
; CHECK-LABEL: xvtdivdp_shift:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    xvtdivdp cr0, v2, v3
; CHECK-NEXT:    mfocrf r3, 128
; CHECK-NEXT:    srwi r3, r3, 28
; CHECK-NEXT:    rlwinm r3, r3, 28, 31, 31
; CHECK-NEXT:    blr
entry:
  %0 = tail call i32 @llvm.ppc.vsx.xvtdivdp(<2 x double> %a, <2 x double> %b)
  %1 = lshr i32 %0, 4
  %.lobit = and i32 %1, 1
  ret i32 %.lobit
}

; Function Attrs: nounwind readnone
define <2 x double> @test_lxvd2x(ptr %a) {
; CHECK-P9UP-LABEL: test_lxvd2x:
; CHECK-P9UP:       # %bb.0: # %entry
; CHECK-P9UP-NEXT:    lxv v2, 0(r3)
; CHECK-P9UP-NEXT:    blr
;
; CHECK-NOINTRIN-LABEL: test_lxvd2x:
; CHECK-NOINTRIN:       # %bb.0: # %entry
; CHECK-NOINTRIN-NEXT:    lxvd2x vs0, 0, r3
; CHECK-NOINTRIN-NEXT:    xxswapd v2, vs0
; CHECK-NOINTRIN-NEXT:    blr
;
; CHECK-INTRIN-LABEL: test_lxvd2x:
; CHECK-INTRIN:       # %bb.0: # %entry
; CHECK-INTRIN-NEXT:    lxvd2x v2, 0, r3
; CHECK-INTRIN-NEXT:    blr
entry:
  %0 = tail call <2 x double> @llvm.ppc.vsx.lxvd2x(ptr %a)
  ret <2 x double> %0
}
; Function Attrs: nounwind readnone
declare <2 x double> @llvm.ppc.vsx.lxvd2x(ptr)

; Function Attrs: nounwind readnone
define void @test_stxvd2x(<2 x double> %a, ptr %b) {
; CHECK-P9UP-LABEL: test_stxvd2x:
; CHECK-P9UP:       # %bb.0: # %entry
; CHECK-P9UP-NEXT:    stxv v2, 0(r5)
; CHECK-P9UP-NEXT:    blr
;
; CHECK-NOINTRIN-LABEL: test_stxvd2x:
; CHECK-NOINTRIN:       # %bb.0: # %entry
; CHECK-NOINTRIN-NEXT:    xxswapd vs0, v2
; CHECK-NOINTRIN-NEXT:    stxvd2x vs0, 0, r5
; CHECK-NOINTRIN-NEXT:    blr
;
; CHECK-INTRIN-LABEL: test_stxvd2x:
; CHECK-INTRIN:       # %bb.0: # %entry
; CHECK-INTRIN-NEXT:    stxvd2x v2, 0, r5
; CHECK-INTRIN-NEXT:    blr
entry:
  tail call void @llvm.ppc.vsx.stxvd2x(<2 x double> %a, ptr %b)
  ret void
}
; Function Attrs: nounwind readnone
declare void @llvm.ppc.vsx.stxvd2x(<2 x double>, ptr)
