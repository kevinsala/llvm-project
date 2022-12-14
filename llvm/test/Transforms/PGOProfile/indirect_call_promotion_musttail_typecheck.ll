; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; Mustcall needs stricter parameter type checks otherwise it will fail in verifier.

; RUN: opt < %s -passes=pgo-icall-prom -S | FileCheck %s

; Here we check there is no ICP due to parameter mismatch.
define ptr @func(ptr %msg, ptr %ptr, ptr %ctx, i64 %data.coerce, ptr %table, i64 %hasbits) {
; CHECK-LABEL: @func(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr null, align 8
; CHECK-NEXT:    ret ptr null
; CHECK:       1:
; CHECK-NEXT:    [[CALL11_I:%.*]] = musttail call ptr [[TMP0]](ptr null, ptr null, ptr null, i64 0, ptr null, i64 0), !prof [[PROF0:![0-9]+]]
; CHECK-NEXT:    ret ptr [[CALL11_I]]
;
entry:
  %0 = load ptr, ptr null, align 8
  ret ptr null

1:
  %call11.i = musttail call ptr %0(ptr null, ptr null, ptr null, i64 0, ptr null, i64 0), !prof !0
  ret ptr %call11.i
}

; Here we check that ICP succeeds since parameters match. Also check the direct-call has a MustCall attribute.
define ptr @func2(ptr %msg, i64 %tag, ptr %ctx, ptr %type, ptr %table, ptr %ptr) {
; CHECK-LABEL: @func2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP1:%.*]] = load ptr, ptr null, align 8
; CHECK-NEXT:    ret ptr null
; CHECK:       1:
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq ptr [[TMP1]], @_ZN6proto28internal12ExtensionSet10ParseFieldEmPKcPKNS_7MessageEPNS0_16InternalMetadataEPNS0_12ParseContextE
; CHECK-NEXT:    br i1 [[TMP2]], label [[IF_TRUE_DIRECT_TARG:%.*]], label [[TMP4:%.*]], !prof [[PROF1:![0-9]+]]
; CHECK:       if.true.direct_targ:
; CHECK-NEXT:    [[TMP3:%.*]] = musttail call ptr @_ZN6proto28internal12ExtensionSet10ParseFieldEmPKcPKNS_7MessageEPNS0_16InternalMetadataEPNS0_12ParseContextE(ptr null, i64 0, ptr null, ptr null, ptr null, ptr null)
; CHECK-NEXT:    ret ptr [[TMP3]]
; CHECK:       4:
; CHECK-NEXT:    [[CALL11_I:%.*]] = musttail call ptr [[TMP1]](ptr null, i64 0, ptr null, ptr null, ptr null, ptr null), !prof [[PROF2:![0-9]+]]
; CHECK-NEXT:    ret ptr [[CALL11_I]]
;
entry:
  %0 = load ptr, ptr null, align 8
  ret ptr null

1:
  %call11.i = musttail call ptr %0(ptr null, i64 0, ptr null, ptr null, ptr null, ptr null), !prof !0
  ret ptr %call11.i
}

define available_externally ptr @_ZN6proto28internal12ExtensionSet10ParseFieldEmPKcPKNS_7MessageEPNS0_16InternalMetadataEPNS0_12ParseContextE(ptr %this, i64 %tag, ptr %ptr, ptr %containing_type, ptr %metadata, ptr %ctx) {
entry:
  ret ptr null
}

!0 = !{!"VP", i32 0, i64 2024, i64 -4843250054591211088, i64 -1, i64 1456131869974120143, i64 947, i64 -4941069334091589447, i64 18}
