; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux -mcpu=a2 < %s | FileCheck %s
target datalayout = "E-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f128:128:128-v128:128:128-n32:64"
target triple = "powerpc64le-unknown-linux"

%struct.BG_CoordinateMapping_t = type { [4 x i8] }

; Function Attrs: alwaysinline inlinehint nounwind
define zeroext i32 @Kernel_RanksToCoords(i64 %mapsize, ptr %map, ptr %numentries) #0 {
entry:
  %mapsize.addr = alloca i64, align 8
  %map.addr = alloca ptr, align 8
  %numentries.addr = alloca ptr, align 8
  %r0 = alloca i64, align 8
  %r3 = alloca i64, align 8
  %r4 = alloca i64, align 8
  %r5 = alloca i64, align 8
  %tmp = alloca i64, align 8
  store i64 %mapsize, ptr %mapsize.addr, align 8
  store ptr %map, ptr %map.addr, align 8
  store ptr %numentries, ptr %numentries.addr, align 8
  store i64 1055, ptr %r0, align 8
  %0 = load i64, ptr %mapsize.addr, align 8
  store i64 %0, ptr %r3, align 8
  %1 = load ptr, ptr %map.addr, align 8
  %2 = ptrtoint ptr %1 to i64
  store i64 %2, ptr %r4, align 8
  %3 = load ptr, ptr %numentries.addr, align 8
  %4 = ptrtoint ptr %3 to i64
  store i64 %4, ptr %r5, align 8
  %5 = load i64, ptr %r0, align 8
  %6 = load i64, ptr %r3, align 8
  %7 = load i64, ptr %r4, align 8
  %8 = load i64, ptr %r5, align 8
  %9 = call { i64, i64, i64, i64 } asm sideeffect "sc", "={r0},={r3},={r4},={r5},{r0},{r3},{r4},{r5},~{r6},~{r7},~{r8},~{r9},~{r10},~{r11},~{r12},~{cr0},~{memory}"(i64 %5, i64 %6, i64 %7, i64 %8) #1, !srcloc !0

; CHECK-LABEL: @Kernel_RanksToCoords

; These need to be 64-bit loads, not 32-bit loads (not lwz).
; CHECK-NOT: lwz

; CHECK: #APP
; CHECK: sc
; CHECK: #NO_APP

; CHECK: blr

  %asmresult = extractvalue { i64, i64, i64, i64 } %9, 0
  %asmresult1 = extractvalue { i64, i64, i64, i64 } %9, 1
  %asmresult2 = extractvalue { i64, i64, i64, i64 } %9, 2
  %asmresult3 = extractvalue { i64, i64, i64, i64 } %9, 3
  store i64 %asmresult, ptr %r0, align 8
  store i64 %asmresult1, ptr %r3, align 8
  store i64 %asmresult2, ptr %r4, align 8
  store i64 %asmresult3, ptr %r5, align 8
  %10 = load i64, ptr %r3, align 8
  store i64 %10, ptr %tmp
  %11 = load i64, ptr %tmp
  %conv = trunc i64 %11 to i32
  ret i32 %conv
}

declare void @mtrace()

define signext i32 @main(i32 signext %argc, ptr %argv) {
entry:
  %argc.addr = alloca i32, align 4
  store i32 %argc, ptr %argc.addr, align 4
  %0 = call { i64, i64 } asm sideeffect "sc", "={r0},={r3},{r0},~{r4},~{r5},~{r6},~{r7},~{r8},~{r9},~{r10},~{r11},~{r12},~{cr0},~{memory}"(i64 1076)
  %asmresult1.i = extractvalue { i64, i64 } %0, 1
  %conv.i = trunc i64 %asmresult1.i to i32
  %cmp = icmp eq i32 %conv.i, 0
  br i1 %cmp, label %if.then, label %if.end

; CHECK-LABEL: @main

; CHECK: mr [[REG:[0-9]+]], 3
; CHECK: std 0,
; CHECK: stw [[REG]],

; CHECK:     #APP
; CHECK:     sc
; CHECK:     #NO_APP
                                      
; CHECK:     cmpwi [[REG]], 1

; CHECK: blr

if.then:                                          ; preds = %entry
  call void @mtrace()
  %.pre = load i32, ptr %argc.addr, align 4
  br label %if.end

if.end:                                           ; preds = %if.then, %entry
  %1 = phi i32 [ %.pre, %if.then ], [ %argc, %entry ]
  %cmp1 = icmp slt i32 %1, 2
  br i1 %cmp1, label %usage, label %if.end40

usage:    
  ret i32 8

if.end40:
  ret i32 0
}

attributes #0 = { alwaysinline inlinehint nounwind }
attributes #1 = { nounwind }

!0 = !{i32 -2146895770}
