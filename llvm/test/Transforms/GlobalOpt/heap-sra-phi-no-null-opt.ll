; RUN: opt < %s -passes=globalopt -S | FileCheck %s
target datalayout = "E-p:64:64:64-a0:0:8-f32:32:32-f64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-v64:64:64-v128:128:128"

%struct.foo = type { i32, i32 }

@X = internal global ptr null		; <ptr> [#uses=2]
; CHECK: @X
; CHECK-NOT: @X.f0

define void @bar(i32 %Size) nounwind noinline #0 {
;  CHECK-LABEL: @bar(
entry:
	%malloccall = tail call ptr @malloc(i64 8000000) ; <ptr> [#uses=1]
	%.sub = getelementptr [1000000 x %struct.foo], ptr %malloccall, i32 0, i32 0		; <ptr> [#uses=1]
	store ptr %.sub, ptr @X, align 4
	ret void
}

declare noalias ptr @malloc(i64)

define i32 @baz() nounwind readonly noinline #0 {
; CHECK-LABEL: @baz(
bb1.thread:
	%tmpLD1 = load ptr, ptr @X, align 4		; <ptr> [#uses=1]
; CHECK: load ptr, ptr @X, align 4
	br label %bb1

bb1:		; preds = %bb1, %bb1.thread
        %tmp = phi ptr [%tmpLD1, %bb1.thread ], [ %tmpLD2, %bb1 ]		; <i32> [#uses=2]
; CHECK: %tmp = phi ptr [ %tmpLD1, %bb1.thread ], [ %tmpLD2, %bb1 ]
	%i.0.reg2mem.0 = phi i32 [ 0, %bb1.thread ], [ %indvar.next, %bb1 ]		; <i32> [#uses=2]
	%sum.0.reg2mem.0 = phi i32 [ 0, %bb1.thread ], [ %tmp3, %bb1 ]		; <i32> [#uses=1]
	%tmp1 = getelementptr %struct.foo, ptr %tmp, i32 %i.0.reg2mem.0, i32 0		; <ptr> [#uses=1]
	%tmp2 = load i32, ptr %tmp1, align 4		; <i32> [#uses=1]
; CHECK: load i32, ptr %tmp1, align 4
	%tmp6 = add i32 %tmp2, %sum.0.reg2mem.0		; <i32> [#uses=2]
	%tmp4 = getelementptr %struct.foo, ptr %tmp, i32 %i.0.reg2mem.0, i32 1		; <ptr> [#uses=1]
        %tmp5 = load i32 , ptr %tmp4
;  CHECK: load i32, ptr %tmp4
        %tmp3 = add i32 %tmp5, %tmp6
	%indvar.next = add i32 %i.0.reg2mem.0, 1		; <i32> [#uses=2]

      	%tmpLD2 = load ptr, ptr @X, align 4		; <ptr> [#uses=1]
; CHECK: load ptr, ptr @X, align 4

	%exitcond = icmp eq i32 %indvar.next, 1200		; <i1> [#uses=1]
	br i1 %exitcond, label %bb2, label %bb1

bb2:		; preds = %bb1
	ret i32 %tmp3
}

attributes #0 = { null_pointer_is_valid }
