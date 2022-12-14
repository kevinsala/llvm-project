; RUN: opt < %s -passes=globalopt -S | FileCheck %s
target datalayout = "E-p:64:64:64-a0:0:8-f32:32:32-f64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-v64:64:64-v128:128:128"

;; Heap SROA has been removed. This tests we don't perform heap SROA.
; CHECK: @X =
	%struct.foo = type { i32, i32 }
@X = internal global ptr null

define void @bar(i64 %Size) nounwind noinline {
entry:
  %mallocsize = mul i64 %Size, 8                  ; <i64> [#uses=1]
  %malloccall = tail call ptr @malloc(i64 %mallocsize) ; <ptr> [#uses=1]
	store ptr %malloccall, ptr @X, align 4
	ret void
}

declare noalias ptr @malloc(i64)

define i32 @baz() nounwind readonly noinline {
bb1.thread:
	%0 = load ptr, ptr @X, align 4		
	br label %bb1

bb1:		; preds = %bb1, %bb1.thread
	%i.0.reg2mem.0 = phi i32 [ 0, %bb1.thread ], [ %indvar.next, %bb1 ]
	%sum.0.reg2mem.0 = phi i32 [ 0, %bb1.thread ], [ %3, %bb1 ]
	%1 = getelementptr %struct.foo, ptr %0, i32 %i.0.reg2mem.0, i32 0
	%2 = load i32, ptr %1, align 4
	%3 = add i32 %2, %sum.0.reg2mem.0	
	%indvar.next = add i32 %i.0.reg2mem.0, 1	
	%exitcond = icmp eq i32 %indvar.next, 1200		
	br i1 %exitcond, label %bb2, label %bb1

bb2:		; preds = %bb1
	ret i32 %3
}

define void @bam(i64 %Size) nounwind noinline #0 {
entry:
	%0 = load ptr, ptr @X, align 4
        ret void
}

attributes #0 = { null_pointer_is_valid }
