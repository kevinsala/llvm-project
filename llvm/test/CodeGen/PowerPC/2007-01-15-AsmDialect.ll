; RUN: llc -verify-machineinstrs < %s -mtriple=powerpc-unknown-linux-gnu | FileCheck %s

define i32 @foo() nounwind {
entry:
; CHECK: cntlzw 3, 3
	%retval = alloca i32, align 4		; <ptr> [#uses=2]
	%temp = alloca i32, align 4		; <ptr> [#uses=2]
	%ctz_x = alloca i32, align 4		; <ptr> [#uses=3]
	%ctz_c = alloca i32, align 4		; <ptr> [#uses=2]
	store i32 61440, ptr %ctz_x
	%tmp = load i32, ptr %ctz_x		; <i32> [#uses=1]
	%tmp1 = sub i32 0, %tmp		; <i32> [#uses=1]
	%tmp2 = load i32, ptr %ctz_x		; <i32> [#uses=1]
	%tmp3 = and i32 %tmp1, %tmp2		; <i32> [#uses=1]
	%tmp4 = call i32 asm "$(cntlz$|cntlzw$) $0,$1", "=r,r,~{dirflag},~{fpsr},~{flags}"( i32 %tmp3 )		; <i32> [#uses=1]
	store i32 %tmp4, ptr %ctz_c
	%tmp5 = load i32, ptr %ctz_c		; <i32> [#uses=1]
	store i32 %tmp5, ptr %temp
	%tmp6 = load i32, ptr %temp		; <i32> [#uses=1]
	store i32 %tmp6, ptr %retval
	br label %return

return:		; preds = %entry
	%retval2 = load i32, ptr %retval		; <i32> [#uses=1]
	ret i32 %retval2
}
