; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=loop-idiom -mtriple=x86_64 -mcpu=core-avx2 < %s -S | FileCheck --check-prefix=ALL %s
; RUN: opt -passes=loop-idiom -mtriple=x86_64 -mcpu=corei7 < %s -S | FileCheck --check-prefix=ALL %s

; Recognize CTTZ builtin pattern.
; Here it will replace the loop -
; assume builtin is always profitable.
;
; int cttz_zero_check(int n)
; {
;   int i = 0;
;   while(n) {
;     n <<= 1;
;     i++;
;   }
;   return i;
; }
;
define i32 @cttz_zero_check(i32 %n) {
; ALL-LABEL: @cttz_zero_check(
; ALL-NEXT:  entry:
; ALL-NEXT:    [[TOBOOL4:%.*]] = icmp eq i32 [[N:%.*]], 0
; ALL-NEXT:    br i1 [[TOBOOL4]], label [[WHILE_END:%.*]], label [[WHILE_BODY_PREHEADER:%.*]]
; ALL:       while.body.preheader:
; ALL-NEXT:    [[TMP0:%.*]] = call i32 @llvm.cttz.i32(i32 [[N]], i1 true)
; ALL-NEXT:    [[TMP1:%.*]] = sub i32 32, [[TMP0]]
; ALL-NEXT:    br label [[WHILE_BODY:%.*]]
; ALL:       while.body:
; ALL-NEXT:    [[TCPHI:%.*]] = phi i32 [ [[TMP1]], [[WHILE_BODY_PREHEADER]] ], [ [[TCDEC:%.*]], [[WHILE_BODY]] ]
; ALL-NEXT:    [[I_06:%.*]] = phi i32 [ [[INC:%.*]], [[WHILE_BODY]] ], [ 0, [[WHILE_BODY_PREHEADER]] ]
; ALL-NEXT:    [[N_ADDR_05:%.*]] = phi i32 [ [[SHL:%.*]], [[WHILE_BODY]] ], [ [[N]], [[WHILE_BODY_PREHEADER]] ]
; ALL-NEXT:    [[SHL]] = shl i32 [[N_ADDR_05]], 1
; ALL-NEXT:    [[INC]] = add nsw i32 [[I_06]], 1
; ALL-NEXT:    [[TCDEC]] = sub nsw i32 [[TCPHI]], 1
; ALL-NEXT:    [[TOBOOL:%.*]] = icmp eq i32 [[TCDEC]], 0
; ALL-NEXT:    br i1 [[TOBOOL]], label [[WHILE_END_LOOPEXIT:%.*]], label [[WHILE_BODY]]
; ALL:       while.end.loopexit:
; ALL-NEXT:    [[INC_LCSSA:%.*]] = phi i32 [ [[TMP1]], [[WHILE_BODY]] ]
; ALL-NEXT:    br label [[WHILE_END]]
; ALL:       while.end:
; ALL-NEXT:    [[I_0_LCSSA:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ [[INC_LCSSA]], [[WHILE_END_LOOPEXIT]] ]
; ALL-NEXT:    ret i32 [[I_0_LCSSA]]
;
entry:
  %tobool4 = icmp eq i32 %n, 0
  br i1 %tobool4, label %while.end, label %while.body.preheader

while.body.preheader:                             ; preds = %entry
  br label %while.body

while.body:                                       ; preds = %while.body.preheader, %while.body
  %i.06 = phi i32 [ %inc, %while.body ], [ 0, %while.body.preheader ]
  %n.addr.05 = phi i32 [ %shl, %while.body ], [ %n, %while.body.preheader ]
  %shl = shl i32 %n.addr.05, 1
  %inc = add nsw i32 %i.06, 1
  %tobool = icmp eq i32 %shl, 0
  br i1 %tobool, label %while.end.loopexit, label %while.body

while.end.loopexit:                               ; preds = %while.body
  br label %while.end

while.end:                                        ; preds = %while.end.loopexit, %entry
  %i.0.lcssa = phi i32 [ 0, %entry ], [ %inc, %while.end.loopexit ]
  ret i32 %i.0.lcssa
}

; Recognize CTTZ builtin pattern.
; Here it will replace the loop -
; assume builtin is always profitable.
;
; int cttz(int n)
; {
;   int i = 0;
;   while(n <<= 1) {
;     i++;
;   }
;   return i;
; }
;
define i32 @cttz(i32 %n) {
; ALL-LABEL: @cttz(
; ALL-NEXT:  entry:
; ALL-NEXT:    [[TMP0:%.*]] = shl i32 [[N:%.*]], 1
; ALL-NEXT:    [[TMP1:%.*]] = call i32 @llvm.cttz.i32(i32 [[TMP0]], i1 false)
; ALL-NEXT:    [[TMP2:%.*]] = sub i32 32, [[TMP1]]
; ALL-NEXT:    [[TMP3:%.*]] = add i32 [[TMP2]], 1
; ALL-NEXT:    br label [[WHILE_COND:%.*]]
; ALL:       while.cond:
; ALL-NEXT:    [[TCPHI:%.*]] = phi i32 [ [[TMP3]], [[ENTRY:%.*]] ], [ [[TCDEC:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[N_ADDR_0:%.*]] = phi i32 [ [[N]], [[ENTRY]] ], [ [[SHL:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[I_0:%.*]] = phi i32 [ 0, [[ENTRY]] ], [ [[INC:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[SHL]] = shl i32 [[N_ADDR_0]], 1
; ALL-NEXT:    [[TCDEC]] = sub nsw i32 [[TCPHI]], 1
; ALL-NEXT:    [[TOBOOL:%.*]] = icmp eq i32 [[TCDEC]], 0
; ALL-NEXT:    [[INC]] = add nsw i32 [[I_0]], 1
; ALL-NEXT:    br i1 [[TOBOOL]], label [[WHILE_END:%.*]], label [[WHILE_COND]]
; ALL:       while.end:
; ALL-NEXT:    [[I_0_LCSSA:%.*]] = phi i32 [ [[TMP2]], [[WHILE_COND]] ]
; ALL-NEXT:    ret i32 [[I_0_LCSSA]]
;
entry:
  br label %while.cond

while.cond:                                       ; preds = %while.cond, %entry
  %n.addr.0 = phi i32 [ %n, %entry ], [ %shl, %while.cond ]
  %i.0 = phi i32 [ 0, %entry ], [ %inc, %while.cond ]
  %shl = shl i32 %n.addr.0, 1
  %tobool = icmp eq i32 %shl, 0
  %inc = add nsw i32 %i.0, 1
  br i1 %tobool, label %while.end, label %while.cond

while.end:                                        ; preds = %while.cond
  ret i32 %i.0
}

; Recognize CTTZ builtin pattern.
; Here it will replace the loop -
; assume builtin is always profitable.
;
; int ctlz_decrement(int n)
; {
;   int i = 32;
;   while(n) {
;     n <<= 1;
;     i--;
;   }
;   return i;
; }
;
define i32 @cttz_decrement(i32 %n) {
; ALL-LABEL: @cttz_decrement(
; ALL-NEXT:  entry:
; ALL-NEXT:    [[TOBOOL4:%.*]] = icmp eq i32 [[N:%.*]], 0
; ALL-NEXT:    br i1 [[TOBOOL4]], label [[WHILE_END:%.*]], label [[WHILE_BODY_PREHEADER:%.*]]
; ALL:       while.body.preheader:
; ALL-NEXT:    [[TMP0:%.*]] = call i32 @llvm.cttz.i32(i32 [[N]], i1 true)
; ALL-NEXT:    [[TMP1:%.*]] = sub i32 32, [[TMP0]]
; ALL-NEXT:    [[TMP2:%.*]] = sub i32 32, [[TMP1]]
; ALL-NEXT:    br label [[WHILE_BODY:%.*]]
; ALL:       while.body:
; ALL-NEXT:    [[TCPHI:%.*]] = phi i32 [ [[TMP1]], [[WHILE_BODY_PREHEADER]] ], [ [[TCDEC:%.*]], [[WHILE_BODY]] ]
; ALL-NEXT:    [[I_06:%.*]] = phi i32 [ [[INC:%.*]], [[WHILE_BODY]] ], [ 32, [[WHILE_BODY_PREHEADER]] ]
; ALL-NEXT:    [[N_ADDR_05:%.*]] = phi i32 [ [[SHL:%.*]], [[WHILE_BODY]] ], [ [[N]], [[WHILE_BODY_PREHEADER]] ]
; ALL-NEXT:    [[SHL]] = shl i32 [[N_ADDR_05]], 1
; ALL-NEXT:    [[INC]] = add nsw i32 [[I_06]], -1
; ALL-NEXT:    [[TCDEC]] = sub nsw i32 [[TCPHI]], 1
; ALL-NEXT:    [[TOBOOL:%.*]] = icmp eq i32 [[TCDEC]], 0
; ALL-NEXT:    br i1 [[TOBOOL]], label [[WHILE_END_LOOPEXIT:%.*]], label [[WHILE_BODY]]
; ALL:       while.end.loopexit:
; ALL-NEXT:    [[INC_LCSSA:%.*]] = phi i32 [ [[TMP2]], [[WHILE_BODY]] ]
; ALL-NEXT:    br label [[WHILE_END]]
; ALL:       while.end:
; ALL-NEXT:    [[I_0_LCSSA:%.*]] = phi i32 [ 32, [[ENTRY:%.*]] ], [ [[INC_LCSSA]], [[WHILE_END_LOOPEXIT]] ]
; ALL-NEXT:    ret i32 [[I_0_LCSSA]]
;
entry:
  %tobool4 = icmp eq i32 %n, 0
  br i1 %tobool4, label %while.end, label %while.body.preheader

while.body.preheader:                             ; preds = %entry
  br label %while.body

while.body:                                       ; preds = %while.body.preheader, %while.body
  %i.06 = phi i32 [ %inc, %while.body ], [ 32, %while.body.preheader ]
  %n.addr.05 = phi i32 [ %shl, %while.body ], [ %n, %while.body.preheader ]
  %shl = shl i32 %n.addr.05, 1
  %inc = add nsw i32 %i.06, -1
  %tobool = icmp eq i32 %shl, 0
  br i1 %tobool, label %while.end.loopexit, label %while.body

while.end.loopexit:                               ; preds = %while.body
  br label %while.end

while.end:                                        ; preds = %while.end.loopexit, %entry
  %i.0.lcssa = phi i32 [ 32, %entry ], [ %inc, %while.end.loopexit ]
  ret i32 %i.0.lcssa
}

; Recognize CTTZ builtin pattern.
; Here it will replace the loop -
; assume builtin is always profitable.
;
; int cttz_shl_decrement(int n)
; {
;   int i = 31;
;   while(n <<= 1) {
;     i--;
;   }
;   return i;
; }
;
define i32 @cttz_shl_decrement(i32 %n) {
; ALL-LABEL: @cttz_shl_decrement(
; ALL-NEXT:  entry:
; ALL-NEXT:    [[TMP0:%.*]] = shl i32 [[N:%.*]], 1
; ALL-NEXT:    [[TMP1:%.*]] = call i32 @llvm.cttz.i32(i32 [[TMP0]], i1 false)
; ALL-NEXT:    [[TMP2:%.*]] = sub i32 32, [[TMP1]]
; ALL-NEXT:    [[TMP3:%.*]] = add i32 [[TMP2]], 1
; ALL-NEXT:    [[TMP4:%.*]] = sub i32 31, [[TMP2]]
; ALL-NEXT:    br label [[WHILE_COND:%.*]]
; ALL:       while.cond:
; ALL-NEXT:    [[TCPHI:%.*]] = phi i32 [ [[TMP3]], [[ENTRY:%.*]] ], [ [[TCDEC:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[N_ADDR_0:%.*]] = phi i32 [ [[N]], [[ENTRY]] ], [ [[SHL:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[I_0:%.*]] = phi i32 [ 31, [[ENTRY]] ], [ [[INC:%.*]], [[WHILE_COND]] ]
; ALL-NEXT:    [[SHL]] = shl i32 [[N_ADDR_0]], 1
; ALL-NEXT:    [[TCDEC]] = sub nsw i32 [[TCPHI]], 1
; ALL-NEXT:    [[TOBOOL:%.*]] = icmp eq i32 [[TCDEC]], 0
; ALL-NEXT:    [[INC]] = add nsw i32 [[I_0]], -1
; ALL-NEXT:    br i1 [[TOBOOL]], label [[WHILE_END:%.*]], label [[WHILE_COND]]
; ALL:       while.end:
; ALL-NEXT:    [[I_0_LCSSA:%.*]] = phi i32 [ [[TMP4]], [[WHILE_COND]] ]
; ALL-NEXT:    ret i32 [[I_0_LCSSA]]
;
entry:
  br label %while.cond

while.cond:                                       ; preds = %while.cond, %entry
  %n.addr.0 = phi i32 [ %n, %entry ], [ %shl, %while.cond ]
  %i.0 = phi i32 [ 31, %entry ], [ %inc, %while.cond ]
  %shl = shl i32 %n.addr.0, 1
  %tobool = icmp eq i32 %shl, 0
  %inc = add nsw i32 %i.0, -1
  br i1 %tobool, label %while.end, label %while.cond

while.end:                                        ; preds = %while.cond
  ret i32 %i.0
}
