; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -S -passes=simplifycfg -simplifycfg-require-and-preserve-domtree=1 | FileCheck %s

declare void @foo()
declare void @bar()

define void @test_and1(i32 %a, i32 %b) {
; CHECK-LABEL: @test_and1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP1:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMP2:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[AND:%.*]] = and i1 [[CMP1]], [[CMP2]]
; CHECK-NEXT:    br i1 [[AND]], label [[TAKEN:%.*]], label [[END:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
entry:
  %cmp1 = icmp eq i32 %a, 0
  %cmp2 = icmp eq i32 %b, 0
  %and = and i1 %cmp1, %cmp2
  br i1 %and, label %taken, label %end

taken:
  call void @bar()
  %cmp3 = icmp eq i32 %a, 0  ;; <-- implied true
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

; We can't infer anything if the result of the 'and' is false

define void @test_and2(i32 %a, i32 %b) {
; CHECK-LABEL: @test_and2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP1:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMP2:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[AND:%.*]] = and i1 [[CMP1]], [[CMP2]]
; CHECK-NEXT:    br i1 [[AND]], label [[END:%.*]], label [[TAKEN:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    [[CMP3:%.*]] = icmp eq i32 [[A]], 0
; CHECK-NEXT:    br i1 [[CMP3]], label [[IF_THEN:%.*]], label [[END]]
; CHECK:       if.then:
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
entry:
  %cmp1 = icmp eq i32 %a, 0
  %cmp2 = icmp eq i32 %b, 0
  %and = and i1 %cmp1, %cmp2
  br i1 %and, label %end, label %taken

taken:
  call void @bar()
  %cmp3 = icmp eq i32 %a, 0
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

define void @test_or1(i32 %a, i32 %b) {
; CHECK-LABEL: @test_or1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP1:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMP2:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[OR:%.*]] = or i1 [[CMP1]], [[CMP2]]
; CHECK-NEXT:    br i1 [[OR]], label [[END:%.*]], label [[TAKEN:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
entry:
  %cmp1 = icmp eq i32 %a, 0
  %cmp2 = icmp eq i32 %b, 0
  %or = or i1 %cmp1, %cmp2
  br i1 %or, label %end, label %taken

taken:
  call void @bar()
  %cmp3 = icmp ne i32 %a, 0   ;; <-- implied true
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

; We can't infer anything if the result of the 'or' is true

define void @test_or2(i32 %a, i32 %b) {
; CHECK-LABEL: @test_or2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP1:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMP2:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[OR:%.*]] = or i1 [[CMP1]], [[CMP2]]
; CHECK-NEXT:    br i1 [[OR]], label [[TAKEN:%.*]], label [[END:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    [[CMP3:%.*]] = icmp eq i32 [[A]], 0
; CHECK-NEXT:    br i1 [[CMP3]], label [[IF_THEN:%.*]], label [[END]]
; CHECK:       if.then:
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
entry:
  %cmp1 = icmp eq i32 %a, 0
  %cmp2 = icmp eq i32 %b, 0
  %or = or i1 %cmp1, %cmp2
  br i1 %or, label %taken, label %end

taken:
  call void @bar()
  %cmp3 = icmp eq i32 %a, 0
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

; We can recurse a tree of 'and' or 'or's.

define void @test_and_recurse1(i32 %a, i32 %b, i32 %c) {
; CHECK-LABEL: @test_and_recurse1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMPA:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMPB:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[CMPC:%.*]] = icmp eq i32 [[C:%.*]], 0
; CHECK-NEXT:    [[AND1:%.*]] = and i1 [[CMPA]], [[CMPB]]
; CHECK-NEXT:    [[AND2:%.*]] = and i1 [[AND1]], [[CMPC]]
; CHECK-NEXT:    br i1 [[AND2]], label [[TAKEN:%.*]], label [[END:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
entry:
  %cmpa = icmp eq i32 %a, 0
  %cmpb = icmp eq i32 %b, 0
  %cmpc = icmp eq i32 %c, 0
  %and1 = and i1 %cmpa, %cmpb
  %and2 = and i1 %and1, %cmpc
  br i1 %and2, label %taken, label %end

taken:
  call void @bar()
  %cmp3 = icmp eq i32 %a, 0
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

; Check to make sure we don't recurse too deep.

define void @test_and_recurse2(i32 %a, i32 %b, i32 %c, i32 %d, i32 %e, i32 %f,
; CHECK-LABEL: @test_and_recurse2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMPA:%.*]] = icmp eq i32 [[A:%.*]], 0
; CHECK-NEXT:    [[CMPB:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    [[CMPC:%.*]] = icmp eq i32 [[C:%.*]], 0
; CHECK-NEXT:    [[CMPD:%.*]] = icmp eq i32 [[D:%.*]], 0
; CHECK-NEXT:    [[CMPE:%.*]] = icmp eq i32 [[E:%.*]], 0
; CHECK-NEXT:    [[CMPF:%.*]] = icmp eq i32 [[F:%.*]], 0
; CHECK-NEXT:    [[CMPG:%.*]] = icmp eq i32 [[G:%.*]], 0
; CHECK-NEXT:    [[CMPH:%.*]] = icmp eq i32 [[H:%.*]], 0
; CHECK-NEXT:    [[AND1:%.*]] = and i1 [[CMPA]], [[CMPB]]
; CHECK-NEXT:    [[AND2:%.*]] = and i1 [[AND1]], [[CMPC]]
; CHECK-NEXT:    [[AND3:%.*]] = and i1 [[AND2]], [[CMPD]]
; CHECK-NEXT:    [[AND4:%.*]] = and i1 [[AND3]], [[CMPE]]
; CHECK-NEXT:    [[AND5:%.*]] = and i1 [[AND4]], [[CMPF]]
; CHECK-NEXT:    [[AND6:%.*]] = and i1 [[AND5]], [[CMPG]]
; CHECK-NEXT:    [[AND7:%.*]] = and i1 [[AND6]], [[CMPH]]
; CHECK-NEXT:    br i1 [[AND7]], label [[TAKEN:%.*]], label [[END:%.*]]
; CHECK:       taken:
; CHECK-NEXT:    call void @bar()
; CHECK-NEXT:    [[CMP3:%.*]] = icmp eq i32 [[A]], 0
; CHECK-NEXT:    br i1 [[CMP3]], label [[IF_THEN:%.*]], label [[END]]
; CHECK:       if.then:
; CHECK-NEXT:    call void @foo()
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    ret void
;
  i32 %g, i32 %h) {
entry:
  %cmpa = icmp eq i32 %a, 0
  %cmpb = icmp eq i32 %b, 0
  %cmpc = icmp eq i32 %c, 0
  %cmpd = icmp eq i32 %d, 0
  %cmpe = icmp eq i32 %e, 0
  %cmpf = icmp eq i32 %f, 0
  %cmpg = icmp eq i32 %g, 0
  %cmph = icmp eq i32 %h, 0
  %and1 = and i1 %cmpa, %cmpb
  %and2 = and i1 %and1, %cmpc
  %and3 = and i1 %and2, %cmpd
  %and4 = and i1 %and3, %cmpe
  %and5 = and i1 %and4, %cmpf
  %and6 = and i1 %and5, %cmpg
  %and7 = and i1 %and6, %cmph
  br i1 %and7, label %taken, label %end

taken:
  call void @bar()
  %cmp3 = icmp eq i32 %a, 0 ; <-- can be implied true
  br i1 %cmp3, label %if.then, label %end

if.then:
  call void @foo()
  br label %end

end:
  ret void
}

