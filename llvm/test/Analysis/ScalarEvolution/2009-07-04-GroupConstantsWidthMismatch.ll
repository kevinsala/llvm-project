; RUN: opt < %s -passes='print<scalar-evolution>'
; PR4501

define void @test() {
entry:
        %0 = load i16, ptr undef, align 1
        %1 = lshr i16 %0, 8
        %2 = and i16 %1, 3
        %3 = zext i16 %2 to i32
        %4 = load i8, ptr undef, align 1
        %5 = lshr i8 %4, 4
        %6 = and i8 %5, 1
        %7 = zext i8 %6 to i32
        %t1 = add i32 %3, %7
        ret void
}
