target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

define weak dso_local noundef i32 @foo() local_unnamed_addr {
  ret i32 1234
}
