target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

@bar = alias void (), ptr @zed
define void @zed() {
  ret void
}
