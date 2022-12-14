target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.11.0"

; Alias are not optimized
@linkonceodralias = linkonce_odr alias void (), ptr @linkonceodrfuncwithalias

; Alias are not optimized
@linkoncealias = linkonce alias void (), ptr @linkoncefuncwithalias

; Function with an alias are not optimized
define linkonce_odr void @linkonceodrfuncwithalias() #0 {
entry:
  ret void
}

; Function with an alias are not optimized
define linkonce void @linkoncefuncwithalias() #0 {
entry:
  ret void
}

define linkonce_odr void @linkonceodrfunc() #0 {
entry:
  ret void
}
define linkonce void @linkoncefunc() #0 {
entry:
  ret void
}
define weak_odr void @weakodrfunc() #0 {
entry:
  ret void
}
define weak void @weakfunc() #0 {
entry:
  ret void
}

