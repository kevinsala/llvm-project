// RUN: %clang_cc1 %s -emit-llvm -triple x86_64-apple-darwin -o - | FileCheck %s

// Make sure pointers are passed as pointers, not converted to int.
// The first load should be of type ptr in either 32 or 64 bit mode.
// This formerly happened on x86-64, 7375899.

class StringRef {
public:
  const char *Data;
  long Len;
};
void foo(StringRef X);
void bar(StringRef &A) {
// CHECK: @_Z3barR9StringRef
// CHECK: load ptr, ptr
  foo(A);
// CHECK: ret void
}
