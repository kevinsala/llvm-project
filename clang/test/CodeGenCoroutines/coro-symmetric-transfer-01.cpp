// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -std=c++20 -O0 -emit-llvm %s -o - -disable-llvm-passes | FileCheck %s
// RUN: %clang -std=c++20 -O0 -emit-llvm -c  %s -o %t -Xclang -disable-llvm-passes && %clang -c %t

#include "Inputs/coroutine.h"

struct detached_task {
  struct promise_type {
    detached_task get_return_object() noexcept {
      return detached_task{std::coroutine_handle<promise_type>::from_promise(*this)};
    }

    void return_void() noexcept {}

    struct final_awaiter {
      bool await_ready() noexcept { return false; }
      std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_type> h) noexcept {
        h.destroy();
        return {};
      }
      void await_resume() noexcept {}
    };

    void unhandled_exception() noexcept {}

    final_awaiter final_suspend() noexcept { return {}; }

    std::suspend_always initial_suspend() noexcept { return {}; }
  };

  ~detached_task() {
    if (coro_) {
      coro_.destroy();
      coro_ = {};
    }
  }

  void start() && {
    auto tmp = coro_;
    coro_ = {};
    tmp.resume();
  }

  std::coroutine_handle<promise_type> coro_;
};

detached_task foo() {
  co_return;
}

// check that the lifetime of the coroutine handle used to obtain the address is contained within single basic block, and hence does not live across suspension points.
// CHECK-LABEL: final.suspend:
// CHECK:         %{{.+}} = call token @llvm.coro.save(ptr null)
// CHECK:         call void @llvm.lifetime.start.p0(i64 8, ptr %[[HDL:.+]])
// CHECK:         %[[CALL:.+]] = call ptr @_ZN13detached_task12promise_type13final_awaiter13await_suspendESt16coroutine_handleIS0_E(
// CHECK:         %[[HDL_CAST2:.+]] = getelementptr inbounds %"struct.std::coroutine_handle.0", ptr %[[HDL]], i32 0, i32 0
// CHECK:         store ptr %[[CALL]], ptr %[[HDL_CAST2]], align 8
// CHECK:         %[[HDL_TRANSFER:.+]] = call noundef ptr @_ZNKSt16coroutine_handleIvE7addressEv(ptr noundef {{.*}}%[[HDL]])
// CHECK:         call void @llvm.lifetime.end.p0(i64 8, ptr %[[HDL]])
// CHECK:         call void @llvm.coro.resume(ptr %[[HDL_TRANSFER]])
