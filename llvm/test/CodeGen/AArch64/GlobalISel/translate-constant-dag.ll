; NOTE: Assertions have been autogenerated by utils/update_mir_test_checks.py
; RUN: llc -mtriple aarch64 -O0 -stop-after=instruction-select -global-isel -verify-machineinstrs %s -o - 2>&1 | FileCheck %s

%dag = type { { { i8, { i8 } }, { { i8, { i8 } }, { i8 } } }, { { i8, { i8 } }, { i8 } } }

define void @test_const(ptr %dst) {
  ; CHECK-LABEL: name: test_const
  ; CHECK: bb.1.entry:
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:gpr64sp = COPY $x0
  ; CHECK:   [[MOVi32imm:%[0-9]+]]:gpr32 = MOVi32imm 10
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 0 :: (store (s8) into %ir.dst)
  ; CHECK:   [[MOVi32imm1:%[0-9]+]]:gpr32 = MOVi32imm 20
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 1 :: (store (s8) into %ir.dst + 1)
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 2 :: (store (s8) into %ir.dst + 2)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 3 :: (store (s8) into %ir.dst + 3)
  ; CHECK:   [[MOVi32imm2:%[0-9]+]]:gpr32 = MOVi32imm 50
  ; CHECK:   STRBBui [[MOVi32imm2]], [[COPY]], 4 :: (store (s8) into %ir.dst + 4)
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 5 :: (store (s8) into %ir.dst + 5)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 6 :: (store (s8) into %ir.dst + 6)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 7 :: (store (s8) into %ir.dst + 7)
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 0 :: (store (s8) into %ir.dst)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 1 :: (store (s8) into %ir.dst + 1)
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 2 :: (store (s8) into %ir.dst + 2)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 3 :: (store (s8) into %ir.dst + 3)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 4 :: (store (s8) into %ir.dst + 4)
  ; CHECK:   STRBBui [[MOVi32imm]], [[COPY]], 5 :: (store (s8) into %ir.dst + 5)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 6 :: (store (s8) into %ir.dst + 6)
  ; CHECK:   STRBBui [[MOVi32imm1]], [[COPY]], 7 :: (store (s8) into %ir.dst + 7)
  ; CHECK:   RET_ReallyLR
entry:
 %updated = insertvalue
   ; Check that we're visiting constants with shared parts
   ; (deduplicated via LLVMContext, forming a proper DAG) correctly:
   %dag {
     { { i8, { i8 } }, { { i8, { i8 } }, { i8 } } } {
       { i8, { i8 } } {
         i8 10,
         { i8 } { i8 20 }
       },
       { { i8, { i8 } }, { i8 } } {
         { i8, { i8 } } {
           i8 10,
           { i8 } { i8 20 }
         },
         { i8 } { i8 20 }
       }
     },
     { { i8, { i8 } }, { i8 } } {
       { i8, { i8 } } {
         i8 10,
         { i8 } { i8 20 }
       },
       { i8 } { i8 20 }
     }
   },
   { { i8, { i8 } }, { i8 } } {
     { i8, { i8 } } {
       i8 10,
       { i8 } { i8 20 }
     },
     { i8 } { i8 50 }
   },
   0,
   1
 store %dag %updated, ptr %dst
 ; 10, 20, 10, 20, 50, 10, 20, 20 sequence is expected

 store
   ; Check that we didn't overwrite a previously seen constant
   ; while processing an insertvalue into it:
   %dag {
     { { i8, { i8 } }, { { i8, { i8 } }, { i8 } } } {
       { i8, { i8 } } {
         i8 10,
         { i8 } { i8 20 }
       },
       { { i8, { i8 } }, { i8 } } {
         { i8, { i8 } } {
           i8 10,
           { i8 } { i8 20 }
         },
         { i8 } { i8 20 }
       }
     },
     { { i8, { i8 } }, { i8 } } {
       { i8, { i8 } } {
         i8 10,
         { i8 } { i8 20 }
       },
       { i8 } { i8 20 }
     }
   },
   ptr %dst
 ; 10, 20, 10, 20, 20, 10, 20, 20 sequence is expected
 ret void
}
