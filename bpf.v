Require Import PeanoNat.

Section Syntax.

Definition reg_index := nat.
Definition double_word := nat.
Definition offset_type := nat.
Definition byte := nat.

Inductive reg_or_imm :=
  | reg (n: nat)
  | imm (v: double_word)
.

Inductive alu_op :=
  | op_add | op_sub | op_mul | op_div | op_mod
  | op_or  | op_lsh | op_rsh | op_xor | op_arsh
  | op_mov
.

Inductive cmp_op :=
  | cmp_eq | cmp_neq
  | cmp_lt | cmp_lte | cmp_slt | cmp_sle
  | cmp_gt | cmp_gte | cmp_sgt | cmp_sge
.

Definition width := {w | w = 1 \/ w = 2 \/ w = 4 \/ w = 8}.

Inductive load_type :=
  | lt_simple
  | lt_ind
  | lt_abs
.

Inductive store_type :=
  | st_simple
  | st_ind
  | st_abs
.

Inductive instruction :=
  | bpf_alu (op: alu_op) (dst: reg_index) (src: reg_or_imm) (wide: bool)
  | bpf_neg (dst: reg_index) (wide: bool)
  | bpf_load (dst: reg_index) (src: reg_index) (offset: offset_type) (t: load_type) (w: width)
  | bpf_store (src: reg_index) (dst: reg_index) (offset: offset_type) (t: store_type) (w: width)
  | bpf_jump (op: cmp_op) (a: reg_index) (b: reg_or_imm) (offset: offset_type) (wide: bool)
  | bpf_goto (offset: offset_type)
  | bpf_call (func: nat)
  | bpf_exit
.

End Syntax.

Section InsSemantics.

Definition kind := nat.

Definition kind_beq := Nat.eqb.
(* Scheme Equality for kind. *)

Inductive value :=
  | uninitialized
  | number (n: double_word)
  | pointer (k: kind) (offset: nat)
.


Definition value_sub (a b : value) :=
  match (a, b) with
  | (uninitialized, _) => None
  | (_, uninitialized) => None
  | (number n1, number n2) => Some (number (n1 - n2))
  | (number _, _) => None
  | (pointer k offset, number n) => Some (pointer k (offset - n))
  | (pointer k1 offset1, pointer k2 offset2) =>
      if kind_beq k1 k2 then Some (pointer k1 (offset1 - offset2))
      else None
  end.

Definition value_add (a b : value) :=
  match (a, b) with
  | (uninitialized, _) => None
  | (_, uninitialized) => None
  | (number n1, number n2) => Some (number (n1 + n2))
  | (number n, pointer k offset) => Some (pointer k (n + offset))
  | (pointer k offset, number n) => Some (pointer k (offset + n))
  | (pointer _ _, pointer _ _) => None
  end.


Record env := {
  prog: list (list instruction);
  prog_type: nat;
  maps: nat -> bool
}.

Variable e: env.

Definition mem := nat -> byte.

Record state := mkState {
  pc: nat;
  regs : reg_index -> value;
  memory: kind -> mem;
  sizes: kind -> nat
}.

Definition update_pc p (s s': state) : Prop :=
  s' = mkState p (regs s) (memory s) (sizes s).

Definition update_reg r v (s s': state) : Prop :=
  s' = mkState (pc s) (fun i => if i =? r then v else regs s i) (memory s) (sizes s).

Definition update_mem k m (s s': state) : Prop :=
  s' = mkState (pc s) (regs s) (fun k' => if kind_beq k' k then m else (memory s k)) (sizes s).

Axiom cmp : cmp_op -> reg_index -> reg_or_imm -> bool.

Axiom func_call : state -> state -> Prop.

Axiom load : nat -> load_type -> width -> mem -> value.
Axiom store : nat -> store_type -> width -> value -> mem -> mem.

Axiom offset_of : value -> nat.
Axiom kind_of : value -> kind.

(* A realtion beacause reads from maps are not deterministic *)
Definition step (inst: instruction) (s s': state) : Prop :=
  match inst with
  | bpf_alu op dst src wide => False

  | bpf_neg dst wide => False

  | bpf_load dst src offset t w =>
      let src_v := regs s src in
      let m := memory s (kind_of src_v) in
      let reg := load (offset_of src_v + offset) t w m in
      update_reg dst reg s s'

  | bpf_store src dst offset t w =>
      let dst_v := regs s dst in
      let k := kind_of dst_v in
      let m' := store (offset_of dst_v + offset) t w (regs s src) (memory s k) in
      update_mem k m' s s'

  | bpf_jump op a b offset wide =>
      cmp op a b = true -> update_pc (pc s + offset) s s'

  | bpf_goto offset =>
      update_pc (pc s + offset) s s'

  | bpf_call func =>
      func_call s s'

  | bpf_exit => False
  end
.

Inductive error_classes :=
  | write_out_of_bounds
  | read_out_of_bounds (* since it can crash *)
  | divide_by_zero
  | no_instructions_left
.

Inductive leak_classes :=
  | return_uninit  | compare_uninit  | write_uninit_to_map
  | return_address | compare_address_to_number | compare_addresses_from_different_region | write_address_to_map
.

Inductive defense_classes :=
  | write_uninit_to_stack | read_misaligned_ptr | unable_to_find_recursion
.

End InsSemantics.
