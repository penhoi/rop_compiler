import paktCommon
from paktAst import *
from paktCdefs import *

def instr_type(x):
    #(* T0, because we want them at every stage *)
    if type(x) in [Lbl, Comment, AdvanceStack, RawHex, MovRegConst, MovRegReg, MovRegSymb, WriteM, ReadM, SaveFlags, OpStack, BinO]:
        return T0
    elif type(x) in [ReadMConst, WriteMConst]:
        return T1
    elif type(x) in [LocalAddr, PushReg, PopReg]:
        return T2
    elif type(x) in [WriteLocal, ReadLocal]:
        return T3


#(* IN: instr, gmeta list *)
#(* OUT: gmeta corresponding to instr *)
def find_all_gmetas(instr, gms):
    def find_gms(f_match):
        def pred(gm):
            g = gm.param()[0]
            return f_match(g, gm)

        return filter(pred, gms)

    def is_opstack(g):
        return type(g) == paktCommon.OpEsp
            
    def get_stack_fix(gm):
        sf = gm.param()[-1]
        return sf
    
    def f_match_movreg(r, g, gm):
        if type(g) == paktCommon.LoadConst:
            (gr, _) = g.param()
            return gr == r
        else:
            return False
        
    def f_match_op_esp(op, r, g, gm):
        if type(g) == paktCommon.OpEsp:
            (gop, gr, _) = g.param()
            return (gop == op) and (gr == r)
        else:
            return False

    def f_match():
        if type(instr) == OpStack:
            (op, C_r) = instr.param()
            r = r.param()
            op_prime = ast_op_to_gadget_op(op)
            return f_match_op_esp(op_prime, r)
        
        elif type(instr) == BinO:
            (C_r0, C_r1, op, C_r2) = instr.param()
            (r0) = C_r0.param()
            (r1) = C_r1.param()
            (r2) = C_r2.param()
            op_prime  = ast_op_to_gadget_op(op)
            return  (lambda(g, gm): g == paktCommon.BinOp(r0, r1, op_prime, r2))
        
        elif type(instr) == WriteM:
            (C_addr_reg, C_src_reg) = instr.param()
            addr_reg = C_addr_reg.param()
            src_reg = C_src_reg.param()
            return (lambda(g, gm): g == paktCommon.WriteMem(addr_reg, Int32.zero, src_reg))
        
        elif type(instr) == ReadM:
            (C_dst_reg, C_addr_reg) = instr.param()
            dst_reg = C_dst_reg.param()
            addr_reg = C_addr_reg.param()
            return (lambda(g, gm): g == paktCommon.ReadMem(dst_reg, addr_reg, Int32.zero))
        
        #(* movregsymb will be converted to mov reg const *)
        elif type(instr) in [MovRegConst, MovRegSymb]:
            (C_r) = instr.param()
            r = C_r.param()
            return f_match_movreg(r)

        elif type(instr) == MovRegReg:
            (C_dst, C_src) = instr.param()
            dst = C_dst.param()
            src = C_src.param()
            return (lambda(g, gm): g == paktCommon.CopyReg(dst, src))
        
        elif type(instr) == SaveFlags:
            return (lambda(g, gm): g == paktCommon.Lahf)
        
        elif type(instr) == AdvanceStack:
            n = instr.param()
            return (lambda(g, gm): (not is_opstack(g)) and (get_stack_fix(gm) == n))
                    
        #(* Can match anything, but this simplifies things *)
        elif type(instr) == RawHex:
            return (lambda(g, gm): get_stack_fix(gm) == 4)
        
        #(* we don't want to lose these, so match with anything *)
        elif type(instr) in [Lbl, Comment]:
            return (lambda(g, gm): True)
        
        else:
            raise Exception("analysys 105")

    matching_gms = find_gms(f_match)
    if len(matching_gms) == 0:
        raise Exception("anything 109")
    else:
        return matching_gms


def make_implement(stack_ptr, frame_ptr):
    def implement_t1(f_next_reg, instr):
        if type(instr) == ReadMConst:
            (r, addr) = instr.param()
            reg = f_next_reg()
            mov = MovRegConst(reg, addr)
            rm = ReadM(r, reg)
            return [mov, rm]
        
        elif type(instr) == WriteMConst:
            (addr, r) = instr.param()
            addr_reg = f_next_reg()
            mov = MovRegConst(addr_reg, addr)
            wm = WriteM(addr_reg, r)
            return [mov, wm]
        else:
            raise Exception("analysys 129")

    def implement_t2(f_next_reg, instr):
        if type(instr) == PushReg:
            r = instr.param()
            addr_reg = f_next_reg()
            rm = ReadMConst(addr_reg, stack_ptr)
            wm1 = WriteM(addr_reg, r)
            reg1 = f_next_reg()
            rm2 = ReadMConst(reg1, stack_ptr) in
            reg2 = f_next_reg()
            mov = MovRegConst(reg2, 4)
            reg3 = f_next_reg()
            sub = BinO(reg3, reg1, Sub, reg2)
            wm2 = WriteMConst(stack_ptr, reg3)
            return [rm, wm1, rm2, mov, sub, wm2]
        
        elif type(instr) == PopReg:
            r = instr.param()
            reg1 = f_next_reg()
            rm1 = ReadMConst(reg1, stack_ptr)
            reg2 = f_next_reg()
            mov = MovRegConst(reg2, 4)
            reg3 = f_next_reg()
            sub = BinO(reg3, reg1, Add, reg2)
            wm = WriteMConst(stack_ptr, reg3)
            rm2 = ReadM(r, reg3)
            return [rm1, mov, sub, wm, rm2]
        
        elif type(instr) == LocalAddr:
            (off, r) = instr.param()
            reg1 = f_next_reg()
            rm1 = ReadMConst(reg1, frame_ptr)
            reg2 = f_next_reg()
            mov = MovRegConst(reg2, off)
            add = BinO(r, reg1, Add, reg2)
            return [rm1, mov, add]
        
        else:
            raise Exception("analysys 165")

    def implement_t3(f_next_reg, instr):
        if type(instr) == ReadLocal:
            (off, r) = instr.param()
            addr_reg = f_next_reg()
            la = LocalAddr(off, addr_reg)
            rm = ReadM(r, addr_reg)
            return [la, rm]
        
        elif type(instr) == WriteLocal:
            (off, r) = instr.param()
            addr_reg = f_next_reg()
            la = LocalAddr(off, addr_reg)
            wm = WriteM(addr_reg, r)
            return [la, wm]
        
        #(* Caller should be aware these are special *)
        elif type(instr) == Lbl:
            return []

        elif type(instr) == Comment:
            raise Exception("analysys 184")
        else:
            raise Exception("analysys 186")

    def implement(instr):
        def type2idx(typ):
            if typ == T3:
                return  2
            elif typ == T2:
                return  1
            elif typ == T1:
                return 0
            elif typ == T0:
                raise Exception(analysys 197)
        def init():
            f_next_reg = make_reg_generator()
            funs = [implement_t1;implement_t2;implement_t3] #?????
            funs = List.map(fun f -> f f_next_reg) funs #?????
            funs

        funs = init()
        typ = instr_type(instr)
        idx = type2idx(typ)
        f_implement = List.nth(funs idx) #?????
        return f_implement(instr)

def arg_dumper(instr):
    if type(instr) == AdvanceStack:
        return []
    elif type(instr) == RawHex:
        return []
    elif type(instr) == MovRegConst:
        (a1, _) = instr.param()
        return [a1]
    elif type(instr) == MovRegReg:
        (a1, a2) = instr.param()
        returns [a1, a2]
    elif type(instr) == MovRegSymb:
        (a1, _) = instr.param()
        return [a1]
    elif type(instr) == WriteM:
        (a1, a2) = instr.param()
        return [a1, a2]
    elif type(instr) == ReadM:
        (a1, a2) = instr.param()
        return [a1, a2]
    elif type(instr) == SaveFlags:
        return []
    elif type(instr) == OpStack:
        (_, a1) = instr.param()
        return [a1]
    elif type(instr) == BinO:
        (a1, a2, _, a3) = instr.param()
        return [a1, a2, a3]

    elif type(instr) == ReadMConst:
        (a1, _) = instr.param()

    elif type(instr) == WriteMConst:
        (_, a1) = instr.param()
        return [a1]
    elif type(instr) == LocalAddr:
        (_, a1) = instr.param()
        return [a1]
    elif type(instr) == PushReg:
        (a1) = instr.param()
    elif type(instr) == PopReg:
        (a1) = instr.param()
        return [a1]
    elif type(instr) == ReadLocal:
        (_, a1) = instr.param()
    elif type(instr) == WriteLocal:
        (_, a1) = instr.param()
        return [a1]
    elif type(instr) == Lbl:
        (_) = instr.param()
    elif type(instr) == Comment:
        (_) = instr.param()
        return []

def number_of_args(instr):
    return len (arg_dumper(instr))

def arg_positions(instr, arg):#?????
    args = arg_dumper(instr)
    let enum(i, l) x = (i+1,(i, x)::l) in #?????
    let _, args = List.fold_left enum(0,[]) args in #?????拷贝先前的定义
    let args = List.filter(fun (_, a) -> a=arg) args in
    positions = List.map(fst args)
    positions

#(* get possible regs at position pos for instructions matching type of instr.
# * for example: BinOp(r0, _,+,_) 0 -> possible values for r0 *)
def possible_regs_t0(gms, instr):
    def f_binop(op):
        def f(acc, g):
            if type(g) == paktCommon.BinOp:
                (r0, r1, op1, r2) = g.param()
                if op == op1:
                    return [r0, r1, r2]+acc
                else:
                    return acc
            elif type(g) == _:
                return acc

        return f(acc, g)

    def f_op_esp(op):
        def f(acc, g):
            if type(g) == paktCommon.OpEsp:
                (op1, r, _) = g.param()
                if op == op1:
                    return [r] + acc
                else:
                    return acc
            elif type(g) == _:
                return acc
        return f(acc, g)

    def f_write_mem(acc, g):
        if type(g) == paktCommon.WriteMem:
            (r0, _, r1) = g.param()
            return [r0, r1]+acc
        elif type(g) == _ :
            return acc

    def f_read_mem(acc, g):
        if type(g) == paktCommon.ReadMem:
            (r0, r1, _) = g.param()
            return [r0, r1]+acc
        elif type(g) == _:
            return acc

    def f_load_const(acc, g):
        if type(g) == paktCommon.LoadConst:
            (r, _) = g.param()
            return [r]+acc
        elif type(g) == _:
            return acc

    def f_copy_reg(acc, g):
        if type(g) == paktCommon.CopyReg:
            (r0, r1) = g.param()
            return [r0, r1] + acc
        elif type(g) == _:
            return acc

    #(* [[a1;..];[b1..]] -> [a1;b1],[[..];[..]] *)
    def group_args(regs):
        def f(heads, tails, l):
            if len(l) != 0:
                if len(l) > 1:
                    return l[0] + heads + l[1:] + tails
                else:
                    return l + heads + tails
            else:
                raise Exception("analysis 314")

        def aux(acc, ll):

            match ll with
            | (hd::_)::tll -> #(* at least one non-empty list *)
                let(heads, tails) = List.fold_left f([],[]) ll in#拷贝先前的定义
                aux(heads::acc) tails
            elif type() == _:
             List.rev acc

        aux [] regs

    def make_sets(groups):#?????
        def f(acc, l):
            set = Cdefs.set_from_list(l)
            set::acc

        let sets = List.fold_left f [] groups in
        List.rev sets

    def f_collect():
        if type(instr) == OpStack:
            (op, _) = instr.param()
            op1 = ast_op_to_gadget_op(op)
            return f_op_esp(op1)
        elif type(instr) == WriteM:
            (_, _) = instr.param
            return f_write_mem#不带任何参数
        elif type(instr) == BinO:
            (_, _, op, _) = instr.param()
            op1 = ast_op_to_gadget_op(op)
            return f_binop(op1)
        elif type(instr) == ReadM:
            return f_read_mem
        #(* movregsymb will be converted to mov reg const *)#?????
        elif type(instr) == MovRegConst:(_, _) | MovRegSymb(_, _) -> f_load_const
        elif type(instr) == MovRegReg:
            return f_copy_reg
        elif type(instr) == _:
            raise Exception("analysis 354")

    #(* regs is a list of lists *)
    let regs = List.fold_left f_collect [] gms in #拷贝先前的定义
    groups = group_args(regs)
    sets = make_sets(groups)
    return sets

def matching_func_for_instr(instr):
    def f_match(): #?????
        elif type(instr) == OpStack:
            (op, _) = instr.param()
                (fun instr -> match instr with OpStack(op'',_) -> op'' = op | _ -> False)
        elif type() == WriteM(_, _):

                (fun instr -> match instr with WriteM(_, _) -> True | _ -> False)
        elif type() == BinO(_, _, op, _):

                (fun instr -> match instr with  BinO(_, _, op'',_) -> op'' = op | _ -> False)
        elif type() == ReadM(_, _):

                (fun instr -> match instr with ReadM(_, _) -> True | _ -> False)
        #(* movregsymb will be converted to mov reg const *)
        | MovRegConst(_, _) | MovRegSymb(_, _) ->
                (fun instr -> match instr with
                MovRegConst(_, _) | MovRegSymb(_, _) -> True |_ -> False)
        elif type() == MovRegReg(_, _):

                (fun instr -> match instr with MovRegReg(_, _) -> True | _ -> False)

        elif type() == ReadMConst(_, _):

                (fun instr -> match instr with ReadMConst(_, _) -> True | _ -> False)
        elif type() == WriteMConst(_, _):

                (fun instr -> match instr with WriteMConst(_, _) -> True | _ -> False)
        elif type() == LocalAddr(_, _):

                (fun instr -> match instr with LocalAddr(_, _) -> True | _ -> False)
        | PushReg(_)->
                (fun instr -> match instr with PushReg(_) -> True | _ -> False)
        elif type() == PopReg(_):

                (fun instr -> match instr with PopReg(_) -> True | _ -> False)

        | ReadLocal(_, _)->
                (fun instr -> match instr with ReadLocal(_, _) -> True | _ -> False)
        elif type() == WriteLocal(_, _):

                (fun instr -> match instr with WriteLocal(_, _) -> True | _ -> False)
        | AdvanceStack(_)->
                (fun instr -> match instr with AdvanceStack(_) -> True | _ -> False)
        elif type() == RawHex(_):

                (fun instr -> match instr with RawHex(_) -> True | _ -> False)
        | Lbl(_)-> assert False
        elif type() == Comment(_):
         assert False
        elif type() == _:
         assert False

    f_match

#(* Make f_assign x an identity for concrete regs *)
def wrap_f_assign(f):
    def g(r):
        elif type(r) == C:
            try :
                f(r)
            except Exception, e:
                print r
        elif type(r) == S:
            try:
                f(r)
            except Exception, e:
                print r
    return g

def apply_assignment(f_assign, instr):
    f = wrap_f_assign(f_assign)
    if type(instr) == MovRegConst:
        (r, c) = instr.param()
        return MovRegConst(f(r),c)
    elif type(instr) == MovRegSymb:
        (r, sc) = instr.param()
        return MovRegSymb(f(r),sc)
    elif type(instr) == ReadMConst:
        (r, ma) = instr.param()
        return ReadMConst(f(r),ma)
    elif type(instr) == WriteMConst:
        (ma, r) = instr.param()
        return WriteMConst(ma, f(r))
    elif type(instr) == ReadLocal:
        (off, r) = instr.param()
        return ReadLocal(off, f(r))
    elif type(instr) == WriteLocal:
        (off, r) = instr.param()
        return WriteLocal(off, f(r))
    elif type(instr) == LocalAddr:
        (v, r) = instr.param()
        return LocalAddr(v, f(r))
    elif type(instr) == PopReg:
        (r) instr.param()
        return PopReg(f(r))
    elif type(instr) == PushReg:
        (r) = instr.param()
        return PushReg(f(r))
    elif type(instr) == OpStack:
        (op, r) = instr.param()
        return OpStack(op, f(r))

    elif type(instr) == MovRegReg:
        (r1, r2) = instr.param()
        return MovRegReg(f(r1) ,f(r2))
    elif type(instr) == WriteM:
        (r1, r2) = instr.param()
        return WriteM(f(r1) ,f(r2))
    elif type(instr) == ReadM:
        (r1, r2) = instr.param()
        return ReadM(f(r1) ,f(r2))
    elif type(instr) == BinO:
        (ro, r1, op, r2) = instr.param()
        return BinO(f(ro) , f(r1) , op, f(r2))

    elif type(instr) == _:
        return instr

def make_cache_funs():
    let cache = ref(fun i p -> raise Not_found) in
    def cache_add(instr, reg_set_list):
        f_match = matching_func_for_instr(instr)
        def new_cache(i, p):
            if f_match i then
                List.nth reg_set_list p
            else
                !cache i p #(* FIXME ? *)

        begin
            cache := new_cache
        end

    def cache_test(instr, pos):
        try let _ = !cache instr pos in True with Not_found -> False

    def cache_get(instr, pos):
        try !cache instr pos with Not_found -> assert False

    (cache_add, cache_test, cache_get)

#(* All registers used in implementations are "local".
 * Use noncolliding regs for params: S(-1), S(-2) ... *)
def make_fake_instr(instr):
    args = arg_dumper(instr)
    let f(n, f_assign) arg =
        def f_new(x): if x=arg then (S(-n)) else f_assign x in
        (n+1, f_new)

    let f_assert = (fun x->assert False) in
    let(_, f_assign) = List.fold_left f(1, f_assert) args in
    fake_instr = apply_assignment(f_assign instr)
    fake_instr

"""
(* *by_pos/by_arg are mutually recursive.
 * by_pos returns possible regs for ith argument
 * by_arg returns possible regs for a specific arg
 * difference: if two args are equal then we need to intersect corresponding
 * sets *)
 """
def make_possible_regs_funs(gadgets, implement):
    #(* let(cache_add, cache_test, cache_get) = make_cache_funs() in *)
    def possible_regs_by_pos(gadgets, implement instr pos):
        possible_regs_t0 = possible_regs_t0(gadgets)
        def cache_add(instr, reg_set_list):
            ()

        #(* FIXME *)
        def cache_test(instr, pos): False in
        def cache_get(instr, pos): assert False in
        def higher_t(instr, pos):
            def process_impl(impl, arg):
                def collect(reg_set, instr):
                    regs = possible_regs_by_arg(gadgets implement instr arg)
                    RegSet.inter reg_set regs

                List.fold_left collect fULL_REG_SET impl

            #(* Beware: this works correctly only because higher types don't take multiple reg params *)
            fake_instr = make_fake_instr(instr)
            args = arg_dumper(fake_instr)
            impl = implement(fake_instr)
            def f(acc, arg):
                let regs = process_impl impl arg in
                regs::acc

            let possible_for_all_args = List.fold_left f [] args in
            List.rev possible_for_all_args

        if(cache_test instr pos) then
            cache_get instr pos
        else
            #(* list of sets. i-th set contains possible regs for ith param *)
            let reg_set_list =
                typ = instr_type(instr)
                match typ with
                elif type() == T0:

                        #(* get possible regs for all arguments *)
                        reg_set_list = possible_regs_t0(instr)
                        reg_set_list
                elif type() == _:
                 higher_t instr pos

            _ = cache_add(instr reg_set_list)
            total_args = number_of_args(instr)
            if pos > (total_args-1) then assert False
            else List.nth reg_set_list pos
    and
    possible_regs_by_arg gadgets implement instr arg =
        positions = arg_positions(instr arg)
        def collect(reg_set, pos):
            regs = possible_regs_by_pos(gadgets implement instr pos)
            RegSet.inter reg_set regs

        List.fold_left collect fULL_REG_SET positions

    by_arg = possible_regs_by_arg(gadgets implement)
    by_pos = possible_regs_by_pos(gadgets implement)
    by_arg, by_pos


def mod_read_vars(x):
    | AdvanceStack(_)
    elif type() == RawHex(_):
     [],[]
    | MovRegConst(r, _)
    | MovRegSymb(r, _)
    | ReadMConst(r, _)
    | ReadLocal(_, r)
    | LocalAddr(_, r)
    elif type() == PopReg(r):
     [r],[]

    | WriteLocal(_, r)
    | WriteMConst(_, r)
    | PushReg(r)
    elif type() == OpStack(_, r):
     [],[r]

    elif type() == MovRegReg(r1, r2):
     [r1],[r2]
    elif type() == WriteM(r1, r2):
     [],[r1;r2]
    elif type() == ReadM(r1, r2):
     [r1],[r2]
    elif type() == BinO(ro, r1, op, r2):
     [ro],[r1;r2]

    elif type() == SaveFlags:
     [C(EAX)],[]
    | Lbl(_)
    elif type() == Comment(_):
     [],[]

def mod_vars(instr): fst(mod_read_vars instr)
def read_vars(instr): snd (mod_read_vars instr)

#(* Assumes SSA form.
 * Overapproximated for non-SSA.
 * Store first write and last read *)
def analyse_reads_writes(instrs):
    reads = Hashtbl.create(8)
    writes = Hashtbl.create(8)
    def update_hashes(i, instr reads writes):
        wr = mod_vars(instr)
        rd = read_vars(instr)
        #(* first write *)
        def f_w(acc, reg):
            try
                _ = Hashtbl.find(writes reg)
                ()
            with Not_found ->
                Hashtbl.add writes reg i

        #(* last read *)
        def f_r(acc, reg): Hashtbl.add reads reg i in
        _ = List.fold_left f_w() wr
        _ = List.fold_left f_r() rd
        ()

    def f(i, instr):
        _ = update_hashes(i instr reads writes)
        i+1

    _ = List.fold_left(f 0 instrs)
    (reads, writes)

def get_kv(h):
    #(* Hashtbl.fold provides history of bindings, but we only want the most
     * recent one. *)
    seen = Hashtbl.create(8)
    def f(k, v acc):
        try
            _ = Hashtbl.find(seen k)
            acc
        with Not_found ->
            _ = Hashtbl.add(seen k True)
            (k, v)::acc

    let l = Hashtbl.fold f h [] in
    l

def inverse_hash(h):
    inv = Hashtbl.create(16)
    kv_pairs = get_kv(h)
    let f h(k, v) =
        let cur = try Hashtbl.find h v with Not_found -> SRegSet.empty in
        cur = SRegSet.add(k cur)
        _ = Hashtbl.add(h v cur)
        h

    inv = List.fold_left(f inv kv_pairs)
v

def hash_get(h, k empty): try Hashtbl.find h k with Not_found -> empty

def find_read_but_not_written(reads, writes):
    def f(k, v acc):
        try
            let _ = Hashtbl.find writes k in
            acc
        with Not_found -> k::acc

    let in_args = Hashtbl.fold f reads [] in
    sreg_set_from_list in_args

#(* liveness analysis *)
def analyse_liveness(instrs):
    let(reads, writes) = analyse_reads_writes(instrs) in
    l2rd = inverse_hash(reads)
    l2wr = inverse_hash(writes)
    in_args = find_read_but_not_written(reads writes)
    cur = hash_get l2wr 0 SRegSet.empty
    cur = SRegSet.union(cur in_args)
    _ = Hashtbl.add(l2wr 0 cur)
    #(* Add a set of live vars to every instruction.
     * il - list of pairs(instr, live_vars)
     * alive - alive vars *)
    def attach(instrs):
        let aux(line_no, pairs, alive) instrs =
            match instrs with
            | instr::tl ->
                new_alive = hash_get l2wr line_no SRegSet.empty
                new_dead = hash_get l2rd line_no SRegSet.empty
                alive = SRegSet.union (SRegSet.diff alive new_dead) new_alive
                let pair = (instr, alive) in
                aux(line_no+1, pair::pairs, alive) tl
            else:
             List.rev pairs

        aux(0, [], SRegSet.empty) instrs

    attach instrs

#(* Return a hash: sreg -> set of conflicting sregs.
 * Vars are in conflict, when they can't share a register(they are both alive at the
 * same time).
 *)
def calc_conflicts(pairs):
    let f h(_, alive) =
        def g(acc, sreg):
            cur = hash_get h sreg SRegSet.empty
            new_set = SRegSet.union(cur alive)
            Hashtbl.add h sreg new_set

        elems = SRegSet.elements(alive)
        _ = List.fold_left g() elems
        h

    let fix h(sreg, set) =
        let set' = SRegSet.remove(sreg set) in
        let _ = Hashtbl.add h sreg set' in
        h

    tmp_hash = Hashtbl.create(16)
    _ = List.fold_left(f tmp_hash pairs)
    kv_pairs = get_kv(tmp_hash)
    conflicts = Hashtbl.create(16)
    conflicts = List.fold_left(fix conflicts kv_pairs)
    conflicts

def just_symbolic(args): List.filter(function S(_) -> True | _ -> False) args
def just_concrete(args): List.filter(function C(_) -> True | _ -> False) args

def symbolic_args(instr):
    args = arg_dumper(instr)
    args = just_symbolic(args)
    args

#(* Returns a hash: sreg->set of possible concrete regs *)
def possible_regs(possible_regs_by_arg, instrs):
    def analyse_one(possible, instr):
        args = symbolic_args(instr)
        def f(h, arg_reg):
            regs = possible_regs_by_arg(instr arg_reg)
            let cur =
                try Hashtbl.find h arg_reg
                with Not_found -> regs

            cur = RegSet.inter(cur regs)
            _ = Hashtbl.add(h arg_reg cur)
            h

        possible = List.fold_left(f possible args)
        possible

    possible = Hashtbl.create(16)
    List.fold_left analyse_one possible instrs

def make_assign_regs(gmetas, stack_ptr frame_ptr):
    gadgets = get_gadgets(gmetas)
    implement = make_implement(stack_ptr frame_ptr)
    let p_by_arg, p_by_pos = make_possible_regs_funs(gadgets implement) in

    def dprintf(depth, f):
        let pre = String.make(depth*4) ' ' in
        _ = print_string(pre)
        _ = f()
        ()

    def assign_regs(depth, instrs top_preserved):
        #(* Make assignments only for symbolic regs *)
        def collect_all_vars(instrs):
            def collect(vars, instr):
                args = symbolic_args(instr)
                args_set = sreg_set_from_list(args)
                SRegSet.union vars args_set

            set = List.fold_left collect SRegSet.empty instrs
            SRegSet.elements set

        #(* Return all possible assignments of sreg->concrete reg.
         * Return a list of functions sreg->reg *)
        def all_assignments(sregs, possible conflicts):
            def all_perms(f_acc, sregs):
                match sregs with
                | sreg::tl ->
                    let p_concrete_set =
                        try Hashtbl.find possible sreg with Not_found -> assert False

                    p_concrete_set = common_reg_set_to_sreg_set(p_concrete_set)
                    let conflicting = try Hashtbl.find conflicts sreg with _ -> assert False in
                    #(* Collect conflicting regs *)
                    def f(sreg, acc):
                        match sreg with
                        elif type() == C(creg):
                         SRegSet.add sreg acc
                        elif type() == S(_):

                            begin
                            try
                                creg = f_acc(sreg)
                                SRegSet.add creg acc
                            with _ -> acc
                            end

                    used = SRegSet.fold f conflicting(SRegSet.empty)
                    p_concrete_set = SRegSet.diff(p_concrete_set used)
                    p_concrete_list = SRegSet.elements(p_concrete_set)
                    def assign_one(acc, concrete):
                        def g(sr): if sr=sreg then concrete else f_acc sr in
                        new_perms = all_perms(g) tl
                        new_perms@acc

                    List.fold_left assign_one [] p_concrete_list
                else:
                 [f_acc]

            def f_fail(r):
                let err = sprintf "Unable to assign to: %s" (dump_sreg r) in
                failwith err

            perms = all_perms(f_fail sregs)
            perms

        #(* Apply one of the sregs assignments. Exceptions from this function are
         * always an error.
         * Regs in "alive" sets are also concretized. *)
        def apply_assignment_to_all(f_assign, pairs):
            #(* Don't throw exceptions on concretized regs *)
            f_assign = wrap_f_assign(f_assign)
            let f acc(instr, alive) =
                i = apply_assignment(f_assign instr)
                def g(x, acc): SRegSet.add (f_assign x) acc in
                alive = SRegSet.fold g alive SRegSet.empty
                (i, alive)::acc

            let pairs = List.fold_left f [] pairs in
            pairs = List.rev(pairs)
            pairs

        #(* Which concrete regs need to be preserved between instructions *)
        def calc_preserved(pairs):
            let f acc(instr, alive) =
                mod_params = mod_vars(instr)
                mod_params = sreg_set_from_list(mod_params)
                #(* Instruction can't preserve a param, if it writes to it *)
                preserved = SRegSet.diff(alive mod_params)
                (instr, preserved)::acc

            let pairs = List.fold_left f [] pairs in
            List.rev pairs

        def dump_preserved(preserved):
            def pr(sreg): printf "%s;" (dump_sreg sreg) in
            sregs = SRegSet.elements(preserved)
            let _ = dprintf depth(fun _ -> print_string "$ top_preserved: ") in
            _ = List.map(pr sregs)
            dprintf depth(fun _ -> print_newline())

        #(* Check if the assignment is possible.
         * If it is, return instructions paired with gmetas *)
        def satisfy(perms, pairs):
            #(* Throws Not_found if it's impossible to find a gmeta *)
            let satisfy_t0 instr preserved =
                def check_possible(gmeta):
                    let GMeta(_, _, mod_regs, _) = gmeta in
                    let mod_regs = List.map(fun r -> C(r)) mod_regs in
                    mod_regs = sreg_set_from_list(mod_regs)
                    #(*
                    si = (dump_instr instr)
                    let _ = dprintf depth(fun _ -> printf "@@ %s, preserved: " si) in
                    _ = dump_sreg_set(preserved)
                    let _ = printf "%s" ", mod_regs: " in
                    _ = dump_sreg_set(mod_regs)
                    let _ = dprintf depth(fun _ -> print_newline()) in
                    *)
                    inter = SRegSet.inter(preserved mod_regs)
                    #(* If the intersection is empty, none of the preserved regs is modified *)
                    SRegSet.is_empty inter

                let possible_gmetas = try find_all_gmetas instr gmetas with Not_found -> [] in
                #(* let _ = dprintf depth(fun _ -> printf "possible gmetas: %d\n" (List.length possible_gmetas)) in *)
                #(* Throws Not_found *)
                gmeta = List.find(check_possible possible_gmetas)
                gmeta

            def satisfy_t(instr, preserved):
                impl = implement(instr)
                assign_regs(depth+1) impl preserved

            let satisfy_one(instr, preserved) top_preserved =
                let _ = dprintf depth(fun _ -> printf "implementing %s\n" (dump_instr instr)) in
                preserved = SRegSet.union(preserved top_preserved)
                typ = instr_type(instr)
                let pairs =
                    match typ with
                    elif type() == T0:

                        gmeta = satisfy_t0(instr preserved)
                        [(instr, gmeta)]
                    elif type() == _:
                     satisfy_t instr preserved

                pairs

            def satisfy_all(c_pairs, top_preserved):
                let f acc(instr, preserved) =
                    let impl = satisfy_one(instr, preserved) top_preserved in
                    acc@impl

                let impl = List.fold_left f [] c_pairs in
                impl

            #(* Test all possible assignments *)
            def aux(perms):
                match perms with
                | f_assign::tl ->
                    begin
                    #(* Concretize all regs *)
                    c_pairs = apply_assignment_to_all(f_assign pairs)
                    #(* Remove unnecessary regs from 'alive' set *)
                    c_pairs = calc_preserved(c_pairs)
                    try
                        impl = satisfy_all(c_pairs top_preserved)
                        f_assign, impl
                    with Not_found ->
                        aux tl
                    end
                else:

                    #(* No assignment is satisfiable *)
                    raise Not_found

            let f_assign, impl = aux(perms) in
            f_assign, impl

        def dump_one_perm(vars, f_assign):
            def f(sreg): (sreg, f_assign sreg) in
            l = List.map(f vars)
            let pr(s, c) = dprintf depth(fun _ -> printf "%s -> %s\n" (dump_sreg s) (dump_sreg c)) in
            _ = List.map(pr l)
            ()

        #(* IN: satisfiable assignment, (instr, gmeta) pairs *)
        def dump_satisfied(vars, f_assign pairs):
            let _ = dprintf depth(fun _ -> print_endline "%%% winner assignment:") in
            _ = dump_one_perm(vars f_assign)
            let _ = dprintf depth(fun _ -> print_endline "%%% paired:") in
            let f(instr, gmeta) =
                let _ = dprintf depth(fun _ -> printf "%s\n" (dump_instr instr)) in
                ()

            _ = List.map(f pairs)
            ()

        def dump(vars, possible conflicts perms top_preserved pairs):
            def dump_possible(possible):
                let pr(sreg, set) =
                    set = common_reg_set_to_sreg_set(set)
                    let _ = dprintf depth(fun _ -> printf "%s in {" (dump_sreg sreg)) in
                    _ = dump_sreg_set(set)
                    let _ = dprintf depth(fun _ -> printf "%s\n" "}") in
                    ()

                let _ = dprintf depth(fun _ -> printf "%s\n" "$ possible") in
                kv = get_kv(possible)
                List.map pr kv

            def dump_conflicts(h):
                let _ = dprintf depth(fun _ -> printf "%s\n" "$ conflicts") in
                kv = get_kv(h)
                let pr(k, v) =
                    let _ = dprintf depth(fun _ -> printf "%s conflicts: " (dump_sreg k)) in
                    _ = dump_sreg_set(v)
                    dprintf depth(fun _ -> print_newline())

                _ = List.map(pr kv)
                ()

            def dump_perms(perms):
                let _ = dprintf depth(fun _ -> printf "%s\n" "$ perms") in
                def pr(perm):
                    _ = dump_one_perm(vars perm)
                    dprintf depth(fun _ -> print_endline "-")

                _ = List.map(pr perms)
                ()

            let print_pair(instr, alive) =
                let _ = dprintf depth(fun _ -> Printf.printf "%s alive: " (dump_instr instr)) in
                _ = dump_sreg_set(alive)
                print_newline()

            let _ = dprintf depth(fun _ -> print_endline "--------------") in
            _ = List.map(print_pair pairs)
            _ = dump_preserved(top_preserved)
            _ = dump_possible(possible)
            _ = dump_conflicts(conflicts)
            _ = dump_perms(perms)
            ()

        pairs = analyse_liveness(instrs)
        conflicts = calc_conflicts(pairs)
        possible = possible_regs(p_by_arg instrs)
        vars = collect_all_vars(instrs)
        let perms = all_assignments vars possible conflicts in
        _ = dump(vars possible conflicts perms top_preserved pairs)
        let f_assign, s_pairs = satisfy(perms pairs) in
        _ = dump_satisfied(vars f_assign s_pairs)
        s_pairs

    #(* depth = 0 *)
    assign_regs 0
