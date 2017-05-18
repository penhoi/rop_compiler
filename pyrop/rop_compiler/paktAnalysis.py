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
            r = C_r.param()
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
            return (lambda(g, gm): g == paktCommon.WriteMem(addr_reg, Int32_zero, src_reg))

        elif type(instr) == ReadM:
            (C_dst_reg, C_addr_reg) = instr.param()
            dst_reg = C_dst_reg.param()
            addr_reg = C_addr_reg.param()
            return (lambda(g, gm): g == paktCommon.ReadMem(dst_reg, addr_reg, Int32_zero))

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
            rm2 = ReadMConst(reg1, stack_ptr)
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
                raise Exception("analysys 197")
        def init():
            f_next_reg = make_reg_generator()
            funs = [implement_t1, implement_t2, implement_t3]
            return map((lambda f: f(f_next_reg)), funs)

        funs = init()
        typ = instr_type(instr)
        idx = type2idx(typ)
        f_implement = funs[idx]
        return f_implement(instr)

def arg_dumper(instr):
    if type(instr) in [AdvanceStack, RawHex]:
        return []

    elif type(instr) in [MovRegConst, MovRegSymb]:
        (a1, _) = instr.param()
        return [a1]

    elif type(instr) in [MovRegReg, WriteM, ReadM]:
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

    elif type(instr) in [LocalAddr, PushReg]:
        return []

    elif type(instr) == PopReg:
        (a1) = instr.param()
        return [a1]

    elif type(instr) in [ReadLocal, Lbl, Comment]:
        return []

    elif type(instr) == WriteLocal:
        (_, a1) = instr.param()
        return [a1]

def number_of_args(instr):
    return len(arg_dumper(instr))

def arg_positions(instr, arg):
    args = arg_dumper(instr)
    def enum((i, l), x):
        return (i+1, [(i, x)] +l)
    _, args = fold_left(enum, (0, []), args)
    args = filter((lambda (_, a): a == arg), args)
    return map((lambda x: x[0]), args)

#(* get possible regs at position pos for instructions matching type of instr.
# * for example: BinOp(r0, _,+,_) 0 -> possible values for r0 *)
def possible_regs_t0(gms, instr):
    def f_binop(op):
        def f(acc, g):
            if type(g) == paktCommon.BinOp:
                (r0, r1, op_prime, r2) = g.param()
                if op == op_prime:
                    return [r0, r1, r2]+acc
                else:
                    return acc
            else:
                return acc
        #end def f
        return f

    def f_op_esp(op):
        def f(acc, g):
            if type(g) == paktCommon.OpEsp:
                (op_prime, r, _) = g.param()
                if op == op_prime:
                    return [r] + acc
                else:
                    return acc
            else:
                return acc
        return f

    def f_write_mem(acc, g):
        if type(g) == paktCommon.WriteMem:
            (r0, _, r1) = g.param()
            return [r0, r1]+acc
        else:
            return acc

    def f_read_mem(acc, g):
        if type(g) == paktCommon.ReadMem:
            (r0, r1, _) = g.param()
            return [r0, r1]+acc
        else:
            return acc

    def f_load_const(acc, g):
        if type(g) == paktCommon.LoadConst:
            (r, _) = g.param()
            return [r]+acc
        else:
            return acc

    def f_copy_reg(acc, g):
        if type(g) == paktCommon.CopyReg:
            (r0, r1) = g.param()
            return [r0, r1] + acc
        else:
            return acc

    #(* [[a1;..];[b1..]] -> [a1;b1],[[..];[..]] *)
    def group_args(regs):
        def f(heads, tails, l):
            if len(l) != 0:
                hd, tl = l[0], l[1:]
                return ([hd]+heads, tl+tails)
            else:
                assert False
        #end def f

        def aux(acc, ll):
            if len(ll) != 0 and len(ll[0]) != 0: #(* at least one non-empty list *)
                (heads, tails) = fold_left(f, ([],[]), ll)
                return aux([heads] +acc), tails
            else:
                acc.reverse()
                return acc

        return aux([], regs)

    def make_sets(groups):
        def f(acc, l):
            rset = set_from_list(l)
            return [rset] + acc

        sets = fold_left(f, [], groups)
        sets.reverse()
        return sets

    def f_collect():
        if type(instr) == OpStack:
            (op, _) = instr.param()
            op_prime = ast_op_to_gadget_op(op)
            return f_op_esp(op_prime)

        elif type(instr) == WriteM:
            return f_write_mem

        elif type(instr) == BinO:
            (_, _, op, _) = instr.param()
            op_prime = ast_op_to_gadget_op(op)
            return f_binop(op_prime)

        elif type(instr) == ReadM:
            return f_read_mem

        #(* movregsymb will be converted to mov reg const *)#?????
        elif type(instr) in [MovRegConst, MovRegSymb]:
            return f_load_const

        elif type(instr) == MovRegReg:
            return f_copy_reg

        else:
            assert False
    #end def f_collect

    #(* regs is a list of lists *)
    regs = fold_left(f_collect, [], gms)
    groups = group_args(regs)
    sets = make_sets(groups)
    return sets

def matching_func_for_instr(x):
    f_match = None
    if type(x) == OpStack:
        def fOpStack(instr):
            if type(instr) == OpStack:
                (op_prime_prime,_) =  instr.param()
                return op_prime_prime == op
            else:
                return False
        #end fOpStack
        f_match = fOpStack

    elif type(x) == WriteM:
        f_match = (lambda instr: type(instr) == WriteM)

    elif type(x) == BinO:
        (_, _, op, _) = x.param()
        def f(instr):
            if type(instr) == BinO:
                (_, _, op_prime_prime,_) =  instr.param()
                return op_prime_prime == op
            else:
                return False
        #end f
        f_match = f

    elif type(x) == ReadM:
        f_match = (lambda instr: type(instr) == ReadM)

    #(* movregsymb will be converted to mov reg const *)
    elif type(x) in [MovRegConst, MovRegSymb]:
        f_match = (lambda instr: type(instr) in [MovRegConst, MovRegSymb])

    elif type(x) == MovRegReg:
        f_match = (lambda instr: type(instr) == MovRegReg)

    elif type(x) == MovRegReg:
        f_match = (lambda instr: type(instr) == MovRegReg)

    elif type(x) == ReadMConst:
        f_match = (lambda instr: type(instr) == ReadMConst)

    elif type(x) == WriteMConst:
        f_match = (lambda instr: type(instr) == WriteMConst)

    elif type(x) == LocalAddr:
        f_match = (lambda instr: type(instr) == LocalAddr)

    elif type(x) == PushReg:
        f_match = (lambda instr: type(instr) == PushReg)

    elif type(x) == PopReg:
        f_match = (lambda instr: type(instr) == PopReg)

    elif type(x) == ReadLocal:
        f_match = (lambda instr: type(instr) == ReadLocal)

    elif type(x) == WriteLocal:
        f_match = (lambda instr: type(instr) == WriteLocal)

    elif type(x) == AdvanceStack:
        f_match = (lambda instr: type(instr) == AdvanceStack)

    elif type(x) == RawHex:
        f_match = (lambda instr: type(instr) == RawHex)

    elif type(x) in [RawHex, Comment]:
        assert False

    else:
        assert False

    return f_match

#(* Make f_assign x an identity for concrete regs *)
def wrap_f_assign(f):
    def g(r):
        if type(r) == C:
            try :
                return f(r)
            except:
                return r

        elif type(r) == S:
            try:
                f(r)
            except:
                assert False
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
        (r) = instr.param()
        return PopReg(f(r))

    elif type(instr) == PushReg:
        (r) = instr.param()
        return PushReg(f(r))

    elif type(instr) == OpStack:
        (op, r) = instr.param()
        return OpStack(op, f(r))

    elif type(instr) == MovRegReg:
        (r1, r2) = instr.param()
        return MovRegReg(f(r1), f(r2))

    elif type(instr) == WriteM:
        (r1, r2) = instr.param()
        return WriteM(f(r1), f(r2))

    elif type(instr) == ReadM:
        (r1, r2) = instr.param()
        return ReadM(f(r1), f(r2))

    elif type(instr) == BinO:
        (ro, r1, op, r2) = instr.param()
        return BinO(f(ro), f(r1), op, f(r2))

    else:
        return instr

def make_cache_funs():
    def cache(i, p):
        raise Exception("Not_found")

    def cache_add(instr, reg_set_list):
        f_match = matching_func_for_instr
        def new_cache(i, p):
            if f_match(i):
                return reg_set_list[p]
            else:
                not cache(i, p)    #(* FIXME ? *)

        cache = new_cache

    def cache_test(instr, pos):
        return not cache(instr, pos)

    def cache_get(instr, pos):
        if not cache(instr, pos):
            assert False

    (cache_add, cache_test, cache_get)

"""
(* All registers used in implementations are "local".
 * Use noncolliding regs for params: S(-1), S(-2) ... *)
"""
def make_fake_instr(instr):
    args = arg_dumper
    def f((n, f_assign), arg):
        def f_new(x):
            if x==arg:
                return (S(-n))
            else:
                f_assign(x)
        return (n+1, f_new)


    def f_assert(x):
        assert False

    (_, f_assign) = fold_left(f, (1, f_assert), args)
    fake_instr = apply_assignment(f_assign, instr)
    return fake_instr

"""
(* *by_pos/by_arg are mutually recursive.
 * by_pos returns possible regs for ith argument
 * by_arg returns possible regs for a specific arg
 * difference: if two args are equal then we need to intersect corresponding
 * sets *)
"""
def make_possible_regs_funs(gadgets, implement):
    #(* let(cache_add, cache_test, cache_get) = make_cache_funs() in *)
    def possible_regs_by_pos(gadgets, implement, instr, pos):
        possible_regs_t0 = possible_regs_t0(gadgets)
        def cache_add(instr, reg_set_list):
            return

        #(* FIXME *)
        def cache_test(instr, pos):
            return False

        def cache_get(instr, pos):
            assert False

        def higher_t(instr, pos):
            def process_impl(impl, arg):
                def collect(reg_set, instr):
                    regs = possible_regs_by_arg(gadgets, implement, instr, arg)
                    RegSet.inter(reg_set, regs)

                fold_left(collect, fULL_REG_SET, impl)

            #(* Beware: this works correctly only because higher types don't take multiple reg params *)
            fake_instr = make_fake_instr(instr)
            args = arg_dumper(fake_instr)
            impl = implement(fake_instr)
            def f(acc, arg):
                regs = process_impl(impl, arg)
                return [regs] +acc

            possible_for_all_args = fold_left(f, [], args)
            possible_for_all_args.reverse()
            return possible_for_all_args

        #end def possible_regs_by_pos

        if (cache_test(instr, pos)):
            cache_get(instr, pos)
        else:
            #(* list of sets. i-th set contains possible regs for ith param *)
            reg_set_list = None
            typ = instr_type(instr)
            if type(typ) == T0:
                #(* get possible regs for all arguments *)
                reg_set_list = possible_regs_t0(instr)
            else:
                reg_set_list = higher_t(instr, pos)

            cache_add(instr, reg_set_list)
            total_args = number_of_args(instr)
            if pos > (total_args-1):
                assert False
            else:
                return reg_set_list[pos]

    def possible_regs_by_arg(gadgets, implement, instr, arg):
        positions = arg_positions(instr, arg)
        def collect(reg_set, pos):
            regs = possible_regs_by_pos(gadgets, implement, instr, pos)
            RegSet.inter(reg_set, regs)

        return fold_left(collect, fULL_REG_SET, positions)

    def by_arg(instr, arg):
        return possible_regs_by_arg(gadgets, implement, instr, arg)
    def by_pos(instr, arg):
        return possible_regs_by_pos(gadgets, implement, instr, arg)

    return by_arg, by_pos


def mod_read_vars(x):
    if type(x) in [AdvanceStack, RawHex]:
        return [], []

    elif type(x) in [MovRegConst, MovRegSymb, ReadMConst]:
        (r, _) = x.param()
        return [r], []

    elif type(x) in [ReadLocal, LocalAddr]:
        (_, r) = x.param()
        return [r], []

    elif type(x) == PopReg:
        (r) = x.param()
        return [],[r]

    elif type(x) in [WriteLocal, WriteMConst]:
        (_, r) = x.param()
        return [], [r]

    elif type(x) == PushReg:
        (r) = x.param()
        return [],[r]

    elif type(x) == OpStack:
        (_, r) = x.param()
        return [],[r]

    elif type(x) == MovRegReg:
        (r1, r2) = x.param()
        return [r1],[r2]

    elif type(x) == WriteM:
        (r1, r2) = x.param()
        return [],[r1, r2]

    elif type(x) == ReadM:
        (r1, r2) = x.param()
        return [r1],[r2]

    elif type() == BinO:
        (ro, r1, op, r2) = x.param()
        return [ro], [r1, r2]

    elif type(x) == SaveFlags:
        return [C(EAX)],[]

    elif type(x) in [Lbl, Comment]:
        return [], []

def mod_vars(instr):
    ret = mod_read_vars(instr)
    return ret[0]

def read_vars(instr):
    ret = mod_read_vars(instr)
    return ret[1]

"""
(* Assumes SSA form.
 * Overapproximated for non-SSA.
 * Store first write and last read *)
"""
def analyse_reads_writes(instrs):
    reads = {}
    writes = {}
    def update_hashes(i, instr, reads, writes):
        wr = mod_vars(instr)
        rd = read_vars(instr)
        #(* first write *)
        def f_w(acc, reg):
            if reg not in writes:
                writes[reg] = i

        #(* last read *)
        def f_r(acc, reg):
            reads[reg] = i
        fold_left(f_w, (), wr)
        fold_left(f_r, (), rd)
        

    def f(i, instr):
        update_hashes(i, instr, reads, writes)
        return i+1

    fold_left(f, 0, instrs)
    return (reads, writes)

def get_kv(h):
    """
    (* Hashtbl_fold provides history of bindings, but we only want the most
     * recent one. *)
     """
    seen = {}
    def f(k, v, acc):
        if k in seen:
            return acc
        else:
            seen[k] = True
            return [(k, v)] + acc

    l = Hashtbl_fold(f, h, [])
    return l

def inverse_hash(h):
    inv = {}
    kv_pairs = get_kv(h)
    def f(h, (k, v)):
        cur = SRegSet.empty
        if v in h:
            cur = h[v]

        cur = SRegSet.add(k, cur)
        h[v] = cur

    inv = fold_left(f, inv, kv_pairs)
    return inv

def hash_get(h, k, empty):
    return h.get(k, empty)

def find_read_but_not_written(reads, writes):
    def f(k, v, acc):
        if k in writes:
            return acc
        else:
            return [k] + acc

    in_args = Hashtbl_fold(f, reads, [])
    return sreg_set_from_list(in_args)

#(* liveness analysis *)
def analyse_liveness(instrs):
    (reads, writes) = analyse_reads_writes(instrs)
    l2rd = inverse_hash(reads)
    l2wr = inverse_hash(writes)
    in_args = find_read_but_not_written(reads, writes)
    cur = hash_get(l2wr, 0, SRegSet.empty)
    cur = SRegSet.union(cur, in_args)
    l2wr[0] =  cur
    def attach(instrs):
        def aux ((line_no, pairs, alive), instrs):
            if len(instrs) != 0:
                instr, tl = instrs[0], instrs[1:]
                new_alive = hash_get(l2wr, line_no, SRegSet.empty)
                new_dead = hash_get(l2rd, line_no, SRegSet.empty)
                alive = SRegSet.union ((SRegSet.diff (alive, new_dead)), new_alive)
                pair = (instr, alive)
                aux((line_no+1, pair+pairs, alive), tl)
            else:
                pairs.reverse()
                return pairs

        return aux((0, [], SRegSet.empty), instrs)

    return attach(instrs)

def calc_conflicts(pairs):
    def f (h, (_, alive)):
        def g(acc, sreg):
            cur = hash_get(h, sreg, SRegSet.empty)
            new_set = SRegSet.union(cur, alive)
            h[sreg] =  new_set

        elems = SRegSet.elements(alive)
        fold_left(g, (), elems)
        return h

    def fix (h, (sreg, rset)):
        set1 = SRegSet.remove(sreg, rset)
        h[sreg] = set1
        return h

    tmp_hash = {}
    fold_left(f, tmp_hash, pairs)
    kv_pairs = get_kv(tmp_hash)
    conflicts = {}
    return fold_left(fix, conflicts, kv_pairs)

def just_symbolic(args):
    return filter((lambda x: type(x) == S), args)
    
def just_concrete(args):
    return filter((lambda x: type(x) == C), args)

def symbolic_args(instr):
    args = arg_dumper(instr)
    args = just_symbolic(args)
    return args

#(* Returns a hash: sreg->set of possible concrete regs *)
def possible_regs(possible_regs_by_arg, instrs):
    def analyse_one(possible, instr):
        args = symbolic_args(instr)
        def f(h, arg_reg):
            regs = possible_regs_by_arg(instr, arg_reg)
            cur = hash_get(h, arg_reg, regs)
            cur = RegSet.inter(cur, regs)
            h[arg_reg] = cur
            return h

        possible = fold_left(f, possible, args)
        return possible

    possible = {}
    fold_left(analyse_one, possible, instrs)

def make_assign_regs(gmetas, stack_ptr, frame_ptr):
    gadgets = get_gadgets(gmetas)
    implement = make_implement(stack_ptr, frame_ptr)
    (p_by_arg, _p_by_pos) = make_possible_regs_funs(gadgets, implement)

    def dprintf(depth, f):
        print ' ' * (depth*4)
        f()

    def assign_regs(depth, instrs, top_preserved):
        #(* Make assignments only for symbolic regs *)
        def collect_all_vars(instrs):
            def collect(nvars, instr):
                args = symbolic_args(instr)
                args_set = sreg_set_from_list(args)
                SRegSet.union(nvars, args_set)

            rset = fold_left(collect, SRegSet.empty, instrs)
            SRegSet.elements(rset)

        def all_assignments(sregs, possible, conflicts):
            def all_perms(f_acc, sregs):
                if len(sregs) != 0:
                    sreg, tl = sregs[0], sregs[:1]
                    if sreg in possible:
                        p_concrete_set = possible[sreg]
                    else:
                        assert False

                    p_concrete_set = common_reg_set_to_sreg_set(p_concrete_set)

                    if sreg in conflicts:
                        conflicting = conflicts[sreg]
                    else:
                        assert False

                    #(* Collect conflicting regs *)
                    def f(sreg, acc):
                        if type(sreg) == C:
                            SRegSet.add(sreg, acc)
                            
                        elif type(sreg) == S:
                            try:
                                creg = f_acc(sreg)
                                SRegSet.add(creg, acc)
                            except:
                                return acc

                    used = SRegSet.fold(f, conflicting(SRegSet.empty))
                    p_concrete_set = SRegSet.diff(p_concrete_set, used)
                    p_concrete_list = SRegSet.elements(p_concrete_set)
                    def assign_one(acc, concrete):
                        def g(sr):
                            if sr==sreg:
                                return concrete
                            else:
                                return f_acc(sr)
                        new_perms = all_perms(g, tl)
                        return new_perms+acc

                    fold_left(assign_one, [], p_concrete_list)
                else:
                    return [f_acc]

            def f_fail(r):
                def err():
                    print "Unable to assign to: %s" % dump_sreg(r)
                    assert False

            return  all_perms(f_fail, sregs)

        def apply_assignment_to_all(f_assign, pairs):
            #(* Don't throw exceptions on concretized regs *)
            f_assign = wrap_f_assign(f_assign)
            def f (acc, (instr, alive)):#?????
                i = apply_assignment(f_assign, instr)
                def g(x, acc):
                    SRegSet.add(f_assign(x), acc)
                alive = SRegSet.fold(g, alive, SRegSet.empty)
                return [(i, alive)]+acc

            pairs = fold_left(f, [], pairs)
            pairs.reverse()
            return pairs

        #(* Which concrete regs need to be preserved between instructions *)
        def calc_preserved(pairs):
            def f (acc, (instr, alive)):
                mod_params = mod_vars(instr)
                mod_params = sreg_set_from_list(mod_params)
                #(* Instruction can't preserve a param, if it writes to it *)
                preserved = SRegSet.diff(alive, mod_params)
                return instr+preserved+acc

            pairs = fold_left(f, [], pairs)
            pairs.reverse()
            return pairs

        def dump_preserved(preserved):
            def pr(sreg):
                print "%s;"% (dump_sreg(sreg))
            sregs = SRegSet.elements(preserved)
            def f(x): print "$ top_preserved: "
            dprintf(depth, f)
            map(pr, sregs)
            def f2(x): print ""
            dprintf(depth, f2)

        def satisfy(perms, pairs):
            #(* Throws Not_found if it's impossible to find a gmeta *)
            def satisfy_t0(instr, preserved):
                def check_possible(gmeta):
                    (_, _, mod_regs, _) = gmeta.param()
                    mod_regs = map((lambda x : C(x)), mod_regs)
                    mod_regs = sreg_set_from_list(mod_regs)
                    inter = SRegSet.inter(preserved, mod_regs)
                    #(* If the intersection is empty, none of the preserved regs is modified *)
                    SRegSet.is_empty(inter)

                possible_gmetas =  find_all_gmetas(instr, gmetas)
                #(* let _ = dprintf depth(fun _ -> printf "possible gmetas: %d\n" (List.length possible_gmetas)) in *)
                #(* Throws Not_found *)
                if possible_gmetas in check_possible:
                    gmeta = check_possible[possible_gmetas]
                else:
                    gmeta = []
                return gmeta

            def satisfy_t(instr, preserved):
                impl = implement(instr)
                return assign_regs(depth+1, impl, preserved)

            def satisfy_one((instr, preserved), top_preserved):
                def f(x): print "implementing %s" % (dump_instr(instr))
                dprintf (depth, f)
                preserved = SRegSet.union(preserved, top_preserved)
                typ = instr_type(instr)
                pairs = None
                if type(typ) == T0:
                    gmeta = satisfy_t0(instr, preserved)
                    pairs = (instr, gmeta)
                else:
                    pairs = satisfy_t(instr, preserved)
                return pairs

            def satisfy_all(c_pairs, top_preserved):
                def f (acc, (instr, preserved)):
                    impl = satisfy_one((instr, preserved), top_preserved)
                    return acc+impl
                impl = fold_left(f, [], c_pairs)
                return impl

            #(* Test all possible assignments *)
            def aux(perms):
                if len(perms) >= 1:
                    f_assign = perms[0]
                    tl = perms[1:]
                    c_pairs = apply_assignment_to_all(f_assign, pairs)
                    c_pairs = calc_preserved(c_pairs)
                    impl = satisfy_all(c_pairs, top_preserved)
                    if impl != []:
                        return (f_assign, impl)
                    else:
                        return aux(tl)
                else:
                    assert False
            return aux(perms)

        def dump_one_perm(vvars, f_assign):
            def f(sreg):
                return (sreg, f_assign(sreg))
            
            l = map(f, vvars)
            def pr(s, c):
                def f(x): print "%s -> %s" % (dump_sreg(s), dump_sreg(c))
                dprintf(depth, f)
            map(pr, l)
            

        #(* IN: satisfiable assignment, (instr, gmeta) pairs *)
        def dump_satisfied(nvars, f_assign, pairs):

            def f0(x): print ("%%% winner assignment:")
            dprintf (depth, f0)
            dump_one_perm(nvars, f_assign)
            def f1(x): print("%%% paired:")
            dprintf (depth, f1)
            def f(instr, gmeta):
                def f2(x): print ("%s" % (dump_instr(instr)))
                dprintf (depth, f2)
                
            map(f, pairs)
            

        def dump(nvars, possible, conflicts, perms, top_preserved, pairs):
            def dump_possible(possible):
                def pr(sreg, rset):
                    rset = common_reg_set_to_sreg_set(rset)
                    def f0(x): print "%s in {"  % (dump_sreg(sreg))
                    dprintf(depth, f0)
                    dump_sreg_set(set)
                    def f1(x): print "%s" % ("}")
                    dprintf(depth, f1)
                    

                def f2(x): print "%s" % ("$ possible")
                dprintf (depth, f2)
                kv = get_kv(possible)
                map(pr, kv)

            def dump_conflicts(h):
                def f3(x): print "%s" % ("$ conflicts")
                dprintf (depth, f3)
                kv = get_kv(h)
                def pr(k, v):
                    def f0(x): print "%s conflicts: " % (dump_sreg(k))
                    dprintf (depth, f0)
                    dump_sreg_set(v)
                    def f1(x): print ""
                    dprintf (depth, f1)

                map(pr, kv)
                

            def dump_perms(perms):
                def f0(x): print  "%s" %  ("$ perms")
                dprintf (depth, f0)
                def pr(perm):
                    dump_one_perm(vars, perm)
                    def f1(x): print ("-")
                    dprintf(depth, f1)

                map(pr, perms)
                

            def print_pair(instr, alive):
                def f0(x): print "%s alive: " % (dump_instr(instr))
                dprintf( depth, f0)
                dump_sreg_set(alive)
                print "\n"

            def f10(x): print("--------------")
            dprintf(depth, f10)
            map(print_pair, pairs)
            dump_preserved(top_preserved)
            dump_possible(possible)
            dump_conflicts(conflicts)
            dump_perms(perms)
            

        pairs = analyse_liveness(instrs)
        conflicts = calc_conflicts(pairs)
        possible = possible_regs(p_by_arg, instrs)
        nvars = collect_all_vars(instrs)
        perms = all_assignments(nvars, possible, conflicts)
        dump(nvars, possible, conflicts, perms, top_preserved, pairs)
        (f_assign, s_pairs) = satisfy(perms, pairs)
        dump_satisfied(nvars, f_assign, s_pairs)
        return s_pairs

    #(* depth = 0 *)
    def assign_regs0(instrs, top_preserved):
        return assign_regs0(0, instrs, top_preserved)
    
    
    return assign_regs0
