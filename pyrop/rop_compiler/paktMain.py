import sys
import paktCommon
import paktParser
import paktAst  #(* for types *)
import paktCdefs
import paktAnalysis

#(* Assumes the parser file is parser.mly and the lexer file is "lexer.mll". *)
hARDCODED_PRINTF = 0x080484a0
cRASH_ADDRESS = 0x1111
sTACK_VAR_OFF = 0
fRAME_VAR_OFF = 4
dATA_OFF = 8 #(* start writing tables here *)

nO_NAME_LABEL = "@@"
gLOBAL_END_LABEL = "global_end"

def trd (_1, _2, x):
    return x

def fun_label(tagid):
    return "function_" + tagid
def fun_local_label(fun_id, tagid):
    return "local_" + fun_id + "_" + tagid

def print_errors(errors):
    errors = paktAst.dump_errors(errors)
    def aux(errors):
        if [] != errors:
            hd = errors[0]
            tl = errors[1::]
            hd = "ERROR. " + hd + "\n"
            print "%s" % (hd)
            aux(tl)
        else:
            return ()
    aux(errors)

def pick_different_reg(used):
    regs = paktCommon.rEGS_NO_ESP
    def p(reg):
        if reg in used:
            return False
        else:
            return True

    not_used = filter(p, regs)
    if not_used != []:
        return not_used[0]
    else:
        assert False

#(* every invocation of f_next_reg returns new symbolic reg *)
def make_rewrite_exp(f_next_reg, read_local, ref_local):
    def rewrite_exp(x, oreg):
        if type(x) == BinOp:
            (exp1, op, exp2) = x.param()
            reg1 = f_next_reg()
            iexp1 = rewrite_exp(exp1, reg1)
            reg2 = f_next_reg()
            iexp2 = rewrite_exp(exp2, reg2)
            o = BinOp(oreg, reg1, op, reg2)
            return iexp1 + iexp2 + [o]

        elif type(x) == UnOp:
            (op, exp) = x.param()
            if type(op) == Sub:
                rewrite_exp(BinOp(Const(0),op, exp), oreg)
            elif type(op) == Not:
                rewrite_exp(BinOp(Const(-1),Xor, exp), oreg)
            else:
                raise Exception("make_rewrite_exp")

        elif type(x) == Var:
            (tagid) = x.param()
            rl = read_local(tagid, oreg)
            return [rl]

        elif type(x) == Ref:
            (tagid) = x.param()
            rl = ref_local(tagid, oreg)
            return [rl]

        elif type(x) == ReadMem:
            tagid = x.param()
            addr_reg = f_next_reg()
            rl = read_local(tagid, addr_reg)
            rm = ReadM(oreg, addr_reg)
            return [rl, rm]

        elif type(x) == Const:
            x = x.param()
            mov = MovRegConst(oreg, x)
            return [mov]

    rewrite_exp

def rewrite_stmt(stack_ptr, frame_ptr, locals, fun_id, stmt):
    f_next_reg = make_reg_generator()
    def rw_local(tagid, reg, f_ctor):
        if tagid not in locals:
            raise Exception("rewrite_stmt")
        off = locals(tagid)
        f_ctor(off, reg)

    def write_local(tagid, reg):
        rw_local(tagid, reg, (lambda off, reg: WriteLocal(off, reg)))

    def read_local(tagid, reg):
        rw_local(tagid, reg, (lambda off, reg: ReadLocal(off, reg)))

    def ref_local(tagid, reg):
        rw_local(tagid, reg, (lambda off, reg: LocalAddr(off, reg)))

    def deref_local(tagid, reg):
        def f(off, reg):
            addr_reg = f_next_reg()
            rl = ReadLocal(off, addr_reg)
            wm = WriteM(addr_reg, reg)
            return [rl, wm]

        rw_local(tagid, reg, f)

    rewrite_exp = make_rewrite_exp(f_next_reg, read_local, ref_local)
    def push_arg(arg):
        #(* just check if args are simple *)
        if type(arg) in [Var, ReadMem, Ref, Const]:
            return True
        else:
            raise Exception("push_arg")

        reg = f_next_reg()
        iarg = rewrite_exp(arg, reg)
        push = PushReg(reg)
        return iarg + push

    def push_args(args):
        def aux(acc, args):
            if len(args) != 0:
                pa = push_arg(args[0])
                return aux(pa+acc, args[1:])
            else:
                return acc

        pushes = aux([], args)
        return pushes[0] + pushes[1]

    def set_eax_on_cond(cond):
        #(* ah = SF ZF xx AF xx PF xx CF *)
        #(* returns mask and the value required to take the jump *)
        def flag_mask_const(flag):
            mask = None
            v = None
            if type(flag) == E:
                mask, v =  1<<6, 1<<6
            elif type(flag) == A:
                mask, v = 1|(1<<6), 0
            elif type(flag) == B:
                mask, v = 1, 1
            else : # type(flag) == _:
                raise Exception("set_eax_on_cond")

            mask, v = mask <<  8, v << 8
            return mask, v

        neg = None
        flags = None
        if type(flags) == Cond:
            flags = flags.param()
            neg, flags = false, flags
        if type(flags) == NCond:
            flags = flags.param()
            neg, flags = True, flags

        #(* FIXME: just one flag atm *)
        flag = None
        if len(flags)==1:
            flag = flags[0]
        else:
            raise Exception("set_eax_on_cond 2")

        if flag==MP:
            mov = MovRegConst(C(EAX), 1)
            return [mov]
        else:
            mask, v = flag_mask_const(flag)
            reg = f_next_reg()
            mov1 = MovRegConst(reg, mask)
            and_ah = BinO(C(EAX), C(EAX), And, reg)
            reg = f_next_reg()
            mov2 = MovRegConst(reg, v)
            sub = BinO(C(EAX), C(EAX), Sub, reg)
            lahf = SaveFlags
            reg = f_next_reg()
            #(* ZF position in EAX: 6th bit of AH *)
            mov3 = MovRegConst(reg, 1 << (6+8))
            shr = BinO(C(EAX), C(EAX), Div, reg)
            reg = f_next_reg()
            mov4 = MovRegConst(reg, 1)
            #(* eax=1 iff cond *)
            last = [BinO(C(EAX), C(EAX), And, reg)]
            if neg:
                last = last + [BinO(C(EAX), C(EAX), Xor, reg)]

            return [mov1, and_ah, mov2, sub, lahf, mov3, shr, mov4]+last

    def rewrite(stmt):
        if type(stmt) == Assign:
            (tagid, exp) = stmt.param()
            reg = f_next_reg()
            iexp = rewrite_exp(exp, reg)
            wl = write_local(tagid, reg)
            return iexp+[wl]
        elif type(stmt) == DerefAssign:
            (tagid, exp) = stmt.param()
            reg = f_next_reg()
            iexp = rewrite_exp(exp, reg)
            wl = deref_local(tagid, reg)
            return iexp + wl
        elif type(stmt) == WriteMem:
            (tagid, exp) = stmt.param()
            exp_reg = f_next_reg()
            iexp = rewrite_exp(exp, exp_reg)
            addr_reg = f_next_reg()
            rl = read_local(tagid, addr_reg)
            wm = WriteM(addr_reg, exp_reg)
            return iexp + rl + wm
        elif type(stmt) == Cmp:
            (exp1, exp2) = stmt.param()
            reg1, reg2 = f_next_reg(), f_next_reg()
            iexp1 = rewrite_exp(exp1, reg1)
            iexp2 = rewrite_exp(exp2, reg2)
            reg = f_next_reg()
            sub = BinO(reg, reg1, Sub, reg2)
            lahf = SaveFlags
            return iexp1 + iexp2  +sub+ lahf
        elif type(stmt) == Call:
            (tagid, ExpArgs_exp_args) = stmt.param()
            exp_args = ExpArgs_exp_arg.param()
            pushes = push_args(exp_args)
            reg = f_next_reg()
            mov = MovRegSymb(reg, FromTo(Named(fun_label, tagid), Unnamed(Forward)))
            p = PushReg(reg)
            reg = f_next_reg()
            mov2 = MovRegSymb(reg, FromTo(Unnamed(Forward), Named(fun_label, tagid)))
            add = OpStack(Add, reg)  #(* jmp *)
            lbl = Lbl(nO_NAME_LABEL)
            return pushes + mov + p + mov2 + add + lbl

        elif type(stmt) == ExtCall:
            (tagid, ExpArgs_exp_args) = stmt.param()
            exp_args = ExpArgs_exp_arg.param()

            def range(i, j):
                if i >= j:
                    return []
                else:
                    return i+range(i+1, j)
            def make_filler(n):
                def m(x):
                    x = x&0xFF
                    return (x<<24)|(x<<16)|(x<<8)|x
                def f(acc, x):
                    return RawHex(m, x)+acc
                nums = range(0, n)
                filler = fold_left(f, [], nums)
                filler.reverse()
                return filler

            def store_args(imp_addr, args):
                addr_reg = f_next_reg()
                v_reg = f_next_reg()
                off_reg = f_next_reg()
                fix_reg = f_next_reg()

                def per_arg(acc, arg):
                    iarg = rewrite_exp(arg, v_reg)
                    wm = WriteM(addr_reg, v_reg)
                    set = MovRegConst(off_reg, 4)
                    add = BinO(addr_reg, addr_reg, Add, off_reg)
                    return acc + iarg+[wm, set, add] #(* O(n^2) *)

                tmp_reg = f_next_reg()
                lbl = Lbl(nO_NAME_LABEL)
                save_esp = MovRegReg(tmp_reg, C(ESP))
                mov = MovRegSymb(fix_reg, FromTo(Unnamed(Backward), Unnamed(Forward)))
                fix1 = BinO(addr_reg, tmp_reg, Add, fix_reg)
                #(* Restore import address *)
                reg = f_next_reg()
                set_imp = MovRegConst(reg, imp_addr)
                wm = WriteM(addr_reg, reg)
                reg = f_next_reg()
                set8 = MovRegConst(reg, 8)
                fix2 = BinO(addr_reg, addr_reg, Add, reg)
                stores = fold_left(per_arg, [], args)
                return [save_esp, lbl, mov, fix1, set_imp, wm, set8, fix2]+stores

            def jmp_over_locals(locals_filler):
                n = len(locals_filler)
                reg = f_next_reg()
                mov = MovRegConst(reg, n*4)
                ops = OpStack(Add, reg)
                return [mov, ops]

            imp_addr = hARDCODED_PRINTF
            cmt_s = "jmp %s" % tagid
            #(* At least 128 bytes for locals *)
            n_args = len(exp_args)
            locals_filler = make_filler(256/4)
            jmp_skip_locals = jmp_over_locals(locals_filler)
            #(* FIXME: hardcoded print *)
            jmp_imp = RawHex(imp_addr)
            #(* FIXME: we don't need equality in AdvStack, just >= *)
            adv = AdvanceStack(n_args*4+4)
            lbl = Lbl(nO_NAME_LABEL)
            args_filler = make_filler(n_args)
            write_args = store_args(imp_addr, exp_args)
            return write_args + jmp_skip_locals + locals_filler + [Comment(cmt_s),lbl, jmp_imp, adv] + (args_filler)

        elif type(stmt) == Branch:
            (cond, tagid) = stmt.param()

            #(* eax=1 iff cond, 0 otherwise *)
            setz = set_eax_on_cond(cond)
            reg = f_next_reg()
            start = Unnamed(Forward)
            fin = Named(fun_local_label, fun_id, tagid)
            mov = MovRegSymb(reg, FromTo(start, fin))
            mul = BinO(C(EAX), C(EAX), Mul, reg)
            add = OpStack(Add, C(EAX))  #(* jmp *)
            lbl = Lbl(nO_NAME_LABEL)
            return setz + [mov, mul, add, lbl]
        elif type(stmt) == Label:
            tagid = stmt.param()
            return [Lbl(fun_local_label, fun_id, tagid)]

        elif type(stmt) == Enter:
            n = stmt.param()
            reg = f_next_reg()
            rm1 = ReadMConst(reg, frame_ptr)
            push = PushReg(reg)
            reg = f_next_reg()
            rm2 = ReadMConst(reg, stack_ptr)
            wm1 = WriteMConst(frame_ptr, reg)
            reg1 = f_next_reg()
            rm3 = ReadMConst(reg1, stack_ptr)
            reg2 = f_next_reg()
            mov = MovRegConst(reg2, n)
            reg3 = f_next_reg()
            sub = BinO(reg3, reg1, Sub, reg2)
            wm2 = WriteMConst(stack_ptr, reg3)
            return [rm1, push, rm2, wm1, rm3, mov, sub, wm2]
        elif type(stmt) == Leave:

            reg = f_next_reg()
            rm = ReadMConst(reg, frame_ptr)
            wm1 = WriteMConst(stack_ptr, reg)
            reg = f_next_reg()
            pop = PopReg(reg)
            wm2 = WriteMConst(frame_ptr, reg)
            return [rm, wm1, pop, wm2]
        elif type(stmt) == Ret:
            tagid = stmt.param()
            reg1 = f_next_reg()
            reg2 = f_next_reg()
            reg3 = f_next_reg()
            p2 = PopReg(reg1)
            mov = MovRegSymb(reg2, FromTo(Unnamed(Forward), Named(fun_label, tagid)))
            sub = BinO(reg3, reg2, Add, reg1)
            add = OpStack(Add, reg3) #(* jmp *)
            lbl = Lbl(nO_NAME_LABEL)
            return [p2, mov, sub, add, lbl]
            #(* AssignTab is replaced with Assign(tagid, C) earlier *)
        elif type(stmt) == AssignTab:
            raise Exception("Exception main.py 397")

    new_instrs = rewrite(stmt)
    comments = None
    if type(stmt) == Label:
        return
    else:
        s = paktAst.dump_stmt(stmt)
        comments = [Comment(s)]
    return comments + new_instrs

def rewrite_prog(prog, stack_ptr, frame_ptr):
    def assign_vars(func):
        def collect_locals(stmts):
            def aux(acc, stmts):
                #(* all locals are initialized before use *)
                if len(stmts) == 0:
                    return acc
                else:
                    hd == stmts[0]
                    tl == stmts[1::]
                    if type(hd) == Assign:
                        (tagid, _) = hd.param()
                        return aux([tagid]+acc, tl)
                    else:
                        return aux(acc, tl)

            ids = aux([], stmts)
            ids = paktCommon.generic_unique(ids)
            return ids

        (tagid, Args_args, FunBody_stmts) = func.param()
        args = Args_args.param()
        stmts = FunBody_stmts.param()
        htbl = {}
        def f((h, n), arg):
            h[arg] = n
            return (h, n+4)

        #(* v1, frame, ret, arg1,...,argN *)
        (htbl, _) = fold_left(f, (htbl, 12), args)
        def g((h, n), tagid):
            h[tagid] = n
            return (h, n-4)

        ids = collect_locals(stmts)
        (htbl, _) = fold_left(g, (htbl, 0), ids)
        return htbl

    def rewrite_func(func):
        def add_stack_stuff(fun_id, locals, stmts):
            locals_count = len(locals)
            #(* every local is a dword *)
            pre = [Enter(locals_count*4)]
            suf = [Leave, Ret(fun_id)]
            stmts = pre + stmts + suf
            return stmts

        rewrite_stmt = rewrite_stmt(stack_ptr, frame_ptr)
        (fun_id, Args_args, FunBody_stmts) = func.param()
        args = Args_args.param()
        stmts = FunBody_stmts.param()

        locals = assign_vars(func)
        stmts = add_stack_stuff(fun_id, locals, stmts)
        instrs = map((lambda stmt: rewrite_stmt(locals, fun_id, stmt)), stmts)
        head = paktAst.dump_func_head(func)
        fun_lbl = fun_label(fun_id)
        pre = [Comment(head), Lbl(fun_lbl)]
        instrs = [pre] + instrs
        return instrs

    (func_list) = prog.param()
    rew = map(rewrite_func, func_list)
    #(* let rew = List.concat(rew) in *)
    return rew

"""
(* Extract tables and create a stub that writes them to the data section.
 * All AssignTable(tagid, list) are changed to Assign(tagid, C), where C is the
 * address in .data section *)
 """
def handle_tables(data_s, prog):
    def per_func(data_start, func):
        h = Hashtbl.create(8)
        def per_stmt(acc, stmt):
            (off, pairs, rew) = acc.param()
            if type(stmt) == AssignTab:
                (tagid, l) = stmt.param()

                new_stmt = Assign(tagid, Const(off))
                new_off = off + len(l)
                return new_off, [(off, l)]+pairs, [new_stmt] +rew

            else:
                return off, pairs, [stmt] + rew

        (fun_id, Args_args, FunBody_stmts) = func.param()
        args = Args_args.param()
        stmts = FunBody_stmts.param()
        data_end, pairs, stmts = fold_left(per_stmt, (data_start,[],[]), stmts)
        stmts = stmts.reverse()
        Func = Fun(fun_id, Args(args), FunBody(stmts))
        return data_end, pairs, func

    def per_func_fold((data_start, l_pairs, funs), func):
        data_end, f_pairs, new_func = per_func(data_start, func)
        (data_end, f_pairs+l_pairs, new_func+funs)

    def dump_pairs(pairs):
        def pr(off, l):
            s = dump_int_list(l)
            s = "0x%08x,%s\n" % (off, s)
            return s

        return map(pr, pairs)

    def make_stub(pairs):
        def store(addr, v):
            r = S(-1)
            mov = MovRegConst(r, v)
            wm = WriteMConst(addr, r)
            return [mov, wm]

        def chop(l, n):
            def f((i, a, b), x):
                if i<n:
                    return (i+1,[x]+a, b)
                else:
                    return (i+1, a,[x]+b)

            (_, a, b) = fold_left(f, (0,[],[]), l)
            return a.reverse(), b.reverse()

        def to_int(l):
            def f(acc, x):
                return (acc << 8)+x
            fold_left(f, 0, l)

        def make_one(off, l):
            def aux(acc, off, l):
                pre, suf = chop(l, 3)
                if [] != pre:
                    v = to_int(pre.reverse())
                    s = store(off, v)
                    aux([s]+acc, (off+3), suf)
                else:
                    List.flatten (acc.reverse())

            return aux([], off, l)

        def f(acc, (off, l)):
            s = make_one(off, l)
            return [s] + acc

        ss = fold_left(f, [], pairs)
        List.flatten(ss.reverse())

    data_start = data_s+dATA_OFF
    (func_list) = prog.param()
    (_, l_pairs, funs) = fold_left(per_func_fold, (data_start,[],[]), func_list)
    funs = funs.reverse()
    pairs = (List.flatten(l_pairs)).reverse()
    dump_pairs(pairs)
    new_prog = Prog(funs)
    stub = make_stub(pairs)
    return stub, new_prog

def add_comments(f_comment, new_instrs, prefix, instr):
    comments = []
    if f_comment(instr):
        s = dump_instr(instr)
        comments = [Comment(prefix^s)]

    return comments + new_instrs

#(* concretize symbolic constants *)
#(* IN: (instr, gm) pairs
# * OUT: (instr, gm) pairs without MovRegSymb *)
def fix_symblic(pairs):
    def get_size(gm):
        (_, _, _, stack_fix) = gm.param()
        return stack_fix

    def check_lbl(label, instr):
        if type(instr) == Lbl:
            lab = instr.param()
            label = lab
            return label
        else:
            return False

    def distance_to_generic(f_match, pairs):
        def aux(dist, pairs):
            if len(pairs) == 0:
                return None
            else:
                hd = pairs[0]
                tl = pairs[1::]
                instr, gm = hd.param()
                if f_match(instr):
                    """
                    (*
                    let _ = Printf.print "found label %s in: %s\n" label
                    (dump_instr instr) in
                    *)
                    """
                    return Some(dist)
                else:
                    #(* Ignore gmetas for labels and comments -_-' *)
                    if is_lbl_or_comment(instr):
                        aux(dist, tl)
                    else:
                        size = get_size(gm)
                        aux((size+dist), tl)

        dist = aux(0, pairs)
        return dist

    def distance_to_lbl(lbl, pairs):
        f_match = check_lbl(lbl)
        dist = distance_to_generic(f_match, pairs)
        return dist

    def try_both_ways(tagid, pre, suf):
        before = distance_to_lbl(tagid, pre)
        after = distance_to_lbl(tagid, suf)
        if type(before) == Some and type(after) == Some:
            print "Found duplicate: " + tagid
        elif before == None and after == None:
            print "Can't find label:" + tagid
        elif type(before) == Some and after == None:
            (n) = before.param()
            return -n
        elif before == None and Some(n):
            (n) = before.param()
            return n

    def distance_to_unnamed(dir, pre, suf):
        sign = None
        chunk = None
        if type(dir) == Forward:
            sign, chunk = 1, suf
        elif type() == Backward:
            sign, chunk = -1, pre

        dist = distance_to_lbl(nO_NAME_LABEL, chunk)
        if type(dist) == Some:
            (n) = dist.param()
            return sign*n
        elif type(dist) == None:
            print "Unnamed not found"

    def get_distance(symb, pre, suf):
        if type(symb) == Named:
            (tagid) = symb.param()
            return try_both_ways(tagid, pre, suf)
        elif type(symb) == Unnamed:
            (dir) = symb.param()
            return distance_to_unnamed(dir, pre, suf)

    def aux(pre, suf):
        if len(suf) == 0:
            return pre.reverse()
        else:
            hd = suf[0]
            tl = suf[1::]
            if type(hd) == MovRegSymb:
                (reg, FromTo_start_fin, gm) = suf.param()
                (start, fin) = FromTo_start_fin.param()
                dstart = get_distance(start, pre, suf)
                dfin = get_distance(fin, pre, suf)
                dist = dfin - dstart
                print "FromTo: (%s,%s)->(%d,%d)->%d\n" % (dump_symb(start), dump_symb(fin), dstart, dfin, dist)
                fix = MovRegConst(reg, dist)
                aux([(fix, gm)] + pre, tl)
            else:
                return aux([hd] + pre, tl)
    #end aux
    aux([], pairs)
"""
(* AdvanceStack -> RawHex.
 * to_binary would try to fill the gap before the return address,
 * but we use that space for arguments. *)
"""
def fix_ext_call_stuff(pairs):
    def get_addr(gm):
        (_, fm, _, _) = gm.param()
        (off_s, _) = fm.param()
        return off_s

    def set_stack_fix(gm, sf):
        (g, fm, mod_reg, _) = gm.param()
        return GMeta(g, fm, mod_reg, sf)

    def f(acc, (instr, gmeta)):
        new_instr = instr
        if type(instr) == AdvanceStack:
            (n) = instr.param()
            new_instr = RawHex(get_addr, gmeta)

        if new_instr != instr:
            cmt = Comment(dump_instr, instr)
            fake_gm = set_stack_fix(gmeta, 4)
            p1 = (new_instr, fake_gm)
            p2 = (cmt, gmeta)
            return [p1, p2] + acc
        else:
            return [(instr, gmeta)] + acc

    pairs = fold_left(f, [], pairs)
    return pairs.reverse()

def write_const_const(src_reg, addr_reg, addr, value):
    m1 = MovRegConst(src_reg, value)
    m2 = MovRegConst(addr_reg, addr)
    wm1 = WriteM(addr_reg, src_reg)
    return [m1, m2, wm1]

def global_prefix_suffix(data_s, data_e):
    stack_top = data_e
    stack_frame = stack_top
    st_ptr = data_s+sTACK_VAR_OFF   #(* global var holding stack_top *)
    sf_ptr = data_s+fRAME_VAR_OFF   #(* -- stack_frame *)
    addr_reg, src_reg = S(-1), S(-2)    #(* HACK *)
    write_st = write_const_const(src_reg, addr_reg, st_ptr, stack_top)
    write_sf = write_const_const(src_reg, addr_reg, sf_ptr, stack_frame)
    reg = S(-3)
    mov = MovRegSymb(reg, FromTo(Named(fun_label, "main"), Named(gLOBAL_END_LABEL)))
    push = PushReg(reg)
    lbl = Lbl(gLOBAL_END_LABEL)
    pre = write_st + write_sf + [mov, push]
    suf = [lbl]
    return pre, suf, st_ptr, sf_ptr

def to_binary_one(io, (instr, gm)):
    def get_lc_off(g):
        if type(g) == LoadConst:
            (_, off) = g.param()
            return off
        else:
            raise Exception("to_binary_one")

    def fill(io, n):
        dwords = n / 4
        bytes = n % 4
        def aux(i, f, m):
            if i < m :
                f(n, io)
                return aux((i+1), f, m)
            else:
                return ()

        def f_d(n, io):
            IO.write_i32(io, n)
        def f_b(n, io):
            IO.write_byte(io, n)
        aux(0, f_d ,dwords)
        aux(dwords, f_b, (dwords+bytes))
        return ()

    def value_to_write(instr, off_s):
        if type(instr) == RawHex:
            (v) = instr.param()
            return v
        else:
            return off_s

    (g, fm, _, stack_fix) = gm.param()
    (off_s, _) = fm.param()
    v = value_to_write(instr, off_s)
    IO.write_i32(io, v)

    if type(instr) == MovRegConst:
            (r, v) = instr.param()

            off = get_lc_off(g)
            assert(stack_fix - off - 4 >= 0)
            fill(io, off)
            IO.write_i32(io, v)
            fill(io, (stack_fix - off - 8))
    elif type(instr) == RawHex(_):
        assert(stack_fix == 4)
    else:
        fill(io, (stack_fix-4))

    #(* return string *)
    return ()

def filter_trash(pairs):
    def p(i, _):
        if type(i) ==  Lbl:
            return False
        elif type(i) ==  Comment:
            return False
        return True

    filter(p, pairs)

def to_binary(pairs):
    io = IO.output_string()
    def consume(acc, (instr, gm)):
        to_binary_one(io, (instr, gm))

    fold_left(consume, (), pairs)
    map((lambda i: IO.write_i32(io, cRASH_ADDRESS)), [1, 2, 3, 4, 5, 6, 7])
    IO.close_out(io)

def dump_possible(gadgets, stack_ptr, frame_ptr, instrs):
    implement = make_implement(stack_ptr, frame_ptr)
    p_by_arg, p_by_pos = make_possible_regs_funs(gadgets, implement)
    def f(_, instr):
        print "%s - " % (dump_instr(instr))
        args = arg_dumper(instr)
        def per_arg(_, arg):
            print "| %s: " % (dump_sreg(arg))
            set = p_by_arg(instr(arg))
            regs = RegSet.elements(set)
            generic_dumper((lambda r: dump_reg(r)), regs)
            return ()

        fold_left(per_arg, (), args)
        print "%s" % "\n"

    fold_left(f, (), instrs)
    return ()

#(* dump 'compiled' program *)
def dump_instrs(cl):
    def pr(i):
        s = dump_instr(i)
        print "%s\n" % s
    map(pr, cl)

def dump_pairs(pairs):
    print "~~~~~~~~~~~~~"
    def pr(acc, (instr, gmeta)):
        (_, _, _, stack_fix) = gmeta.param()
        if is_lbl_or_comment(instr):
            (off, sep) = acc, " "
        else:
            (off, sep) = acc+stack_fix, "\t"

        print "0x%04x%s%s\n" % (acc, sep, dump_instr(instr))
        return off

    #(* First RET will add 4 *)
    fold_left(pr, 4, pairs)
    return ()

#(* FIXME: main has to be at the beginning *)
def compile(prog, container):
    def process_func(assign_regs, instr_lll):
        def per_stmt(acc, instrs):
            #(* list of instructions, set of regs to preserve *)
            impl = None
            try:
                impl = assign_regs(instrs, SRegSet.empty)
            except Not_found:
                dump_instrs(instrs)
                assert False
            return impl+acc

        def per_func(acc, stmts):
            impl = fold_left(per_stmt, [], stmts)
            impl = impl.reverse()
            return impl+acc

        impl_lll = fold_left(per_func, [], instr_lll)
        return impl_lll.reverse()

    def verify_impl(impl):
        def p(instr):
            return instr_type(instr) == T0
        ok = all(map(p, impl))
        if not ok:
            raise Exception("compile not ok ")
        else:
            return ()

    (fn, (data_s, data_e), gmetas) = container.param()
    gadgets = get_gadgets(gmetas)
    prefix, suffix, stack_ptr, frame_ptr = global_prefix_suffix(data_s, data_e)
    """
    (* Swap AssignTable with Assign (const).
    * stub stores all tables in .data section *)
    """
    stub, prog = handle_tables(data_s, prog)
    """
    (* Function to implement instructions in terms of simpler instructions.
    * Ultimately instruction is converted to a list of gadgets. *)
    """
    implement = make_implement(stack_ptr, frame_ptr)
    assign_regs = make_assign_regs(gmetas, stack_ptr, frame_ptr)
    """
    (* instr list list list.
     * 1st level: list of functions
     * 2nd level: list of(rewritten) stmts
     * 3rd level: instructions *)
     """
    instrs_ll = rewrite_prog(prog, stack_ptr, frame_ptr)
    instrs_ll = [stub] + [prefix] + instrs_ll + [[suffix]]
    instrs_lll = [[[Comment("lol"), Lbl("1")]]]
    instrs_lll = [[stub]]
    impl_lll = process_func(assign_regs, instrs_ll)
    impl_ll = List.flatten(impl_lll)
    pairs = List.flatten(impl_ll)
    pairs = fix_ext_call_stuff(pairs)

    instrs = map((lambda x: x), pairs)
    dump_pairs(pairs)
    verify_impl(instrs)

    pairs = fix_symblic(pairs)
    pairs = filter_trash(pairs)
    bin_str = to_binary(pairs)
    return strs, pairs, bin_str

def parse_ropl_file(src_fn):
    data = open(src_fn).read()
    p = paktParser.parser.parse(data)
    
    errors = paktAst.verify_prog(p)
    
    return (p, errors)

def main ():
    argc = len(sys.argv)
    if argc <= 2:
        print "Usage:\n%s <ropl file> <gadget file>" % sys.argv[0]
        sys.exit()
        
    ropl_file = sys.argv[1]
    gadget_file = sys.argv[2]
    out_fn = "compiled.bin"
    (p, errors) = parse_ropl_file(ropl_file)
    if errors != []:
        print_errors(errors)
    else:
        p = paktAst.unwrap_prog(p)
        p = paktAst.move_main_to_front(p)
        p = paktAst.flatten_prog(p)
        #container = paktCommon.unmarshal_from_file(gadget_file)
        s = paktAst.dump_prog(p)
        cl, pairs, bin_str = compile(p, container)
        print "DUMPED:\n%s\n####\n" % (s)
        write_str_to_file(out_fn, bin_str)

if __name__ == "__main__":
    main()
