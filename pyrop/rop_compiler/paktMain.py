#(* Assumes the parser file is parser.mly and the lexer file is "lexer.mll". *)

import paktAst #(* for types *)
import paktCdefs
import paktAnalysis

hARDCODED_PRINTF = 0x080484a0
cRASH_ADDRESS = 0x1111
sTACK_VAR_OFF = 0
fRAME_VAR_OFF = 4
dATA_OFF = 8 #(* start writing tables here *)

nO_NAME_LABEL = "@@"
gLOBAL_END_LABEL = "global_end"

def trd (_,_,x):
    return x
i32 = Int32.of_int
def fun_label(id):
    return "function_" + id
def fun_local_label(fun_id, tagid):
    return "local_" + fun_id + "_" + id

def print_errors(errors):
    errors = paktAst.dump_errors(errors)
    def aux(errors):
        if [] != errors:
            hd = "ERROR. " + hd + "\n"
            print "%s" % (hd)
            aux(tl)
        else:
            return ()
    aux(errors)

def pick_different_reg(used):
    regs = Common.rEGS_NO_ESP
    def p(reg):
        try:
            let _ = List.find (fun x->x=reg) used in false #??????????
        except Not_found:
            return True
    not_used = filter(p, regs)
    if not_used != []:
        reutrn not_used[0]
    else:
        assert False

#(* every invocation of f_next_reg returns new symbolic reg *)
def make_rewrite_exp(f_next_reg, read_local, ref_local):
    def rewrite_exp(exp_all, oreg ):
        if type(exp_all) == BinOp:
            (exp1, op, exp2) = exp_all.param():
            reg1 = f_next_reg()
            iexp1 = rewrite_exp(exp1, reg1)
            reg2 = f_next_reg()
            iexp2 = rewrite_exp(exp2, reg2)
            o = BinOp(oreg, reg1, op, reg2)
            iexp1 + iexp2 + [o]
            
        elif type(exp_all) == UnOp:
            (op, exp) = exp_all.param()
            if type(op) == Sub:
                rewrite_exp (BinOp(Const(0),op,exp)) oreg
            elif type(op) == Not:
                rewrite_exp (BinOp(Const(-1),Xor,exp)) oreg
            else:
                assert false
                
        elif type(exp_all) == Var:
            (id) = exp_all.param()
            rl = read_local(tagid, oreg)
            return [rl]
        
        elif type(exp_all) == Ref:
            (id) = exp_all.param()
            rl = ref_local(id oreg)
            return [rl]

        elif type(exp_all) = ReadMem:
            addr_reg = f_next_reg()
            rl = read_local(id, addr_reg)
            rm = ReadM(oreg, addr_reg)
            return [rl, rm]

        elif type(exp_all) == Const:
            mov = MovRegConst(oreg, x)
            return [mov]

    rewrite_exp

def rewrite_stmt(stack_ptr, frame_ptr, locals, fun_id, stmt ):
    f_next_reg = make_reg_generator ()
    def rw_local(tagid, reg, f_ctor):
        #let id2off id = try Hashtbl.find locals id with Not_found -> assert false in
        def id2off(id):
            #????查找算法
        off = id2off(id)
        f_ctor (off, reg)

    def write_local(tagid, reg ):#off参数
        rw_local id reg(fun off  WriteLocal(off,reg))

    def read_local(tagid, reg ):
        rw_local id reg(fun off reg -> ReadLocal(off,reg))

    def ref_local(tagid, reg ):
        rw_local id reg(fun off reg -> LocalAddr(off, reg))

    def deref_local(tagid, reg ):
        def f(off, reg ):
            addr_reg = f_next_reg()
            rl = ReadLocal(off, addr_reg) 
            wm = WriteM(addr_reg, reg) 
            return [rl, wm]

        rw_local (id, reg, f)

    rewrite_exp = make_rewrite_exp(f_next_reg, read_local, ref_local)
    def push_arg(arg):
        #(* just check if args are simple *)
        #????
        if type(arg) in [Var, ReadMem, Ref, Const]:
            return True
        else:
            raise Exception("push_arg")
        '''
        let _ = match arg with
            | Var(_) | ReadMem(_) | Ref(_) | Const(_) -> true
            elif type() == _:
             assert false
             '''

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
                mask, v = 1,1
            else : # type(flag) == _:
                raise Exception("set_eax_on_cond")


            
            mask,v = mask <<  8, v << 8 
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
        if flag=MP :
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
            mov3 = MovRegConst(reg, 1 lsl (6+8))
            shr = BinO(C(EAX), C(EAX), Div, reg)
            reg = f_next_reg()
            mov4 = MovRegConst(reg, 1)
            #(* eax=1 iff cond *)
            last = [BinO(C(EAX), C(EAX), And, reg)]
            if neg:
                last = last + [BinO(C(EAX), C(EAX), Xor, reg)]

            return [mov1;and_ah;mov2;sub;lahf;mov3;shr;mov4]+last

    def rewrite(stmt):
        match stmt with
        elif type(stmt) == Assign:
            (tagid, exp) = stmt.param()
            reg = f_next_reg()
            iexp = rewrite_exp(exp, reg)
            wl = write_local(id, reg)
            return iexp+[wl]
        elif type(stmt) == DerefAssign:
            (tagid, exp) = stmt.param()
            reg = f_next_reg()
            iexp = rewrite_exp(exp, reg)
            wl = deref_local(id, reg)
            return iexp + wl
        elif type(stmt) == WriteMem:
            (tagid, exp) = stmt.param()
            exp_reg = f_next_reg()
            iexp = rewrite_exp(exp, exp_reg)
            addr_reg = f_next_reg()
            rl = read_local(id, addr_reg)
            wm = WriteM(addr_reg, exp_reg) 
            return iexp + rl + wm # [rl;wm]
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
            (tagid, ExpArgs(exp_args)) = stmt.param()
            pushes = push_args(exp_args)
            reg = f_next_reg()
            mov = MovRegSymb(reg, FromTo(Named(fun_label, tagid), Unnamed(Forward))) 
            p = PushReg(reg)
            reg = f_next_reg()
            mov2 = MovRegSymb(reg, FromTo(Unnamed(Forward), Named(fun_label tagid))) 
            add = OpStack(Add, reg)  #(* jmp *)
            lbl = Lbl(nO_NAME_LABEL)
            return pushes + mov + p + mov2 + add + lbl # [mov;p;mov2;add;lbl]

        elif type(stmt) == ExtCall:
            (tagid, ExpArgs(exp_args)) = stmt.param()

            def range(i, j ): 
                if i >= j:
                    return [] 
                else:
                    return i+range(i+1, j)
            def make_filler(n):
                def m(x):
                    x = x&0xFF
                    return (x<<24)|(x<<16)|(x<<8)|x
                    #x = x land 0xFF in (x lsl 24) lor (x lsl 16) lor (x lsl 8) lor x#先算iｎ里面的还是外面的？？？
                def f(acc, x ): 
                    return RawHex(m x)+acc 
                nums = range(0, n)
                let filler = List.fold_left f [] nums in #从先前的文件拷贝
                filler.reverse() 
                return filler

            def store_args(imp_addr, args):
                addr_reg = f_next_reg()
                v_reg = f_next_reg()
                off_reg = f_next_reg()
                fix_reg = f_next_reg()

                def per_arg(acc, arg ):
                    iarg = rewrite_exp(arg v_reg)
                    wm = WriteM(addr_reg, v_reg)
                    set = MovRegConst(off_reg, 4)
                    add = BinO(addr_reg, addr_reg, Add, off_reg)
                    return acc + iarg+[wm,set,add] #(* O(n^2) *) 

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
                stores = List.fold_left per_arg [] args #从先前的文件拷贝
                return [save_esp,lbl,mov,fix1,set_imp,wm,set8,fix2]+stores 

            def jmp_over_locals(locals_filler):
                n = len(locals_filler)
                reg = f_next_reg()
                mov = MovRegConst(reg, n*4)
                ops = OpStack(Add, reg)
                return [mov,ops]

            imp_addr = hARDCODED_PRINTF
            let cmt_s = sprint "jmp %s" id in #???
            #(* At least 128 bytes for locals *)
            n_args = len(exp_args)
            locals_filler = make_filler (256/4)
            jmp_skip_locals = jmp_over_locals(locals_filler)
            #(* FIXME: hardcoded print *)
            jmp_imp = RawHex(imp_addr)
            #(* FIXME: we don't need equality in AdvStack, just >= *)
            adv = AdvanceStack(n_args*4+4)
            lbl = Lbl(nO_NAME_LABEL)
            args_filler = make_filler(n_args)
            write_args = store_args(imp_addr, exp_args)
            return write_args + jmp_skip_locals + locals_filler +
                [Comment(cmt_s),lbl,jmp_imp,adv] + (args_filler)
        elif type(stmt) == Branch:
            (cond, tagid) = stmt.param()

            #(* eax=1 iff cond, 0 otherwise *)
            setz = set_eax_on_cond cond in
            reg = f_next_reg()
            start = Unnamed(Forward)
            fin = Named(fun_local_label, fun_id, tagid)
            mov = MovRegSymb(reg, FromTo(start, fin))
            mul = BinO(C(EAX), C(EAX), Mul, reg)
            add = OpStack(Add, C(EAX))  #(* jmp *)
            lbl = Lbl(nO_NAME_LABEL)
            setz @ [mov; mul; add; lbl;]
        elif type() == Label(id):
         [Lbl(fun_local_label fun_id tagid)]

        elif type() == Enter(n):

                reg = f_next_reg()
                let rm1 = ReadMConst(reg, frame_ptr) in
                push = PushReg(reg)
                reg = f_next_reg()
                let rm2 = ReadMConst(reg, stack_ptr) in
                let wm1 = WriteMConst(frame_ptr, reg) in
                reg1 = f_next_reg()
                let rm3 = ReadMConst(reg1, stack_ptr) in
                reg2 = f_next_reg()
                let mov = MovRegConst(reg2, n) in
                reg3 = f_next_reg()
                let sub = BinO(reg3, reg1, Sub, reg2) in
                let wm2 = WriteMConst(stack_ptr, reg3) in
                [rm1;push;rm2;wm1;rm3;mov;sub;wm2]
        elif type() == Leave:

                reg = f_next_reg()
                let rm = ReadMConst(reg, frame_ptr) in
                let wm1 = WriteMConst(stack_ptr, reg) in
                reg = f_next_reg()
                pop = PopReg(reg)
                let wm2 = WriteMConst(frame_ptr, reg) in
                [rm;wm1;pop;wm2]
        elif type() == Ret(id):

                reg1 = f_next_reg()
                reg2 = f_next_reg()
                reg3 = f_next_reg()
                p2 = PopReg(reg1)
                let mov = MovRegSymb(reg2, FromTo(Unnamed(Forward), Named(fun_label, tagid))) in
                let sub = BinO(reg3, reg2, Add, reg1) in
                let add = OpStack(Add, reg3) in #(* jmp *)
                lbl = Lbl(nO_NAME_LABEL)
                [p2;mov;sub;add;lbl;]
        #(* AssignTab is replaced with Assign(tagid,C) earlier *)
        elif type() == AssignTab(_,_):
         assert false

    new_instrs = rewrite(stmt)
        comments = None
        match stmt with
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
                match stmts with
                #(* all locals are initialized before use *)
                | (Assign(tagid,_))::tl -> aux (id::acc) tl
                if [] != :
                 aux acc tl
                else:
                 acc

            let ids = aux [] stmts in
            ids = Common.generic_unique(ids)
            ids

        let Fun(tagid, Args(args), FunBody(stmts)) = func in
        let h = Hashtbl.create 32 in
        let f (h,n) arg =
            _ = Hashtbl.add(h arg n)
            (h,n+4)

        #(* v1,frame,ret,arg1,...,argN *)
        let (h,_) = List.fold_left f (h,12) args in
        let g(h,n) id =
            _ = Hashtbl.add(h id n)
            (h,n-4)

        ids = collect_locals(stmts)
        let (h,_) = List.fold_left g(h,0) ids in
        h

    def rewrite_func(func):
        def add_stack_stuff(fun_id, locals stmts):
            locals_count = Hashtbl.length(locals)
            #(* every local is a dword *)
            let pre = [Enter(locals_count*4)] in
            let suf = [Leave;Ret(fun_id)] in
            let stmts = pre@stmts@suf in
            stmts

        rewrite_stmt = rewrite_stmt(stack_ptr, frame_ptr)
        let Fun(fun_id, Args(args), FunBody(stmts)) = func in
        let locals = assign_vars func in
        stmts = add_stack_stuff(fun_id locals stmts)
        let instrs = List.map (fun stmt -> rewrite_stmt locals fun_id stmt) stmts in
        head = paktAst.dump_func_head(func)
        fun_lbl = fun_label(fun_id)
        let pre = [Comment(head); Lbl(fun_lbl);] in
        let instrs = [pre]@instrs in
strs

    Prog(func_list) = prog
    rew = List.map(rewrite_func func_list)
    #(* let rew = List.concat (rew) in *)
    rew

#(* Extract tables and create a stub that writes them to the data section.
 * All AssignTable(tagid,list) are changed to Assign(tagid,C), where C is the
 * address in .data section *)
def handle_tables(data_s, prog ):
    def per_func(data_start, func ):
        h = Hashtbl.create(8)
        def per_stmt(acc, stmt ):
            let (off, pairs, rew) = acc in
            match stmt with
            elif type() == AssignTab(tagid, l):

                let new_stmt = Assign(tagid, Const(off)) in
                let new_off = off + List.length l in
                new_off,(off,l)::pairs,new_stmt::rew

            elif type() == _:
             off,pairs,stmt::rew

        let Fun(fun_id, Args(args), FunBody(stmts)) = func in
        let data_end, pairs, stmts = List.fold_left per_stmt (data_start,[],[]) stmts in
        stmts = List.rev(stmts)
        let func = Fun(fun_id, Args(args), FunBody(stmts)) in
        data_end, pairs, func

    let per_func_fold (data_start,l_pairs,funs) func =
        let data_end, f_pairs, new_func = per_func(data_start func) in
        (data_end, f_pairs::l_pairs, new_func::funs)

    def dump_pairs(pairs):
        let pr (off, l) =
            s = dump_int_list(l)
            print "0x%08x,%s\n" off s

        List.map pr pairs

    def make_stub(pairs):
        def store(addr, v ):
            let r = S(-1) in
            let mov = MovRegConst(r, v) in
            let wm = WriteMConst(addr, r) in
            [mov;wm]

        def chop(l, n ):
            let f (i,a,b) x = if i<n then (i+1,x::a,b) else (i+1,a,x::b) in
            let (_,a,b) = List.fold_left f (0,[],[]) l in
            List.rev a, List.rev b

        def to_int(l):
            def f(acc, x ): (acc lsl 8)+x in
            List.fold_left f 0 l

        def make_one(off, l):
            def aux(acc, off l):
                let pre,suf = chop(l 3) in
                match pre with
                if [] != :

                    v = to_int (List.rev pre)
                    s = store(off v)
                    aux (s::acc) (off+3) suf
                else:
                 List.flatten (List.rev acc)

            let s = aux [] off l in
            s

        let f acc (off,l) =
            s = make_one(off l)
            s::acc

        let ss = List.fold_left f [] pairs in
        List.flatten (List.rev ss)

    let data_start = data_s+dATA_OFF in
    Prog(func_list) = prog
    let (_,l_pairs,funs) = List.fold_left per_func_fold (data_start,[],[]) func_list in
    funs = List.rev(funs)
    pairs = List.rev (List.flatten l_pairs)
    _ = dump_pairs(pairs)
    new_prog = Prog(funs)
    stub = make_stub(pairs)
    stub, new_prog

def add_comments(f_comment, new_instrs prefix instr):
    let comments =
        if f_comment instr then
            s = dump_instr(instr)
            [Comment(prefix^s)]
        else
            []

    comments @ new_instrs

#(* concretize symbolic constants *)
#(* IN: (instr,gm) pairs
 * OUT: (instr,gm) pairs without MovRegSymb *)
def fix_symblic(pairs):
    def get_size(gm):
        let GMeta(_,_,_,stack_fix) = gm in
        stack_fix

    def check_lbl(label, instr): match instr with Lbl(lab) -> label=lab | _ -> false in
    def distance_to_generic(f_match, pairs):
        def aux(dist, pairs):
            match pairs with
            | (instr,gm)::tl ->
                if f_match instr then
                    #(*
                    let _ = Printf.print "found label %s in: %s\n" label
                    (dump_instr instr) in
                    *)
                    Some(dist)
                else
                    begin
                    #(* Ignore gmetas for labels and comments -_-' *)
                    if is_lbl_or_comment instr then
                        aux dist tl
                    else
                        size = get_size(gm)
                        aux (size+dist) tl
                    end
            else:
             None

        dist = aux(0 pairs)
        dist

    def distance_to_lbl(lbl, pairs):
        f_match = check_lbl(lbl)
        dist = distance_to_generic(f_match pairs)
        dist

    def try_both_ways(tagid, pre suf ):
        before = distance_to_lbl(id pre)
        after = distance_to_lbl(id suf)
        match before,after with
        elif type() == Some(_),Some(_):
         failwith ("Found duplicate: "^id)
        elif type() == None, None:
         failwith ("Can't find label:"^id)
        elif type() == Some(n),None:
         -n
        elif type() == None,Some(n):
         n

    def distance_to_unnamed(dir, pre suf ):
        let sign,chunk =
            match dir with
            elif type() == Forward:
             1,suf
            elif type() == Backward:
             -1,pre

        dist = distance_to_lbl(nO_NAME_LABEL chunk)
        match dist with
        elif type() == Some(n):
         sign*n
        elif type() == None:
         failwith "Unnamed not found"

    def get_distance(symb, pre suf ):
        match symb with
        elif type() == Named(id):
         try_both_ways id pre suf
        elif type() == Unnamed(dir):
         distance_to_unnamed dir pre suf

    def aux(pre, suf ):
        match suf with
        | (MovRegSymb(reg, FromTo(start, fin)),gm)::tl->
            dstart = get_distance(start pre suf)
            dfin = get_distance(fin pre suf)
            let dist = dfin-dstart in
            let _ = print "FromTo: (%s,%s)->(%d,%d)->%d\n" (dump_symb start) (dump_symb fin) dstart dfin dist in
            let fix = MovRegConst(reg, dist) in
            aux ((fix,gm)::pre) tl
        if [] != :
         aux (hd::pre) tl
        else:
         List.rev pre

    aux [] pairs

#(* AdvanceStack -> RawHex.
 * to_binary would try to fill the gap before the return address,
 * but we use that space for arguments. *)
def fix_ext_call_stuff(pairs):
    def get_addr(gm):
        let GMeta(_, fm, _, _) = gm in
        let FileMeta(off_s, _) = fm in
        off_s

    def set_stack_fix(gm, sf ):
        let GMeta(g,fm,mod_reg,_) = gm in
        GMeta(g,fm,mod_reg,sf)

    let f acc (instr,gmeta) =
        let new_instr =
            match instr with
            elif type() == AdvanceStack(n):
             RawHex(get_addr gmeta)
            elif type() == _:
             instr

        if new_instr <> instr then
            cmt = Comment(dump_instr instr)
            fake_gm = set_stack_fix(gmeta 4)
            let p1 = (new_instr, fake_gm) in
            let p2 = (cmt, gmeta) in
            p1::p2::acc
        else (instr,gmeta)::acc

    let pairs = List.fold_left f [] pairs in
    List.rev pairs

def write_const_const(src_reg, addr_reg addr value ):
    let m1 = MovRegConst(src_reg, value) in
    let m2 = MovRegConst(addr_reg, addr) in
    let wm1 = WriteM(addr_reg, src_reg) in
    [m1; m2; wm1]

def global_prefix_suffix(data_s, data_e ):
    stack_top = data_e
    stack_frame = stack_top
    let st_ptr = data_s+sTACK_VAR_OFF in #(* global var holding stack_top *)
    let sf_ptr = data_s+fRAME_VAR_OFF in #(* -- stack_frame *)
    let addr_reg, src_reg = S(-1), S(-2) in #(* HACK *)
    write_st = write_const_const(src_reg addr_reg st_ptr stack_top)
    write_sf = write_const_const(src_reg addr_reg sf_ptr stack_frame)
    let reg = S(-3) in
    let mov = MovRegSymb(reg, FromTo(Named(fun_label "main"), Named(gLOBAL_END_LABEL))) in
    push = PushReg(reg)
    lbl = Lbl(gLOBAL_END_LABEL)
    let pre = write_st @ write_sf @ [mov; push] in
    let suf = [lbl] in
    pre, suf, st_ptr, sf_ptr

let to_binary_one io (instr,gm) =
    def get_lc_off(g):
        match g with
        elif type() == LoadConst(_,off):
         off
        elif type() == _:
         assert false

    def fill(io, n ):
        let dwords = n / 4 in
        bytes = n(mod 4)
        def aux(i, f m ):
            if i < m then
                let _ = f n io in aux (i+1) f m
            else ()

        def f_d(n, io ): IO.write_i32 io n in
        def f_b(n, io ): IO.write_byte io n in
        _ = aux(0 f_d dwords)
        let _ = aux dwords f_b (dwords+bytes) in
        ()

    def value_to_write(instr, off_s):
        match instr with
        elif type() == RawHex(v):
         v
        elif type() == _:
         off_s

    let GMeta(g, fm, _, stack_fix) = gm in
    let FileMeta(off_s, _) = fm in
    v = value_to_write(instr off_s)
    _ = IO.write_i32(io v)

    let _ =
        match instr with
        elif type() == MovRegConst(r,v):

                off = get_lc_off(g)
                let _ = assert (stack_fix - off - 4 >= 0) in
                _ = fill(io off)
                _ = IO.write_i32(io v)
                fill io (stack_fix - off - 8)
        elif type() == RawHex(_):
         assert (stack_fix = 4)
        elif type() == _:
         fill io (stack_fix-4)

    #(* return string *)
    ()

def filter_trash(pairs):
    def p (i,_):
        if type(i) ==  Lbl:
            return False
        elif type(i) ==  Comment:
            return False
        return True

    filter(p, pairs)

def to_binary(pairs):
    io = IO.output_string()
    let consume acc (instr,gm) =
        to_binary_one io (instr,gm)

    _ = List.fold_left consume () pairs
    let _ = List.map (fun i -> IO.write_i32 io cRASH_ADDRESS) [1;2;3;4;5;6;7] in
    IO.close_out io

def dump_possible(gadgets, stack_ptr, frame_ptr instrs):
    implement = make_implement(stack_ptr, frame_ptr)
    let p_by_arg, p_by_pos = make_possible_regs_funs(gadgets implement) in
    def f(_, instr):
        let _ = Printf.print "%s - " (dump_instr instr) in
        args = arg_dumper(instr)
        def per_arg(_, arg ):
            let _ = Printf.print "| %s: " (dump_sreg arg) in
            set = p_by_arg(instr arg)
            regs = RegSet.elements(set)
            let _ = Common.generic_dumper (fun r -> Common.dump_reg r) regs in
            ()

        _ = List.fold_left per_arg() args
        Printf.print "%s" "\n"

    _ = List.fold_left f () instrs
    ()

#(* dump 'compiled' program *)
def dump_instrs(cl):
    def pr(i):
        s = dump_instr(i)
        print "%s\n" % s
    map(pr, cl)

def dump_pairs(pairs):
    print "~~~~~~~~~~~~~"
    let pr acc (instr,gmeta) =
        let GMeta(_,_,_,stack_fix) = gmeta in
        let (off, sep) =
            if is_lbl_or_comment instr then
                acc, " "
            else
                acc+stack_fix, "\t"

        let _ = print "0x%04x%s%s\n" acc sep (dump_instr instr) in
        off

    #(* First RET will add 4 *)
    _ = List.fold_left(pr 4 pairs)
    ()

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
            impl = List.fold_left per_stmt [] stmts in
            impl = impl.reverse()
            return impl+acc

        let impl_lll = List.fold_left per_func [] instr_lll in
        List.rev impl_lll

    def verify_impl(impl):
        def p(instr): instr_type instr = T0 in
        ok = List.for_all(p impl)
        if not ok then assert false
        else ()

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
     * 2nd level: list of (rewritten) stmts
     * 3rd level: instructions *)
     """
    instrs_ll = rewrite_prog(prog stack_ptr, frame_ptr)
    instrs_ll = [stub] + [prefix] + instrs_ll + [[suffix]]
    instrs_lll = [[[Comment("lol");Lbl("1")]]]
    instrs_lll = [[stub]]
    impl_lll = process_func(assign_regs, instrs_ll)
    impl_ll = List.flatten(impl_lll)
    pairs = List.flatten(impl_ll)
    pairs = fix_ext_call_stuff(pairs)

    instrs = List.map(fst, pairs)
    dump_pairs(pairs)
    verify_impl(instrs)

    pairs = fix_symblic(pairs)
    pairs = filter_trash(pairs)
    bin_str = to_binary(pairs)
return strs, pairs, bin_str

def parse_src(src_fn):
    cin = open_in(src_fn)
    lexbuf = Lexing.from_channel(cin)
    p = Parser.input(Lexer.token, lexbuf)
    errors = paktAst.verify_prog(p)
    return (p, errors)

def main ():
    argc = len(sys.argv)
    if argc > 2:
        src_fn = sys.argv[1]
        vg_fn = sys.argv[2]
        out_fn = "compiled.bin"
        (p, errors) = parse_src(src_fn)
        if errors != []:
            print_errors(errors)
        else:
            p = paktAst.unwrap_prog(p)
            p = paktAst.move_main_to_front(p)
            p = paktAst.flatten_prog(p)
            container = Common.unmarshal_from_file(vg_fn)
            s = paktAst.dump_prog(p)
            cl, pairs, bin_str = compile(p, container)
            print "DUMPED:\n%s\n####\n" % (s)
            write_str_to_file(out_fn, bin_str)
    else:
        err = "Usage:\n%s <src fn> <vg fn>\n" sys.argv[0]
        print err

if __name__ == "__main__":
    main()
