open Common
open Ast
open Cdefs
open Printf

def instr_type(x):
    #(* T0, because we want them at every stage *)
    if type(x) in [Lbl, Comment, AdvanceStack, RawHex, MovRegConst, MovRegReg, MovRegSymb, WriteM, ReadM, SaveFlags, OpStack, BinO]:
        return T0
    elif type(x) in [ReadMConst, WriteMConst]:
        return T1
    elif type(x) in [LocalAddr, PushReg, PopReg]:
        return T2
    elif typeof(x) in [WriteLocal, ReadLocal]:
        return T3


#(* IN: instr, gmeta list *)
#(* OUT: gmeta corresponding to instr *)
def find_all_gmetas(instr, gms ): 
    def find_gms(f_match): 
        def pred(gm):

            (g,_,_,_) = gm.param() 
            f_match (g, gm)

        List.filter pred #List filter？？？？

    def is_opstack(g): 
        if type(g) == Common.OpEsp:
            return true
        else:
            return false
    
    def get_stack_fix(gm): 
        (_,_,_,sf) = gm.param()
        #??????
        let GMeta(_,_,_,sf) = gm(in sf) in
    def f_match_movreg(r, g, gm ):
        if type(g) == Common.LoadConst:
            (gr,_) = g.param()
            gr = r
            return (gr,_)
        else:
            return false
    def f_match_op_esp(op, r, g, gm ): 
        if type(g) == Common.OpEsp:
            (gop, gr,_) = g.param()
            gop = op
            gr = r
            return (gop, gr, _)
        else:
            return false
    
    def f_match() : 
        if type(instr) == OpStack:
            (op, C(r)) = instr.param()
            op1 = ast_op_to_gadget_op(op)
            return f_match_op_esp( op1, r)
        elif type(instr) == BinO:
            (C_r0, C_r1, op, C_r2) = instr.param()
            (r0) = C_r0.param()
            (r1) = C_r1.param()
            (r2) = C_r2.param()
            op_prime  = ast_op_to_gadget_op(op) 
            return  lambda (g, gm): g == Common.BinOp(r0, r1, op_prime, r2)
        elif type(instr) == WriteM:
            (C_addr_reg, C_src_reg) = instr.param()
            addr_reg = C_addr_reg.param()
            src_reg = C_src_reg.param()
            return lambda (g, gm): g == Common.WriteMem(addr_reg, Int32.zero, src_reg) 
        elif type(instr) == ReadM:
            (C_dst_reg, C_addr_reg) = instr.param()
            dst_reg = C_dst_reg.param()
            addr_reg = C_addr_reg.param()
            return lambda (g, gm):  g == Common.ReadMem(dst_reg, addr_reg, Int32.zero) 
        #(* movregsymb will be converted to mov reg const *)
        elif type(instr) ==  MovRegConst:
            (C_r) = instr.param()
            r = C_r.param()
        elif type(instr) ==  MovRegSymb:
            (C_r,_) = instr.param()
            r = C_r.param()
            return f_match_movreg(r)
        elif type(instr) == MovRegReg:
            (C_dst, C_src) = instr.param()
            dst = C_dst.param()
            src = C_src.param()
            return lambda (g, gm):  g == Common.CopyReg(dst,src) 
        elif type(instr) == SaveFlags:
            retur lambda( g, gm):  g == Common.Lahf
        elif type(instr) == AdvanceStack:
            n = instr.param()
            lambda ( g, gm):  (not (is_opstack( g)) && (get_stack_fix( gm) == n)
        #(* Can match anything, but this simplifies things *)
        elif type(instr) == RawHex:
            _ = instr.param()
            return lambda (g, gm):  get_stack_fix (gm) == 4
        #(* we don't want to lose these, so match with anything *)
        elif type(instr) == Lbl:
        elif type(instr) == Comment:
            _ = instr.param()
            return lambda( g, gm):  true
        elif type(instr) == _:
            raise Exception("analysys 105")

    matching_gms = find_gms(f_match)
    if len(matching_gms) == 0:
        raise Exception("anything 109")
    else:
        matching_gms


def make_implement(stack_ptr, frame_ptr ): 
    def implement_t1(f_next_reg, instr):
        if typeof(inst) == ReadMConst(r, addr):
        
            reg = f_next_reg ()
            mov = MovRegConst(reg, addr)
            rm = ReadM(r, reg)
            [mov;rm]
        elif typeof() == WriteMConst(addr,r):
         
            addr_reg = f_next_reg ()
            mov = MovRegConst(addr_reg, addr)
            wm = WriteM(addr_reg, r)
            [mov;wm]
        elif typeof() == _:
         assert false

    def implement_t2 f_next_reg instr =
        match instr with
        elif typeof() == PushReg(r):
        
                addr_reg = f_next_reg ()
                rm = ReadMConst(addr_reg, stack_ptr)
                wm1 = WriteM(addr_reg, r)
                reg1 = f_next_reg ()
                rm2 = ReadMConst(reg1, stack_ptr) in 
                reg2 = f_next_reg ()
                mov = MovRegConst(reg2, 4)
                reg3 = f_next_reg ()
                sub = BinO(reg3, reg1, Sub, reg2)
                wm2 = WriteMConst(stack_ptr, reg3)
                [rm;wm1;rm2;mov;sub;wm2]
        elif typeof() == PopReg(r):
        
                reg1 = f_next_reg ()
                rm1 = ReadMConst(reg1, stack_ptr)
                reg2 = f_next_reg ()
                mov = MovRegConst(reg2, 4)
                reg3 = f_next_reg ()
                sub = BinO(reg3, reg1, Add, reg2)
                wm = WriteMConst(stack_ptr, reg3)
                rm2 = ReadM(r, reg3)
                [rm1;mov;sub;wm;rm2;]
        elif typeof() == LocalAddr(off,r):
        
                reg1 = f_next_reg ()
                rm1 = ReadMConst(reg1, frame_ptr)
                reg2 = f_next_reg ()
                mov = MovRegConst(reg2, off)
                add = BinO(r, reg1, Add, reg2)
                [rm1;mov;add;]
        elif typeof() == _:
         assert false

    implement_t3 f_next_reg instr =
        match instr with
        elif typeof() == ReadLocal(off, r):
         
                addr_reg = f_next_reg ()
                la = LocalAddr(off, addr_reg)
                rm = ReadM(r, addr_reg)
                [la;rm]
        elif typeof() == WriteLocal(off, r):
        
                addr_reg = f_next_reg ()
                la = LocalAddr(off, addr_reg)
                wm = WriteM(addr_reg, r)
                [la;wm]
        #(* Caller should be aware these are special *)
        | Lbl(_) 
        elif typeof() == Comment(_):
         assert false
        elif typeof() == _:
         assert false

    def implement(instr): 
        def type2idx = function T3 -> 2 | T2 -> 1 | T1 -> 0 | T0 -> assert false
        def init () =
            f_next_reg = make_reg_generator ()
            funs = [implement_t1;implement_t2;implement_t3]
            funs = List.map (fun f -> f f_next_reg) funs
            funs

        funs = init ()
        typ = instr_type(instr)
        idx = type2idx(typ)
        f_implement = List.nth(funs idx)
        f_implement instr

    implement

