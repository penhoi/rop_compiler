from paktCommon import *
from paktAst import *

#(* Types for ropc/analysis *)
class reg(object): pass
class Forward(reg): pass
class Backward(reg): pass

#(* offsets of labels can't be computed early, so use a marker to describe them.
# * offset from begining of the function/payload *)
class symb_simple(object): pass
class Named(symb_simple):   #(* local labels are prefixed with func name, so all searches can be global *)
    def __init__(self, tagid):
        self.id = tagid
    def param(self):
        return self.id

class Unnamed(symb_simple):
    def __init__(self, direction_val):
        self.drt = direction_val
    def param(self):
        return self.drt

#(* (start, end) - what's the distance from label "start" to label "end" ? *)
class symb(object):
    def __init__(self, symb_simple_from, symb_simple_to):
        self.frm = symb_simple_from
        self.to = symb_simple_to
    def param(self):
        return self.frm, self.to

#(* symbolic(tagid), concrete(reg) *)
class sreg(object): pass
class S(sreg):
    def __init__(self, int_val):
        self.v = int_val
    def param(self):
        return self.v

class C(sreg):
    def __init__(self, reg_val):
        self.v = reg_val
    def param(self):
        return self.v

class instr(object): pass
class AdvanceStack(instr):
    def __init__(self, int_val):
        self.v = int_val
    def param(self):
        return self.v

class RawHex(instr):
    def __init__(self, int_val):
        self.v = int_val
    def param(self):
        return self.v

class MovRegConst(instr):
    def __init__(self, sreg_val, int_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.sreg, self.v

class MovRegReg(instr):
    def __init__(self, sreg_v1, sreg_v2):
        self.sreg1 = sreg_v1
        self.sreg1 = sreg_v2
    def param(self):
        return self.sreg_v1, self.sreg_v2

class MovRegSymb(instr):
    def __init__(self, sreg_v, symb_v):
        self.sreg = sreg_v
        self.symb = symb_v
    def param(self):
        return self.sreg_v, self.symb_v

class WriteM(instr):    #(* [addr_reg] <- src *)
    def __init__(self, sreg_v1, sreg_v2):
        self.sreg1 = sreg_v1
        self.sreg1 = sreg_v2
    def param(self):
        return self.sreg_v1, self.sreg_v2

class ReadM(instr):     #(* dst <- [addr_reg] *)
    def __init__(self, sreg_v1, sreg_v2):
        self.sreg1 = sreg_v1
        self.sreg1 = sreg_v2
    def param(self):
        return self.sreg_v1, self.sreg_v2

class SaveFlags(instr): pass

class OpStack(instr):
    def __init__(self, operator_v, sreg_v):
        self.op = operator_v
        self.sreg = sreg_v
    def param(self):
        return self.op, self.sreg

class BinO(instr):
    def __init__(self, sreg_v1, operator_v, sreg_v2, sreg_v3):
        self.sreg1 = sreg_v1
        self.op = operator_v
        self.sreg2 = sreg_v2
        self.sreg3= sreg_v3
    def param(self):
        return self.sreg1, self.op, self.sreg2, self.sreg3

#(* T1 *)
class ReadMConst(instr):    #(* dst <- [const] *)
    def __init__(self, sreg_val, int_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.sreg, self.v

class WriteMConst(instr):   #(* [const] <- src *)
    def __init__(self, int_val, sreg_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.v, self.sreg

#(* T2 *)
class LocalAddr(instr):
    def __init__(self, int_val, sreg_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.v, self.sreg

class PushReg(instr):   #(* push sreg on emu stack *)
    def __init__(self, sreg_val):
        self.sreg = sreg_val
    def param(self):
        return self.sreg

class PopReg(instr):    #(* pop sreg from emu stack *)
    def __init__(self, sreg_val):
        self.sreg = sreg_val
    def param(self):
        return self.sreg

#(* T3 *)
class ReadLocal(instr):     #(* dst <- local_var(i) *)
    def __init__(self, int_val, sreg_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.v, self.sreg

class WriteLocal(instr):    #(* dst <- local_var(i) *)
    def __init__(self, int_val, sreg_val):
        self.sreg = sreg_val
        self.v = int_val
    def param(self):
        return self.v, self.sreg

class Lbl(instr):
    def __init__(self, tagid_val):
        self.id = tagid_val
    def param(self):
        return self.id

class Comment(instr):   #(* store deleted instructions as comments *)
    def __init__(self, str_val):
        self.str = str_val
    def param(self):
        return self.str_val

#type ityp = T0 | T1 | T2 | T3
class ityp(object): pass
class T0(ityp): pass
class T1(ityp): pass
class T2(ityp): pass

def is_lbl_or_comment(instr):
    if type(instr) in [Lbl, Comment]:
        return True
    else:
        return False

def dump_dir(x):
    if type(x) == Forward:
        return "@f"
    elif type(x) == Backward:
        return "@b"

def dump_symb(x):
    if type(x) == Named:
        (tagid) = x.param()
        s = "Named(%s)" % tagid
    elif type(x) == Unnamed:
        (direction) = x.param()
        s = "Unnamed(%s)" % (dump_dir(direction))
    return s

def dump_sreg(x):
    if type(x) == S:
        (tagid) = x.param()
        s = "r%d" % (tagid)
    elif type(x) == C:
        (r) = x.param()
        s = dump_reg(r)
    return s

def dump_instr(x):
    if type(x) == AdvanceStack:
        (n) = x.param()
        s = "esp += %d" % n
    elif type(x) == RawHex:
        (n) = x.param()
        s = "hex(0x%08x)" % n
    elif type(x) == MovRegConst:
        (r, c) = x.param()
        s = "%s = 0x%08x" % (dump_sreg(r), c)
    elif type(x) == MovRegReg:
        (r1, r2)  = x.param()
        s = "%s = %s" % (dump_sreg(r1), dump_sreg(r2))
    elif type(x) == MovRegSymb:
        (r, FromTo_s_f)  = x.param()
        (s, f) = FromTo_s_f.param()
        s = "%s = (from: %s, to: %s)" % (dump_sreg(r), dump_symb(s), dump_symb(f))
    elif type(x) == WriteM:
        (r1, r2) = x.param()
        s = "[%s] = %s" % (dump_sreg(r1), dump_sreg(r2))
    elif type(x) == ReadM:
        (r1, r2) = x.param()
        s = "%s = [%s]" % (dump_sreg(r1), dump_sreg(r2))
    elif type(x) == SaveFlags:
        s = "SaveFlags"
    elif type(x) == OpStack:
        (op, r) = x.param()
        s = "esp = esp %s %s" % (dump_op(op), dump_sreg(r))
    elif type(x) == BinO:
        (ro, r1, op, r2) = x.param()
        s = "%s = %s %s %s" % (dump_sreg(ro), dump_sreg(r1), dump_op(op), dump_sreg(r2))
    elif type(x) == ReadMConst:
        (r, addr) = x.param()
        s = "%s = [0x%08x]" % (dump_sreg(r), addr)
    elif type(x) == WriteMConst:
        (addr, r) = x.param()
        s = "[0x%08x] = %s" % (addr, dump_sreg(r))

    elif type(x) == LocalAddr:
        (off, r) = x.param()
        s = "%s = &local(%d)" % (dump_sreg(r), off)
    elif type(x) == PushReg:
        (r) = x.param()
        s = "push(%s)" % (dump_sreg(r))
    elif type(x) == PopReg:
        (r) = x.param()
        s = "pop(%s)" (dump_sreg(r))

    elif type(x) == ReadLocal:
        (off, r) = x.param()
        s = "%s = *local(%d)" % (dump_sreg(r), off)
    elif type(x) == WriteLocal:
        (off, r) = x.param()
        s = "*local(%d) = %s" % (off, dump_sreg(r))
    elif type(x) == Lbl:
        (tagid) = x.param()
        s = "%s:" % (tagid)
    elif type(x) == Comment:
        (s) = x.param()
        s = ";%s" % s
    else:
        s = ""
    return s

def ast_op_to_gadget_op(op):
    if type(op) == Add:
        return ADD
    elif type(op) == Sub:
        return SUB
    if type(op) == Mul:
        return MUL
    if type(op) == Div:
        return DIV
    if type(op) == Xor:
        return XOR
    if type(op) == And:
        return AND
    if type(op) == Or:
        return OR
    if type(op) == Not:
        print "'Not x' should be: x xor 0xffffffff"

def make_generator(f):
    r = 0
    def fnext():
        tagid = r
        r = r + 1
        f(tagid)
    fnext()

def make_reg_generator():
    make_generator(lambda tagid: S(tagid))

class RegOrder(object):
    def __init__(self):
        self.t = reg
        self.compare = cmp
#Set.Make((RegOrder)
RegSet = set([])

class SRegOrder(object):
    def __init__(self):
        self.t = sreg
        self.compare = cmp
#Set.Make( SRegOrder )
SRegSet = set([])

def set_from_list(l):
    RegSet = set(l)
    return RegSet

def sreg_set_from_list(l):
    SRegSet = set(l)
    return SRegSet

def common_reg_set_to_sreg_set(setx):
    l = RegSet.elements(setx)
    l = map((lambda r: C(r)), l)
    setx = sreg_set_from_list(l)
    return setx

def dump_sreg_set(setx):
    sregs = SRegSet.elements(setx)
    generic_dumper((lambda r: dump_sreg(r)), sregs)
    return ()

fULL_REG_SET = set_from_list(rEGS_NO_ESP)


