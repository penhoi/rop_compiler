'''
type reg = EAX | EBX | ECX | EDX | ESI | EDI | EBP | ESP
type op = ADD | SUB | MUL | DIV | XOR | OR | AND
type gadget =
            | LoadConst of reg * int #(* reg, stack offset *)
            | CopyReg of reg * reg #(* dst reg = src reg *)
            | BinOp of reg * reg * op * reg #(* dst reg = src1 OP src2 *)
            | ReadMem of reg * reg * int32 #(* dst = [addr_reg + offset] *)
            | WriteMem of reg * int32 * reg #(* [addr_reg + offset] = src *)
            | ReadMemOp of reg * op * reg * int32 #(* dst OP= [addr_reg + offset] *)
            | WriteMemOp of reg * int32 * op * reg #(* [addr_reg + offset] OP= src_reg *)
            | Lahf
            | OpEsp of op * reg * int #(* esp = esp op reg, where op=+/-, sf =
                stack_fix *)

#(* (offset_start, offset_end) *)
type fmeta = FileMeta of int * int
#(* gadget, file meta, modified registers, stack_fix *)
type gmeta = GMeta of gadget * fmeta * reg list * int
#(* filename, (data section start, data section end), gadget list
    type used for marshaling candidates for verification *)
type gcontainer = GContainer of string * (int * int) * gmeta list

let rEGS = [EAX; EBX; ECX; EDX; ESI; EDI; EBP; ESP;]
let rEGS_NO_ESP = [EAX; EBX; ECX; EDX; ESI; EDI; EBP;]
'''

class reg(object): pass
class EAX(reg): pass
class EBX(reg): pass
class ECX(reg): pass
class EDX(reg): pass
class ESI(reg): pass
class EDI(reg): pass
class EBP(reg): pass
class ESP(reg): pass

class op(object): pass
class ADD(op): pass
class SUB(op): pass
class MUL(op): pass
class DIV(op): pass
class XOR(op): pass
class OR(op): pass
class AND(op): pass

class gadget(object): pass

class LoadConst(gadget):
    def __init__(self, reg_val, int_val):
        self.reg_v = reg_val
        self.val_v = int_val
    def param(self):
        return (self.reg_v, self.val_v)

class CopyReg(gadget):
    def __init__(self, reg_val1, reg_val2):
        self.reg_v1 = reg_val1
        self.reg_v2 = reg_val2
    def param(self):
        return (self.reg_v1, self.reg_v2)

class BinOp(gadget):
    def __init__(self, reg_val1, reg_val2, op_val, reg_val3):
        self.reg_v1 = reg_val1
        self.reg_v2 = reg_val2
        self.op_v = op_val
        self.reg_v3 = reg_val3
    def param(self):
        return (self.reg_v1, self.reg_v2, self.op_v, self.reg_v3)

class ReadMem(gadget):
    def __init__(self, reg_val1, reg_val2, int_val):
        self.reg_v1 = reg_val1
        self.reg_v2 = reg_val2
        self.int_v = int_val
    def param(self):
        return (self.reg_v1, self.reg_v2, self.int_v)

class WriteMem(gadget):
    def __init__(self, reg_val1, int_val, reg_val2):
        self.reg_v1 = reg_val1
        self.int_v = int_val
        self.reg_v2 = reg_val2
    def param(self):
        return (self.reg_v1, self.int_v, self.reg_v2);

class ReadMemOp(gadget):
    def __init__(self, reg_val1, op_val, reg_val2, int_val):
        self.reg_v1 = reg_val1
        self.op_v = op_val
        self.reg_v2 = reg_val2
        self.int_v = int_val
    def param(self):
        return (self.reg_v1, self.op_v, self.reg_v2, self.int_v);

class WriteMemOp(gadget):
    def __init__(self, reg_val1, int_val, op_val, reg_val2):
        self.reg_v1 = reg_val1
        self.int_v = int_val
        self.op_v = op_val
        self.reg_v2 = reg_val2
    def param(self):
        return (self.reg_v1, self.int_v, self.op_v, self.reg_v2)

class Lahf(gadget): pass
class OpEsp(gadget):
    def __init__(self, op_val, reg_val, int_val):
        self.op_v = op_val
        self.reg_v = reg_val
        self.int_v = int_val
    def param(self):
        return (self.op_v, self.reg_v, self.int_v)

class fmeta(object):pass
class FileMeta(fmeta):
    def __init__(self, int_val1, int_val2):
        self.int_v1 = int_val1
        self.int_v2 = int_val2
    def param(self):
        return (self.int_v1, self.int_v2)

class gmeta(object): pass
class Gmeta(gmeta):
    def __init__(self, gadget_val, fmeta_val, reglist_val, int_val ):
        self.gadget_v = gadget_val
        self.fmeta_v = fmeta_val
        self.reglist_v = reglist_val
        self.int_v = int_val
    def param(self):
        return (self.gadget_v, self.fmeta_v, self.reglist_v, self.int_v)

class gcontainer(object): pass
class GContainer(gcontainer):
    def __init__(self, str_val, (int_val1, int_val2), gmetalist_val): #[int, int]
        self.str_v = str_val
        self.int_v1v2 = (int_val1, int_val2)
        self.gmetalist_v = gmetalist_val
    def param(self):
        return (self.str_v, (self.int_v1v2[0], self.int_v1v2[1]), self.gmetalist_v)

rEGS = [EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP]
rEGS_NO_ESP = [EAX, EBX, ECX, EDX, ESI, EDI, EBP]


def dump_reg(r):
    if type(r) == EAX :
        return "eax"
    elif type(r) == EBX:
        return "ebx"
    elif type(r) == ECX:
        return "ecx"
    elif type(r) == EDX:
        return "edx"
    elif type(r) == ESI:
        return "esi"
    elif type(r) == EDI:
        return "edi"
    elif type(r) == EBP:
        return "ebp"
    elif type(r) == ESP:
        return "esp"


def dump_op(op):
    if type(op) == ADD:
        return "+"
    elif type(op) == SUB:
        return "-"
    elif type(op) == MUL:
        return "*"
    elif type(op) == DIV:
        return "/"
    elif type(op) == XOR:
        return "^"
    elif type(op) == AND:
        return "&"
    elif type(op) == OR :
        return "|"

def dump_filemeta(fm): #??????def
    (off_s, off_e) = fm.param()
    s = "(s: 0x%x, e: 0x%x)" % (off_s, off_e)
    return s


def dump_gadget(g):
    if type(g) == LoadConst:
        (r, off) = g.param()
        s = "LoadConst(%s, 0x%x)" % (dump_reg(r), off)
    elif type(g) == CopyReg:
        (r1, r2) = g.param()
        s = "CopyReg(%s, %s)" % (dump_reg(r1), dump_reg(r2))
    elif type(g) == BinOp:
        (r_dst, r1, op, r2) = g.param()
        s = "BinOp(%s, %s, %s, %s)" % (dump_reg(r_dst), dump_reg(r1), dump_op(op), dump_reg(r2))
    elif type(g) == ReadMem:
        (r_dst, r_addr, off) = g.param()
        s = "ReadMem(%s = [%s+0x%lx])" % (dump_reg(r_dst), dump_reg(r_addr), off)
    elif type(g) == WriteMem:
        (r_addr, r_src, off) = g.param()
        s = "WriteMem([%s+0x%lx] = %s)" % (dump_reg(r_addr), off, dump_reg(r_src))
    elif type(g) == ReadMemOp:
        (r_dst, r_addr, op, off) = g.param()
        s = "ReadMemOp(%s %s= [%s+0x%lx])" % (dump_reg(r_dst), dump_op(op), dump_reg(r_addr), off)
    elif type(g) == WriteMemOp:
        (r_dst, r_addr, op) = g.param()
        s = "WriteMemOp([%s+0x%lx] %s= %s)" % (dump_reg(r_addr), off, dump_op(op), dump_reg(r_src))
    elif type(g) == OpEsp:
        (r, op, sf) = g.param()
        s = "OpEsp(%s, %s, %d)" % (dump_op(op), dump_reg(r), sf)
    elif type(g) == Lahf:
        s = "Lahf"
    else:
        s = None
    return s


def uniq(eq, l):
    if len(l) == 0:
        return l, l
    
    elif len(l) == 1:
        return l, []
    
    else:
        uni, dupes = [], []
        for e in l:
            if e not in uni:
                uni.append(e)
            elif e not in dupes:
                dupes.append(e)
        return uni, dupes
                
def unique(eq, l ):
    u, _ = uniq(eq, l)
    return u


def nonunique(eq, l):
    _, nu = uniq(eq, l)
    return nu

def generic_unique(l):
    l.sort()
    return unique(cmp, l)

def create_hashtable(size, init):
    tbl = {}
    for key, data in init:
        tbl[key] = data
    return tbl


def file_exc(filename, e ):
    print "Cannot open file \"%s\": %s\n" % (filename, e.to_string());
    assert False

def open_file(fn, fopen ):
    try:
        co = fopen(fn)
        return co
    except IOError, e:
        file_exc(fn, e)

def open_file_in(fn):
    return open_file(fn, "r+b")
def open_file_out(fn):
    return open_file(fn, "w+b")

def write_str_to_file(filename, sstr ):
    co = open_file_out(filename)
    #(* let co = Format.formatter_of_out_channel co in*)
    #output_string(co, sstr)
    co.close()

def read_file(fn):
    s = []
    with open(fn) as f:
        l = f.read_line()
        s.append(l)
    return s

def marshal_to_gadgetfile(fn, gadgets):
    #co = open_file_out(fn)
    #Marshal.to_channel co thing []
    return

def unmarshal_gadget_file(gadget_file):
    from  file_finder import FileFinder
    handle = FileFinder(gadget_file, "i386")
    gadget_list = handle.find_gadgets()

    return gadget_list

def IO_output_string():
    pass

def IO_write_i32(io, num):
    pass

def IO_write_byte(io, nbytes):
    pass

def IO_close_out(io):
    pass

#(* this assumes that RET is the last instruction *)
def drop_last(stmts):
    return stmts[:-1]

def fold_left(f, a, list_data):
    tmp = a
    for el in list_data:
        tmp = f(tmp, el)
    return tmp

def fold_right(f, list_data, b):
    tmp = b
    for el in list_data[::-1]:
        tmp = f(el, tmp)
    return tmp

def Hashtbl_fold(f, tbl, init):
    temp = init
    for k, v in tbl.items():
        temp = f(k, v, temp)
    
    return temp

def SRegSet_fold(f, rset, a):
    temp = a
    for ele in rset:
        temp = f(ele, temp)
    
    return temp

def list_flatten(l):
    #return [item for sublist in l for item in sublist]
    acc = []
    for e in l:
        if type(e) == list:
            acc += e
        else:
            acc.append(e)
    #end for
    return acc       


def find_all(p, l ):
    def f(acc, x ):
        if p(x):
            return x+acc
        else:
            return acc
    fold_left(f, [], l)

def generic_dumper(f_dump, l ):
    def f(_, x ):
        print "%s;" % (f_dump(x))

    fold_left( f, (), l)
    return ()

def dump_int_list(l):
    def f(acc, x ):
        s = str(x)
        return acc + ";" + s

    return fold_left(f, "", l)

def get_gadgets(gadget_list):
    gadgets = []
    for g in gadgets:
        gadgets.append(g)
    return gadgets
