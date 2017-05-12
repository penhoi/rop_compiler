import os, sys
from paktCommon import *

class meta(object):
    def __init__(self, int_data):
        self.lnum = int_data
    def param(self):
        return self.lnum    

class operator(object): pass
class Add(operator): pass
class Sub(operator): pass
class Mul(operator): pass
class Div(operator): pass
class Xor(operator): pass  
class And(operator): pass
class Or(operator): pass
class Not(operator): pass 
class exp(object): pass 
    
class BinOp(exp):
    def __init__(self, exp_value_l, op_value, exp_value_r):
        self.expl = exp_value_l
        self.op = op_value
        self.expr = exp_value_r
    def param(self):
        return self.expl, self.op, self.expr
    
class UnOp(exp):
    def __init__(self, op_value, exp_value):
        self.op = op_value
        self.exp = exp_value
    def param(self):
        return self.op, self.exp
    
class Var(exp):
    def __init__(self, id_value):
        self.id = id_value  #(* address of var *)
    def param(self):
        return self.id
    
class Ref(exp):
    def __init__(self, id_value):
        self.id = id_value  #(* address of var *)
    def param(self):
        return self.id
    
class ReadMem(exp):
    def __init__(self, id_value):
        self.id = id_value
    def param(self):
        return self.id
    
class Const(exp):
    def __init__(self, int_value):
        self.val = int_value
    def param(self):
        return self.val
        

E = "flag E"
A = "flag A"
B = "flag B"
MP = "flag MP"  #(* jMP = jump always *)
 
#type cond = Cond of flag list | NCond of flag list
class cond(object): pass
class Cond(cond):
    def __init__(self, flag_list):
        self.list = flag_list
    def param(self):
        return self.list
    
class NCond(cond):
    def __init__(self, flag_list):
        self.list = flag_list
    def param(self):
        return self.list

#type exp_args = ExpArgs of exp list
class exp_args(object): pass
class ExpArgs(exp_args):
    def __init__(self, exp_value, list_value):
        self.exp = exp_value
        self.list = list_value
    def param(self):
        return self.exp, self.list
            

class stmt(object): pass
class Assign(stmt):
    def __init__(self, id_value, exp_value):
        self.id = id_value
        self.exp = exp_value
    def param(self):
        return self.id, self.exp
            
class DerefAssign(stmt):
    def __init__(self, id_value, exp_value):    #(* *var = 1 *)
        self.id = id_value
        self.exp = exp_value
    def param(self):
        return self.id, self.exp
            
class AssignTab(stmt):
    def __init__(self, id_value, int_list):     #(* var = [1,2,3] *)
        self.id = id_value
        self.list = int_list
    def param(self):
        return self.id, self.list
            
class WriteMem(stmt):
    def __init__(self, id_value, exp_value):
        self.id = id_value
        self.exp = exp_value
    def param(self):
        return self.id, self.exp
            
class Branch(stmt):
    def __init__(self, cond_value, exp_value):
        self.cond = cond_value
        self.exp = exp_value
    def param(self):
        return self.cond, self.exp
            
class Label(stmt):
    def __init__(self, id_value):
        self.id = id_value
class Cmp(stmt):
    def __init__(self, exp_value_l, exp_value_r):
        self.expl = exp_value_l
        self.expr = exp_value_r
    def param(self):
        return self.expl, self.expr
    
class Call(stmt):
    def __init__(self, id_value, exp_args_value):
        self.id = id_value
        self.args = exp_args_value
    def param(self):
        return self.id, self.args
    
class ExtCall(stmt):
    def __init__(self, id_value, exp_args_value):
        self.id = id_value
        self.args = exp_args_value
    def param(self):
        return self.id, self.args
    
class Enter(stmt):
    def __init__(self, int_value):
        self.v = int_value
    def param(self):
        return self.v
    
class Leave(stmt): pass
class Ret(stmt):
    def __init__(self, id_value):
        self.id = id_value
    def param(self):
        return self.id

class args(object): pass
class Args(args):
    def __init__(self, id_list):
        self.list = id_list
    def param(self):
        return self.list

class func_body(object): pass
class FunBody(func_body):
    def __init__(self, stmt_list):
        self.list = stmt_list
    def param(self):
        return self.list

#type func = Fun of tagid * args * func_body
class func(object): pass
class Fun(func):
    def __init__(self, id_value, args_value, func_body_value):
        self.id = id_value
        self.args = args_value
        self.func = func_body_value
    def param(self):
        return (self.id, self.args, self.func)


#type program = Prog of func list
class program(object): pass
class Prog(program):
    def __init__(self, func_list):
        self.list = func_list
    def param(self):
        return self.list

#type func_body' = FunBody_prime of stmt wrapped list
class func_body_prime(object): pass
class Func_body_prime(func_body_prime):
    def __init__(self, stmt_wrapped_list):
        self.list = stmt_wrapped_list
    def param(self):
        return self.list

#type func' = Fun_prime of tagid * args * func_body'
class func_prime(object): pass
class Func_prime(func_prime):
    def __init__(self, id_value, args_value, func_body_value):
        self.id = id_value
        self.args = args_value
        self.func_body = func_body_value
    def param(self):
        return (self.id, self.args, self.func_body)
    
#type program' = Prog_prime of func' wrapped list
class program_prime(object): pass
class Prog_prime(program):
    def __init__(self, func_wrapped_list):
        self.list = func_wrapped_list
    def param(self):
        return self.list
    
#type error = Error of meta * string
class error(object): pass
class Error(error):
    def __init__(self, meta_value, string_value):
        self.meta = meta_value
        self.str = string_value
    def param(self):
        return (self.meta, self.str)

def unwrap(wrapped):
    return wrapped.n

def get_meta(wrapped):
    return wrapped.m

def unwrap_func(func):
    func = unwrap(func)
    (tagid, args, FunBody_prime_sl) = func.param()
    sl = FunBody_prime_sl.param()
    sl = map(unwrap, sl)
    return Fun(tagid, args, FunBody(sl))

def unwrap_prog(p):
    Prog_prime_fl = p.param()
    fl = Prog_prime_fl.param()
    fl = map(unwrap_func, fl)
    return Prog(fl)
    
br = ["e", "a", "b"]
branches = br + map(lambda x: "n"+x, br) + ["mp"]

fl_to_char = [(E, 'e'), (A, 'a'), (B, 'b'), (MP, '@')]
ch_to_flag = map((lambda (x,y): (y,x)), fl_to_char)
#let f2c = Common.create_hashtable 8 fl_to_char
f2c = create_hashtable(8, fl_to_char)
#let c2f = Common.create_hashtable 8 ch_to_flag
c2f = create_hashtable(8, ch_to_flag)

 
def str_to_cond(s):
    def char_to_flag (c): 
        if c in c2f:
            return c2f[c]
        else:
            raise Exception("Not find reg c")
        
    def str_to_flag_list(s): #{
        def aux(s, i, n, acc): #{
            if i == n:
                return acc
            else:
                c = s[i]
                if c == 'n':
                    raise Exception("c is n")
                else:
                    f = char_to_flag(c)
                    aux(s, i+1, n, f+acc)
        aux(s, 0, len(s), [])
        #}end aux
    #}end str_to_flag_list
    
    if s == "mp": #{
        c = Cond([MP])
    else:
        tl = s[1::]
        hd = s[0]
        #(* let _ = Printf.print "strtocond: %s\n" (string_of_int(len( fl)) in *)
        if hd == 'n':
            fl = str_to_flag_list(tl)
            c = NCond(fl)
        else:
            fl = str_to_flag_list(s)
            c = Cond(fl)
    #}end if
    return c

def dump_op(op):
    if type(op) == Add: return "+"
    elif type(op) == Add: return "+"
    elif type(op) == Sub: return "-"
    elif type(op) == Mul: return "*"
    elif type(op) == Div: return "/"
    elif type(op) == Xor: return "^"
    elif type(op) == And: return "&"
    elif type(op) == Or: return "|"
    elif type(op) == Not: return "~"

def dump_exp(exp):
    if type(exp) == Const:
        (x) = exp.param()
        s = str(x)
    elif type(exp) == Var:
        s = exp.param()
    elif type(exp) == Ref:
        x = exp.param()
        s = "&%s" % x
    elif type(exp) == UnOp: 
        (op, e) = exp.param()
        s = "UnOp(%s, %s)" % (dump_op(op), dump_exp(e))
    elif type(exp) == BinOp:
        (e1, op, e2) = exp.param()
        s = "BinOp(%s,%s,%s)" % (dump_exp(e1), dump_op(op), dump_exp(e2))
    elif type(exp) == ReadMem:
        tagid = exp.param()
        s = "ReadMem(%s)" % tagid
    else:
        s = ""
    return s

def dump_exp_args(ea):
    if type(ea) == ExpArgs:
        ExpArgs_args = ea.param()
        s_args = str_fold(dump_exp, ExpArgs_args, ",")
        return s_args

def dump_flag_list(ll):
    def aux(l, acc):
        if l != []:
            hd = l[0]
            tl = l[1::]
            if hd in f2c:
                c = f2c(hd)
                aux(tl, [c] + acc)
            else:
                raise Exception("hd not in f2c")
    # end aux(l, acc)
    
    chars = aux(ll, [])
    strs = map((lambda c: str(c)), chars)
    s = str_fold(tagid, strs, ";")
    return s

def dump_cond(cond):
    if type(cond) == Cond:
        l = cond.param()
        s = dump_flag_list(l)
        s = "[%s]" % s
    elif type(cond) == NCond:
        l = cond.param()
        s = dump_flag_list(l)
        s = "~[%s]" % s 
    return s

def dump_stmt(stmt):
    if type(stmt) == Assign:
        (tagid, exp) = stmt.param()
        s = "Assign(%s, %s)" % (tagid, dump_exp(exp))
    elif type(stmt) == DerefAssign:
        (tagid, exp) = stmt.param()
        s = "DerefAssign(%s, %s)" % (tagid, dump_exp(exp))
    elif type(stmt) == AssignTab:
        (tagid, l) = stmt.param()
        s = "AssignTab(%s, %s)" % (tagid, dump_int_list(l))
    elif type(stmt) == Branch:
        (cond_l, tagid) = stmt.param()
        s = "Branch(%s, %s)" % (dump_cond(cond_l), tagid)
    elif type(stmt) == Label:
        (tagid) = stmt.param()
        s = "Label(%s)" % tagid
    elif type(stmt) == WriteMem:
        (tagid, exp) = stmt.param()
        s = "WriteMem(%s, %s)" % (tagid, dump_exp(exp))
    elif type(stmt) == Cmp:
        (e1, e2) = stmt.param()
        s = "Cmp(%s, %s)" % (dump_exp(e1), dump_exp(e2))
    elif type(stmt) == Call:
        (tagid, exp_args) = stmt.param()
        s = "Call(%s, %s)" % (tagid, dump_exp_args(exp_args))
    elif type(stmt) == ExtCall:
        (tagid, exp_args) = stmt.param()
        s = "!Call(%s, %s)" % (tagid, dump_exp_args(exp_args))
    elif type(stmt) == Enter:
        (n) = stmt.param()
        s = "Enter(%d)" % n
    elif type(stmt) == Leave:
        () = stmt.param()
        s = "Leave"
    elif type(stmt) == Ret:
        (s) = stmt.param()
        s = "ret(%s)" % s
    else:
        s = ""
    return s
        

def dump_args (args): 
    if type(args) == Args:
        Args_args = args.param()
        s_args = str_fold(tagid, Args_args, ",")
        return s_args

def dump_body(body):
    if type(body) == FunBody:
        FunBody_stmt_list = body.param()
        str_fold(dump_stmt, FunBody_stmt_list, "\n")

def dump_func_head(f): 
    if type(f) == Fun:
        (tagid, args, _) = f.param()
        s_args = dump_args (args)
        s = "# Fun: %s, args: %s" % (tagid, s_args)
        return s

def dump_func (f):
    if type(f) == Fun:
        (tagid, args, body) = f.param()
        head = dump_func_head(f)
        s_body = dump_body(body)
        s = "%s\n%s\n" %  (head, s_body)
        return s
    
def dump_prog (p):
    if type(p) == Prog:
        Prog_func_list = p.param()
        str_fold(dump_func, Prog_func_list, "\n")

#(* AST verification 
#  * - are all vars initialized before use? (done)
#  * - branches only to defined labels (done)
#  * - calls only to defined functions (done)
#  * - unique function names (done)
#  * - exactly one "main" function without(?) params (done)
#  * - calls with correct number of params (done)
#  *)

def is_label(x): 
    if type(x) == Label:
        return True
    else:
        return False

def is_fun_wr(x): 
    if type(x) == Fun_prime:
        return True
    else:
        return False

def is_branch(x):
    if type(x) == Branch:
        return True;
    else:
        return False

def is_call(x):
    if type(x) == Call:
        return True
    else:
        return False

def is_ext_call(x):
    if type(x) == ExtCall:
        return True
    else:
        return False

def is_init_id(x):
    if type(x) == Assign:
        (tagid, _) = x.param()
        return True, tagid
    else:
        return False, "NOT AN ID"


def make_collect(is_thing, stmts): 
    def aux(stmts, acc): 
        if [] != stmts:
            hd = stmts[0]
            tl = stmts[1:]
            ok = is_thing(hd)
            if ok: 
                aux(tl, [hd] + acc)
            else:
                aux(tl, acc)
        else:
            return acc

    aux(stmts, [])

def make_collect_wr(is_thing, stmts): 
    is_thing = lambda x: is_thing(unwrap (x))
    make_collect(is_thing, stmts)

#collect_labels_wr = make_collect_wr is_label
#collect_branches_wr = make_collect_wr is_branch
#collect_calls_wr = make_collect_wr is_call

"""
(*
collect_call_targets = make_collect is_call_target
collect_ext_call_targets = make_collect is_ext_call_target
*)
"""

def collect_used_vars_exp(exp): 
    def aux(x, acc): #{ 
        if type(x) in [Const, ReadMem]:
            return acc
        elif type(x) in [Var, Ref]:
            return x+acc
        elif type(x) == UnOp:
            (_,e) = x.param()
            aux(e, acc)
        elif type() == BinOp:
            (e1,_,e2) = x.param()
            acc = aux(e1, acc)
            aux(e2, acc)
    #}end aux
    aux(exp, [])        

def update_init_vars(vars, stmt): 
    ok, tagid = is_init_id(stmt)
    if ok:
        return id+vars
    else:
        return vars

def collect_used_vars_stmt(x):
    if type(x) == Assign:
        (_, e) = x.param()
        return []
    elif type(x) == DerefAssign:
        (_, e) = x.param()
        return []
    elif type(x) == WriteMem:
        (_, e) = x.param()
        return collect_used_vars_exp(e)
    elif type(x) == Cmp:
        (e1, e2) = x.param()
        l1 = collect_used_vars_exp(e1)
        l2 = collect_used_vars_exp(e2)
        return l1 + l2
    elif type(x) in [Call, ExtCall]:
        (_, e_args) = x.param()
        def f(acc, exp): 
            vars = collect_used_vars_exp(exp)
            return vars+acc

        (expl) = e_args.param()
        ll = fold_left(f, [], expl)
        List.concat ll
    else:
        return []
    
def collect_init_var(x)
    if type(x) == AssignTab:
        (v,_) = x.param() 
        return []
    elif type(x) == Assign:
        (v,_) = x.param()
        return Some(v)
    else:
        return None
    
def var_id(hd):    
    tagid = None
    if type(hd) == Ref:
        (tagid) = hd.param()
    elif type(hd) == Var:
        (tagid) = hd.param()
    else:
        raise Exception("var_id")
    return tagid

def label_id(x):
    if type(x) == Label:
        (tagid) = x.param()
        return tagid
    else:
        raise Exception("label_id")

def call_id(x):
    if type(x) == Call:
        (tagid, _) = x.param()
        return tagid
    else:
        raise Exception("call_id")

def fun_id_prime(x):
    (tagid, _, _) = x.param()
    return tagid

def make_error_fun(f, l): 
    def aux(acc, node):
        pos, s = f(node)
        e = Error(pos, s)
        return e+acc

    fold_left(aux, [], l)

def fancy_filter_(f, g, defs, nodes, flip): 
    def p(node): 
        pred = lambda x: f(x, =, g, node)
        found = (List.exists pred defs)
        if flip:
            return not found
        else:
            return found

    filter(p, nodes)

#(* return nodes not 'defined' in defs *)
def fancy_filter(f, g, defs, nodes):
    return fancy_filter_(f, g, defs, nodes, True)
    
#(* return nodes 'defined' in defs *)
def fancy_filter_prime(f, g, defs, nodes):
    return fancy_filter_(f, g, defs, nodes, False)

def used_before_init(init_vars, vars): 
    f = var_id
    bad = fancy_filter(id, f, init_vars, vars)
    return bad

def verify_vars_in_func(func):
    def error_not_init(pos, vars): #{
        def f(var): #{
            tagid = var_id(var)
            s = "Uninitialized variable: %s" % tagid
            return (pos, s)
        
        erf = make_error_fun(f)
        return erf, vars
        #}end f
    #}end error_not_init

    (tagid, Args_args, FunBody_prime_stmts) = func.param()
    args =  Args_args.param()
    stmts = FunBody_prime_stmts.param()
     
    #(* uninit. ids are reported only once *)
    def find_uninitialized(stmts): 
        def aux(stmts, init_vars errors): 
            if len(stmts) != 0:
                hd = stmts[0]
                tl = stmts[1:]
                pos = get_meta(hd)
                hd = unwrap(hd)
                vars = collect_used_vars_stmt(hd)
                new_init = collect_init_var(hd) #(* Some(v) / OcamlNone *)
                bad = used_before_init(init_vars, vars)
                new_errors = error_not_init(pos, bad)
                errors = new_errors + errors
                match new_init with
                if type(new_init) == Some(v):
                    aux(tl, [v] + init_vars, errors)
                elif new_init == None:
                    aux(tl, init_vars, errors)
            else:
                return errors
        #end aux
        return aux(stmts, args, [])
    #}end find_uninitialized
    return find_uninitialized(stmts)

def verify_jumps_in_func(func): 
    def branch_target(b):
        if type(b) == Branch:
            (_, t) = b.param()
            return t
        else:
            raise Exception("verify_jumps_in_func")

    def error_bad_label(branches): 
        def f(branch): 
            pos = get_meta(branch)
            branch = unwrap(branch)
            tagid = branch_target(branch)
            s = "No such label: %s" % tagid
            return (pos, s)
        #end f
        erf = make_error_fun(f)
        return erf, branches

    (tagid, args, FunBody_prime_stmts) = func.param()
    stmts = FunBody_prime_stmts.param()
    def_labels = collect_labels_wr(stmts)
    branches = collect_branches_wr(stmts)
    def f(label): 
        label_id(unwrap(label))
    def g(branch): 
        branch_target(unwrap(branch))
    bad = fancy_filter(f, g, def_labels, branches)
    return error_bad_label, bad
            
def cmp_by_pos(e1, e2):
    (p1, _) = e1.param()
    (p2, _) = e2.param()
    return p1.lnum - p2.lnum

def cmp_by_str(e1, e2): 
    (_, s1) = e1.param()
    (_, s2) = e2.param()
    if s1 < s2:
        return -1
    elif s1 == s2:
        return 0
    else:
        return 1

def sort_by_pos(errors): 
    errors.sort(cmp_by_pos) 

def sort_and_cut(errors): 
    errors = sort_by_pos(errors)
    errors = errors.stable_sort(cmp_by_str)
    errors = unique(cmp_by_str, errors)
    errors = sort_by_pos(errors)
    return errors

def pos_id_call(call): 
    pos = get_meta(call)
    tagid = call_id(unwrap(call))
    return (pos, tagid)

def collect_calls_in_func(func): 
    (_, _, FunBody_prime_stmts) = func.param()
    stmts =  FunBody_prime_stmts.param()
    calls = collect_calls_wr(stmts)
    return calls

def verify_calls(f_ids, func): 
    calls = collect_calls_in_func(func)
    def f(call): 
        (pos, tagid) = pos_id_call(call)
        s = "No such function: %s" % tagid
        return (pos, s)

    def g(call):
        call_id(unwrap(call))
    bad_calls = fancy_filter(id, g, f_ids, calls)
    erf = make_error_fun(f)
    return erf, bad,_calls

#(* id_count = [(f_id, f_param_count); ...] *)
def verify_calls_params(id_count, func): 
    def call_arg_count(x): 
        if type(x) == Call:
            (tagid, ExpArgs_l) = x.param():
            l = ExpArgs_l.param()
            return len(l)
        else:
            raise Exception("verify_calls_params")

    calls = collect_calls_in_func(func)
    def f(call): 
        (pos, tagid) = pos_id_call(call)
        c_count = call_arg_count(unwrap(call))
        let(_, f_count) = List.find(fun (f_id, _) -> f_id = tagid) id_count in
        s = "Function \"%s\" takes %d params, not %d" % (tagid, f_count, c_count)
        return (pos, s)

    def g(call): 
        call = (unwrap call)
        tagid = call_id(call)
        c_count = call_arg_count(call)
        return (tagid, c_count)

    def g_id(call):
        call_id(unwrap(call))
    defined_calls = fancy_filter_prime(fst, g_id id_count, calls)
    bad = fancy_filter(id, g, id_count, defined_calls)
    erf = make_error_fun(f)
    return erf, bad

def cmp_func_by_pos(f1, f2): 
    m1 = get_meta(f1)
    m2 = get_meta(f2)
    return m1.lnum - m2.lnum

def cmp_func_by_id(f1, f2): 
    f1 = unwrap(f1)
    f2 = unwrap(f2)
    (id1, _, _) = f1.param()
    (id2, _, _) = f2.param()
    if id1 = id2:
        return 0 
    elif id1 < id2:
        return -1
    else:
        return 1

def verify_funs(f_list): 
    f_list = f_list.sort(cmp_func_by_pos)
    f_list = f_list.sort(cmp_func_by_id)
    def f(func): 
        pos = get_meta(func)
        tagid = fun_id_prime(unwrap(func)) 
        first = List.find(fun f -> fun_id_prime (unwrap f) = tagid) f_list in
        m = get_meta(first)
        lnum = m.lnum 
        s = "Function %s already defined @ %d" % (tagid, lnum)
        return (pos, s)

    bad = nonunique(cmp_func_by_id, f_list) 
    erf = make_error_fun(f)
    return erf, bad

def cmp_by_meta(n1, n2): 
    return n1.m.lnum - n2.m.lnum

def arg_len(func):
    func = unwrap(func)
    (_, Args_args, _) = func.param()
    args = Args_args.param()
    return len(args)

#(* exactly one "main" without params *)
def verify_main_func(f_list): 
    mains = filter((lambda x: fun_id_prime(unwrap(x)) == "main"), f_list)
    if len(mains) == 0:
        s = "There must be exactly one \"main\" function (with no params)"
        error = Error({lnum=0}, s)
        return [error]
    else
        #(* we don't care about dupes, since verify_funs will take care of that *)
        mains = mains.sort(cmp_by_meta)
        let bad = filter((lambda x: arg_len(x) > 0), mains)
        def f(func):
            pos = get_meta(func)
            s = Printf.sprint "\"main\" can't have parameters (this one has %d)" % (arg_len(func))
            return (pos, s)
        #end f
        erf = make_error_fun(f)
        return erf, bad

def verify_prog(p): 
    (f_list) = p.param()
    f_id_count = map(lambda f: fun_id_prime(unwrap(f), arg_len, f)), f_list) 
    f_ids = map(fst, f_id_count) 
    def f(acc, func): 
        func = unwrap(func)
        err1 = verify_jumps_in_func(func)
        err2 = verify_vars_in_func(func)
        err3 = verify_calls(f_ids func)
        err4 = verify_calls_params(f_id_count, func)
        err = err1 + err2 + err3 + err4
        err = sort_and_cut(err)
        return err + acc

    errors = fold_left(f, [], f_list)
    errors = errors[0] + errors[1]
    errors = errors + verify_funs(f_list) 
    errors = errors + verify_main_func(f_list) 
    errors = sort_by_pos(errors)
    return errors

def dump_error(error):
    if type(error) == Error:
        (pos, s) = error.param()
        lnum = pos.lnum
        s = print "%d: %s" lnum s
        return s

def dump_errors(errors):
    return map(dump_error, errors)

#(* Flattening *)

#(* exp. flattening
#  * BinOp(e1, op, e2) ->
#  * tmp1 = flat(e1)
#  * tmp2 = flat(e2)
#  * BinOp(tmp1,op,tmp2)
# *)

def wrap_flatten_exp(exp, n):
    def new_tmp(n): 
            tmp = "tmp" + str(n)
            eid = Var(tmp)
            return eid, tmp

    def wrap(e, l n): 
        if type(e) == Const:
            return e,l,n
        elif type(e) == Var:
            return e,l,n
        elif type(e) == Ref:
            return e,l,n
        else:
            e_prime, tmp = (new_tmp(n)).param()
            e = e_prime.param()
            assign = Assign(tmp, e)
            return e_prime, [assign] + l, n+1

    e_prime, l, n = flatten_exp(exp(n))
    e_prime, l, n = wrap(e_prime, l, n)
    return e_prime, l, n
and
def flatten_exp(exp, n):
    elif type(exp) == Const:
        x = exp.param()
        return exp, [], n
    elif type(exp) == Var:
        x = exp.param()
        return exp, [], n
    elif type(exp) == Ref:
        x = exp.param()
        return exp, [], n
    elif type(exp) == ReadMem:
        (tagid) = exp.param()
        return exp, [], n
    elif type(exp) == UnOp:
        (op,e) = exp.param()
        e_prime, l, n = wrap_flatten_exp(e, n)
        return UnOp(op,e_prime), l, n
        
    elif type(exp) == BinOp:
        (e1, op, e2) = exp.param()
        e1_prime, l1, n = wrap_flatten_exp(e1, n)
        e2_prime, l2, n = wrap_flatten_exp(e2, n)
        l = l1 + l2
        return BinOp(e1_prime,op, e2_prime), l, n

def flatten_stmt(s, n): 
    def handle_call(tagid, el, n):
        def f((ids, ll, n) e):
            v,l_prime,n = wrap_flatten_exp(e, n)
            return (v + ids, l_prime + ll, n)

        (ids, ll, n) = fold_left(f, ([], [], n), el)
        l = ll[0] + ll[1]
        ids = ids.reverse() 
        return ids, l, n

    #end handle_call
    if type(s) == DerefAssign:
        (tagid, e) = s.param()
        e_prime, l, n = flatten_exp(e, n)
        return DerefAssign(tagid, e_prime) + l, n

    elif type(s) == Assign:
        (tagid, e) = s.param()
        e_prime, l, n = flatten_exp(e, n)
        return Assign(tagid,e_prime) + l, n

    elif type(s) == WriteMem:
        (tagid, e) = s.param()
        let e_prime, l, n = flatten_exp(e, n)
        return WriteMem(tagid,e_prime) + l, n

    elif type(s) == Cmp:
        (e1, e2) = s.param()
        v1, l1, n = wrap_flatten_exp(e1, n)
        v2, l2, n = wrap_flatten_exp(e2, n)
        l = l1 + l2
        return Cmp(v1, v2) + l, n
    
    elif type(s) == Call:
        (tagid, ExpArgs_el) = s.param()
        el = ExpArgs_el.param()
        ids, l, n = handle_call(id, el, n)
        c = Call(tagid, ExpArgs(ids))
        return c+l, n
    
    elif type(s) == ExtCall:
        (tagid, ExpArgs_el) = s.param()
        el = ExpArgs_el.param()
        ids, l, n = handle_call(id, el, n)
        c = ExtCall(tagid, ExpArgs(ids))
        return c+l, n
    
    else:
        return [s], n

def flatten_fun_body(fb): 
    def f( (ll, n), stmt):
        l, n = flatten_stmt(stmt, n)
        retun (l::ll, n)

    stmts = None
    if type(fb) == FunBody:
        stmts = fb.param()
        
    ll = folder_left(f, ([], 0), stmts)
    ll = ll[0] + ll[1]
    l = l.reverse()

def flatten_fun(func): 
    if type(func) == Fun:
        (tagid, args, body) = func.param():
        l = flatten_fun_body(body)
        fb = FunBody(l)
        Fun(tagid, args, fb)

def flatten_prog(p): 
    if type(p) == Prog:
        (func_list) = p.param()
        fl = map(flatten_fun, func_list)
        Prog(fl)

def move_main_to_front(p): 
    def aux(main, acc, l): 
        if [] != l:
            (tagid,_,_) == hd.param()
            if tagid = "main":
                aux((Some(hd)), acc, tl)
            else
                aux(main, [hd::acc], tl)
        elif:
            if type(main) == Some:
                (f) = main.param())
                f::(List.rev acc)
            elif type(main) == OcamlNone:
                assert False

    (func_list) = p.param()
    func_list = aux(OcamlNone, [], func_list)
    Prog(func_list)
