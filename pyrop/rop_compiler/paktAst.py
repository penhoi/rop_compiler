import os, sys
#import common

class meta(object):
    def __init__(self, int_data):
        self.lnum = int_data

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
class UnOp(exp):
    def __init__(self, op_value, exp_value):
        self.op = op_value
        self.exp = exp_value
class Var(exp):
    def __init__(self, id_value):
        self.id = id_value  #(* address of var *)
class Ref(exp):
    def __init__(self, id_value):
        self.id = id_value  #(* address of var *)
class ReadMem(exp):
    def __init__(self, id_value):
        self.id = id_value
class Const(exp):
    def __init__(self, int_value):
        self.val = int_value

E = "flag E"
A = "flag A"
B = "flag B"
MP = "flag MP"  #(* jMP = jump always *)
 
class exp_args(object): pass
class ExpArgs(exp_args):
    def __init__(self, exp_value, list_value):
        self.exp = exp_value
        self.list = list_value

class stmt(object): pass
class Assign(stmt):
    def __init__(self, id_value, exp_value):
        self.id = id_value
        self.exp = exp_value
class DerefAssign(stmt):
    def __init__(self, id_value, exp_value):    #(* *var = 1 *)
        self.id = id_value
        self.exp = exp_value
class AssignTab(stmt):
    def __init__(self, id_value, int_list):     #(* var = [1,2,3] *)
        self.id = id_value
        self.list = int_list
class WriteMem(stmt):
    def __init__(self, id_value, exp_value):
        self.id = id_value
        self.exp = exp_value
class Branch(stmt):
    def __init__(self, cond_value, exp_value):
        self.cond = cond_value
        self.exp = exp_value
class Label(stmt):
    def __init__(self, id_value):
        self.id = id_value
class Cmp(stmt):
    def __init__(self, exp_value_l, exp_value_r):
        self.expl = exp_value_l
        self.expr = exp_value_r
class Call(stmt):
    def __init__(self, id_value, exp_args_value):
        self.id = id_value
        self.args = exp_args_value
class ExtCall(stmt):
    def __init__(self, id_value, exp_args_value):
        self.id = id_value
        self.args = exp_args_value
class Enter(stmt):
    def __init__(self, int_value):
        self.int = int_value
class Leave(stmt): pass
class Ret(stmt):
    def __init__(self, id_value):
        self.id = id_value

class args(object): pass
class Args(args):
    def __init__(self, id_list):
        self.list = id_list

class func_body(object): pass
class FunBody(func_body):
    def __init__(self, stmt_list):
        self.list = stmt_list

#type func = Fun of tagid * args * func_body
class func(object): pass
class Fun(func):
    def __init__(self, id_value, args_value, func_body_value):
        self.id = id_value
        self.args = args_value
        self.func_body = func_body_value

#type program = Prog of func list
class program(object): pass
class Prog(program):
    def __init__(self, func_list):
        self.list = func_list

#type func_body' = FunBody_prime of stmt wrapped list
class func_body_prime(object): pass
class Func_body_prime(func_body_prime):
    def __init__(self, stmt_wrapped_list):
        self.list = stmt_wrapped_list

#type func' = Fun_prime of tagid * args * func_body'
class func_prime(object): pass
class Func_prime(func_prime):
    def __init__(self, id_value, args_value, func_body_value):
        self.id = id_value
        self.args = args_value
        self.func_body = func_body_value
    def param(self):
        return self.id, self.args, self.func_body
    
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

def unwrap(wrapped):
    return wrapped.n

def get_meta(wrapped):
    return wrapped.m

def unwrap_func(func):
    func = unwrap(func)
    id, args, FunBody_prime_sl = func.param()
    sl = FunBody_prime_sl.param()
    sl = map(unwrap, sl)
    Fun(tagid, args, FunBody(sl))

def unwrap_prog(p):
    Prog_prime_fl = p.parm()
    fl = Prog_prime_fl.param()
    fl = map(unwrap_func, fl)
    Prog(fl)
    
br = ["e", "a", "b"]
branches = br + map(lambda x: "n"+x, br) + ["mp"]

fl_to_char = [(E, 'e'), (A, 'a'), (B, 'b'), (MP, '@')]
ch_to_flag = map ((lambda (x,y): (y,x)), fl_to_char)
#let f2c = Common.create_hashtable 8 fl_to_char
f2c = create_hashtable(8, fl_to_char)
#let c2f = Common.create_hashtable 8 ch_to_flag
c2f = create_hashtable(8, ch_to_flag)

 
def str_to_cond(s):
    def char_to_flag (c): 
        if c in c2f:
            return c2f[c]
        else:
            raise "Not find reg c"
        
    def str_to_flag_list (s):
        def aux (s, i, n, acc): 
            if i == n:
                acc
            else:
                c = s[i]
                if c == 'n':
                    return False
                else:
                    f = char_to_flag(c)
                    aux(s, i+1, n, [f, acc])
        aux (s, 0, len(s), [])
    
    if s== "mp":
        Cond([MP])
    else:
        tl = s[1::]
        hd = s[0]
        #(* let _ = Printf.print "strtocond: %s\n" (string_of_int (len( fl)) in *)
        if hd == 'n':
            fl = str_to_flag_list (tl)
            NCond(fl)
        else:
            fl = str_to_flag_list (s)
            Cond(fl)

def dump_op (op):
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
    if type(exp) == Const: return str(exp.param())
    elif type(exp) == Var: return exp.param()
    elif type(exp) == Ref:
        print "&%s" exp.param()
    elif type(exp) == UnOp: 
        op, e = exp.param()
        print "UnOp(%s, %s)" (dump_op(op)) (dump_exp(e))
    elif type(exp) == BinOp:
        e1, op, e2 = exp.param()
        print "BinOp(%s,%s,%s)" (dump_exp(e1)) (dump_op(op)) (dump_exp(e2)) 
    elif type(exp) == ReadMem:
        tagid = exp.param()
        print "ReadMem(%s)" tagid

def dump_exp_args(ea):
    if type (ea) == ExpArgs:
        ExpArgs_args = ea.param()
        s_args = str_fold (dump_exp, ExpArgs_args, ",")
        return s_args

def dump_flag_list (ll):
    def aux (l, acc):
        if l != []:
            hd = l[0]
            tl = l[1::]
            try:
                c = Hashtbl.find (f2c, hd)
                aux(tl, [c:acc])
            except:
                assert(False);
    # end def aux (l, acc)
    chars = aux (ll, [])
    strs = map ((lambda c: str(c)), chars)
    s = str_fold (tagid, strs, ";")
    return s

def dump_cond (cond):
    if type (cond) == Cond:
        l = cond.param()
        s = dump_flag_list (l)
        print "[%s]" s
    elif type (cond) == NCond:
        l = cond.param()
        s = dump_flag_list (l)
        print "~[%s]" s 

def dump_stmt (stmt):
    if type(stmt) == Assign:
        (tagid, exp) = stmt.param()
        print "Assign(%s, %s)" tagid (dump_exp(exp))
    elif type(stmt) == DerefAssign:
        (tagid, exp) = stmt.param()
        print "DerefAssign(%s, %s)" tagid (dump_exp(exp))
    elif type(stmt) == AssignTab:
        (tagid, l) = stmt.param()
        print "AssignTab(%s, %s)" tagid (dump_int_list (l))
    elif type(stmt) == Branch:
        (cond_l, id) = stmt.param()
        print "Branch(%s, %s)" (dump_cond (cond_l)) tagid
    elif type(stmt) == Label:
        (id) = stmt.param()
        print "Label(%s)" tagid
    elif type(stmt) == WriteMem:
        (tagid, exp) = stmt.param()
        print "WriteMem(%s, %s)" tagid (dump_exp(exp))
    elif type(stmt) == Cmp:
        (e1, e2) = stmt.param()
        print "Cmp(%s, %s)" (dump_exp e1) (dump_exp(e2))
    elif type(stmt) == Call:
        (tagid, exp_args) = stmt.param()
        print "Call(%s, %s)" tagid (dump_exp_args(exp_args))
    elif type(stmt) == ExtCall:
        (tagid, exp_args) = stmt.param()
        print "!Call(%s, %s)" tagid (dump_exp_args(exp_args))
    elif type(stmt) == Enter:
        (n) = stmt.param()
        print "Enter(%d)" n
    elif type(stmt) == Leave:
        () = stmt.param()
        print "Leave"
    elif type(stmt) == Ret:
        (s) = stmt.param()
        print "ret(%s)" s
        

def dump_args (args): 
    if type (args) == Args:
        Args_args = args.param()
        s_args = str_fold (tagid, Args_args, ",")
        return s_args

def dump_body (body):
    if type (body) == FunBody:
        FunBody_stmt_list = body.param())
        str_fold (dump_stmt, FunBody_stmt_list, "\n")

def dump_func_head (f): 
    if type(f) == Fun:
        (tagid, args, _) = f.param()
        s_args = dump_args (args)
        s = print "# Fun: %s, args: %s" tagid s_args
        return s

def dump_func (f):
    if type (f) == Fun:
        id, args, body) = f.param()
        head = dump_func_head (f)
        s_body = dump_body (body)
        s = print "%s\n%s\n" head s_body
        return self
    
def dump_prog (p):
    if type (p) == Prog:
        Prog_func_list = p.param()
        str_fold (dump_func, Prog_func_list, "\n")

#(* AST verification 
#  * - are all vars initialized before use? (done)
#  * - branches only to defined labels (done)
#  * - calls only to defined functions (done)
#  * - unique function names (done)
#  * - exactly one "main" function without (?) params (done)
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
    if type(x) == Assign(tagid, _):
        return True, tagid
    elif type() == _:
        return False, "NOT AN ID"


def make_collect(is_thing, stmts): 
    def aux(stmts, acc): 
        match stmts with
        if [] != :
         
            ok = is_thing(hd)
            if ok then 
                aux tl (hd::acc)
            else    
                aux tl acc
        else:
         acc

    aux stmts []

def make_collect_wr(is_thing, stmts): 
    let is_thing = fun x -> is_thing (unwrap x) in
    make_collect is_thing stmts

collect_labels_wr = make_collect_wr is_label
collect_branches_wr = make_collect_wr is_branch
collect_calls_wr = make_collect_wr is_call

#(*
collect_call_targets = make_collect is_call_target
collect_ext_call_targets = make_collect is_ext_call_target
*)

def collect_used_vars_exp(exp): 
    def aux(exp, acc): 
        match exp with
        | Const _ | ReadMem _ -> acc
        | Var _ | Ref _ -> exp::acc
        elif type() == UnOp(_,e):
         aux e acc
        elif type() == BinOp(e1,_,e2):
         
            acc = aux(e1 acc)
            aux e2 acc

    aux exp []        

def update_init_vars(vars, stmt): 
    let ok, tagid = is_init_id(stmt) in
    if ok then id::vars
    else vars

collect_used_vars_stmt = function
    | Assign(_, e) 
    | DerefAssign(_, e) 
    elif type() == WriteMem(_, e):
     collect_used_vars_exp e
    elif type() == Cmp(e1, e2):
    
        l1 = collect_used_vars_exp(e1)
        l2 = collect_used_vars_exp(e2)
        l1 @ l2
    | Call(_, e_args) | ExtCall(_, e_args) -> 
        def f(acc, exp): 
            vars = collect_used_vars_exp(exp)
            vars :: acc

        ExpArgs(expl) = e_args
        let ll = List.fold_left f [] expl in
        List.concat ll
    elif type() == _:
     []
    #(*
    | Branch of cond * tagid
    | Label of tagid
    *)

collect_init_var = function
    | AssignTab(v,_) 
    elif type() == Assign(v,_):
     Some(v)
    elif type() == _:
     OcamlNone

def var_id(hd):    
    let tagid = match hd with Ref(id) | Var(id) -> tagid | _ -> assert False in
    tagid

label_id = function
    elif type() == Label(id):
     tagid
    elif type() == _:
     assert False

call_id = function
    elif type() == Call(tagid, _):
     tagid
    elif type() == _:
     assert False

let fun_id_prime = function
    | Fun_prime(tagid, _, _) -> tagid

def make_error_fun(f, l): 
    def aux(acc, node):
        let pos, s = f(node) in
        let e = Error(pos, s) in
        e::acc

    List.fold_left aux [] l

def fancy_filter_(f, g defs nodes flip): 
    def p(node): 
        let pred = fun x -> f x = g(node) in
        found = (List.exists pred defs)
        if flip then
            not found
        else
            found

    List.filter p nodes

#(* return nodes not 'defined' in defs *)
def fancy_filter(f, g defs nodes): fancy_filter_ f g defs nodes True

#(* return nodes 'defined' in defs *)
let fancy_filter' f g defs nodes = fancy_filter_ f g defs nodes False


def used_before_init(init_vars, vars): 
    f = var_id
    bad = fancy_filter(id f init_vars vars)
    bad

def verify_vars_in_func(func):
    def error_not_init(pos, vars): 
        def f(var): 
            tagid = var_id(var)
            let s = Printf.sprint "Uninitialized variable: %s" tagid in
            (pos, s)

        erf = make_error_fun(f)
        erf vars

    let Fun_prime(tagid, Args(args), FunBody_prime(stmts)) = func in
    #(* uninit. ids are reported only once *)
    def find_uninitialized(stmts): 
        def aux(stmts, init_vars errors): 
            match stmts with
            if [] != :
            
                begin
                pos = get_meta(hd)
                hd = unwrap(hd)
                vars = collect_used_vars_stmt(hd)
                let new_init = collect_init_var hd in #(* Some(v) / OcamlNone *)
                bad = used_before_init(init_vars vars)
                new_errors = error_not_init(pos bad)
                let errors = new_errors @ errors in
                match new_init with
                elif type() == Some(v):
                 aux tl (v::init_vars) errors
                elif type() == OcamlNone:
                 aux tl init_vars errors
                end 
            else:
             errors

        aux stmts args []

    find_uninitialized stmts

def verify_jumps_in_func(func): 
    def branch_target(branch):
        match branch with
        elif type() == Branch(_, t):
         t
        elif type() == _:
         assert False

    def error_bad_label(branches): 
        def f(branch): 
            pos = get_meta(branch)
            branch = unwrap(branch)
            tagid = branch_target(branch)
            let s = Printf.sprint "No such label: %s" tagid in
            (pos, s)

        erf = make_error_fun(f)
        erf branches

    let Fun_prime(tagid, args, FunBody_prime(stmts)) = func in
    def_labels = collect_labels_wr(stmts)
    branches = collect_branches_wr(stmts)
    def f(label): label_id (unwrap label) in
    def g(branch): branch_target (unwrap branch) in
    bad = fancy_filter(f g def_labels branches)
    error_bad_label bad
            
let cmp_by_pos e1 e2 =
    let Error(p1, _) = e1 in
    let Error(p2, _) = e2 in
    p1.lnum - p2.lnum

let cmp_by_str e1 e2 = 
    let Error(_, s1) = e1 in
    let Error(_, s2) = e2 in
    if s1 < s2 then -1
    else
        if s1 = s2 then 0
        else 1

def sort_by_pos(errors): 
    List.sort cmp_by_pos errors 

def sort_and_cut(errors): 
    errors = sort_by_pos(errors)
    errors = List.stable_sort(cmp_by_str errors)
    errors = Common.unique(cmp_by_str errors)
    errors = sort_by_pos(errors)
    errors

def pos_id_call(call): 
    pos = get_meta(call)
    tagid = call_id (unwrap call)
    (pos, id)

def collect_calls_in_func(func): 
    (_, _, FunBody_prime_stmts) = func.param() 
    calls = collect_calls_wr(FunBody_prime_stmts)
    return calls

def verify_calls(f_ids, func): 
    calls = collect_calls_in_func(func)
    def f(call): 
        let (pos, id) = pos_id_call(call) in
        let s = Printf.sprint "No such function: %s" tagid in
        (pos, s)

    def g(call): call_id (unwrap call) in
    bad_calls = fancy_filter(id g f_ids calls)
    erf = make_error_fun(f)
    erf bad_calls

#(* id_count = [(f_id, f_param_count); ...] *)
def verify_calls_params(id_count, func): 
    def call_arg_count(call): 
        match call with
        elif type() == Call(tagid, ExpArgs(l)):
         len( l)
        elif type() == _:
         assert False

    calls = collect_calls_in_func(func)
    def f(call): 
        let (pos, id) = pos_id_call(call) in
        c_count = call_arg_count (unwrap call)
        let (_, f_count) = List.find (fun (f_id, _) -> f_id = id) id_count in
        let s = Printf.sprint "Function \"%s\" takes %d params, not %d" tagid f_count c_count in
        (pos, s)

    def g(call): 
        call = (unwrap call)
        tagid = call_id(call)
        c_count = call_arg_count(call)
        (tagid, c_count)

    def g_id(call): call_id (unwrap call) in
    let defined_calls = fancy_filter' fst g_id id_count calls in
    bad = fancy_filter(id g id_count defined_calls)
    erf = make_error_fun(f)
    erf bad

def cmp_func_by_pos(f1, f2): 
    m1 = get_meta(f1)
    m2 = get_meta(f2)
    m1.lnum - m2.lnum

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
    f_list = List.sort(cmp_func_by_pos f_list)
    f_list = List.sort(cmp_func_by_id f_list)
    def f(func): 
        pos = get_meta(func)
        let tagid = fun_id_prime (unwrap func) in 
        let first = List.find (fun f -> fun_id_prime (unwrap f) = id) f_list in
        let lnum = let m = get_meta first in m.lnum in 
        let s = Printf.sprint "Function %s already defined @ %d" tagid lnum in
        (pos, s)

    let bad = Common.nonunique cmp_func_by_id f_list in 
    erf = make_error_fun(f)
    erf bad

def cmp_by_meta(n1, n2): 
    return n1.m.lnum - n2.m.lnum

def arg_len(func):
    func = unwrap(func)
    (_, Args_args, _) = func.param()
    args = Args_args.param()
    return len(args)

#(* exactly one "main" without params *)
def verify_main_func(f_list): 
    let mains = List.filter (fun x -> fun_id_prime (unwrap x) = "main") f_list in
    if len( mains) = 0 then
        let s = "There must be exactly one \"main\" function (with no params)" in
        let error = Error({lnum=0}, s) in
        [error]
    else
        #(* we don't care about dupes, since verify_funs will take care of that *)
        mains = List.sort(cmp_by_meta mains)
        let bad = List.filter (fun x-> arg_len x > 0) mains in
        def f(func):
            pos = get_meta(func)
            let s = Printf.sprint "\"main\" can't have parameters (this one has %d)" (arg_len func) in
            (pos, s)

        erf = make_error_fun(f)
        erf bad

def verify_prog(p): 
    (f_list) = p.param()
    f_id_count = map (lambda f: (fun_id_prime( (unwrap (f)), arg_len, f)))), f_list) 
    f_ids = map(fst, f_id_count) 
    def f(acc, func): 
        func = unwrap(func)
        err1 = verify_jumps_in_func(func)
        err2 = verify_vars_in_func(func)
        err3 = verify_calls(f_ids func)
        err4 = verify_calls_params(f_id_count, func)
        err = err1 + err2 + err3 + err4
        err = sort_and_cut(err)
        return [err :: acc]

    fold_left = f ([], f_list)
    errors =  fold_left[-1]
    errors = List.concat(errors)
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
            let tmp = "tmp" ^ string_of_int n in
            eid = Var(tmp)
            eid, tmp

    def wrap(e, l n): 
        match e with
        if type(e) == Const:
            return e,l,n
        elif type(e) == Var:
            return e,l,n
        elif type() == Ref:
            return e,l,n
        else:
            e_prime, tmp = (new_tmp(n)).param()
            e = e_prime.param()
            assign = Assign(tmp, e)
            return e_prime, [assign, l] ,n+1

    let e', l, n = flatten_exp(exp n) in
    let e', l, n = wrap e' l n in
    e', l, n
and
flatten_exp exp n =
    match exp with
    elif type() == Const x:
     exp, [], n
    elif type() == Var x:
     exp, [], n
    elif type() == Ref x:
     exp, [], n
    elif type() == ReadMem(id):
     exp, [], n
    elif type() == UnOp(op,e):
     
        let e', l, n = wrap_flatten_exp(e n) in
        UnOp(op,e'), l, n
        
    elif type() == BinOp(e1, op, e2):
    
        let e1', l1, n = wrap_flatten_exp(e1 n) in
        let e2', l2, n = wrap_flatten_exp(e2 n) in
        let l = l1 @ l2 in
        BinOp(e1',op, e2'), l, n

def flatten_stmt(s, n): 
    def handle_call(tagid, el, n):
        def f ((ids, ll, n) e):
            v,l_prime,n = wrap_flatten_exp(e, n).param()
            (v::ids, l_prime::ll, n)

        (ids, ll, n) = List.fold_left f ([], [], n) el in
        l = List.concat(ll)
        ids = ids.reverse() 
        return ids, l, n

    match s with 
    elif type() == DerefAssign(tagid, e):
     
        let e', l, n = flatten_exp(e n) in
        DerefAssign(tagid,e') :: l, n
    elif type() == Assign(tagid, e):
     
        let e', l, n = flatten_exp(e n) in
        Assign(tagid,e') :: l, n
    elif type() == WriteMem(tagid, e):
    
        let e', l, n = flatten_exp(e n) in
        WriteMem(tagid,e') :: l, n
    elif type() == Cmp(e1, e2):
    
        let v1, l1, n = wrap_flatten_exp(e1 n) in
        let v2, l2, n = wrap_flatten_exp(e2 n) in
        let l = l1 @ l2 in
        Cmp(v1, v2) :: l, n
    elif type() == Call(tagid, ExpArgs(el)):
     
        let ids, l, n = handle_call(id el n) in
        let c = Call(tagid, ExpArgs(ids)) in
        c::l, n
    elif type() == ExtCall(tagid, ExpArgs(el)):
    
        let ids, l, n = handle_call(id el n) in
        let c = ExtCall(tagid, ExpArgs(ids)) in
        c::l, n
    elif type() == _:
    [s], n

def flatten_fun_body(fb): 
    def f( (ll, n), stmt):
        l, n = flatten_stmt(stmt, n)
        (l::ll, n)

    stmts = None
    if type(fb) == FunBody:
        stmts = fb.param()
        
    ll = map(f ([], 0), stmts)
    ll = ll[::-1]
    l.append(ll)
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
