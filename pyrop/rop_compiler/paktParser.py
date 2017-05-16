
# Parsing rules
from paktLexer import *
from paktAst import *

#(* get meta / save meta *)
def get_meta(tok):
    #lnum = p.pos_lnum
    lnum= 0
    return meta(lnum)

def wrap(node):
    meta = get_meta(1)
    return type_wrapped(node, meta)

def only_small(l):
    return any(map((lambda x: x>255), l))

def unescape(s):
    #Scanf.sscanf ("\"" ^ s ^ "\"") "%S" (fun u -> u)
    pass

def explode(s):
    def exp(i, l):
        if i < 0:
            return l
        else:
            exp(i - 1, [s[i]] + l)
    exp(len(s) -1, ['\x00'])

def str_to_byte_list(s):
    s = unescape(s)
    l = explode(s)
    l = map((lambda c: int(c)), l)
    return l

def assign_tab(id, l):
    if only_small(l):
        s = AssignTab(id, l)
        return s
    else:
        raise Exception("Only byte values (0-255) allowed in tabs")

precedence = (
    ('left','PLUS','MINUS'),
    ('left','MUL','DIV', 'AND', 'OR', 'XOR'),
    ('right', 'NOT', 'UMINUS')
    )

# dictionary of names
names = { }

def p_input(p):
    '''input    : EOF
                | func_list'''

    toks = p.slice
    if toks[1].type == "EOF":
        p[0] = Prog_prime([])
    else:
        p[0] = Prog_prime(p[1].reverse())

def p_func_list(p):
    '''func_list : func_list func
                 | func'''

    toks = p.slice
    if len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 3:
        p[0] = [p[2]] + p[1]

def p_func(p):
    '''func : FUN ID args func_body'''

    f = Fun_prime(p[2], p[3], p[4])
    p[0] = wrap(f)

def p_func_body(p):
    '''func_body : LCURLY stmt_list RCURLY'''

    p[0] = FunBody_prime(p[2].reverse())

def p_args(p):
    '''args : LPAREN args_list RPAREN'''

    p[0] = Args(p[2].reverse())

def p_args_list(p):
    '''args_list    : args_list COMMA ID
                    | ID
                    | '''

    toks = p.slice
    if len(toks) == 1:
        p[0] = []
    elif len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 4:
        p[0] = [p[3]] + p[1]
    print toks
    print p[0]

def p_stmt_list(p):
    '''stmt_list    : stmt_list stmt
                    | stmt'''
    toks = p.slice
    if len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 3:
        p[0] = [p[2]] + p[1]

def p_statement(p):
    '''stmt : ID ASSIGN STR
            | ID ASSIGN LBRACKET num_list RBRACKET
            | ID ASSIGN exp
            | DOLLAR ID ASSIGN exp
            | LABEL
            | BRANCH ID
            | CMP exp COMMA exp
            | LBRACKET ID RBRACKET ASSIGN exp
            | ID exp_args
            | BANG ID exp_args'''

    toks = p.slice
    if len(toks) == 2: #{
        if toks[1].type == "LABEL":
            s = Label(p[1])
            p[0] = wrap(s)
    #end len(toks) == 2:

    elif len(toks) == 3: #{
        if toks[1].type == "BRANCH":
            cond = str_to_cond(p[1])
            s = Branch(cond, p[2])
            p[0] = wrap(s)
        elif toks[1].type == "ID":
            s = Call(p[1], p[2])
            p[0] = wrap(s)
    #end len(toks) == 3

    elif len(toks) == 4:
        if toks[1].type == "BANG":
            s = ExtCall(p[2], p[3])
            p[0] = wrap(s)
        elif toks[1].type == "ID":
            pass
            s = Call(p[1], p[2])
            p[0] = wrap(s)

        print p.slice
    else:
        print p.slice

def p_num_list(p):
    '''num_list : num_list COMMA NUM
                | NUM'''

    toks = p.slice
    if len(toks) == 2: p[0] = [p[1]]
    elif len(toks) == 4: p[0] = [p[3]] + p[1]

def p_exp_args(p):
    '''exp_args : LPAREN exp_args_list RPAREN'''

    s = p[2].reverse()
    p[0] = ExpArgs(s)


def p_exp_args_list(p):
    '''exp_args_list    : exp_args_list COMMA exp
                        | exp
                        | '''
    toks = p.slice
    if len(toks) == 1:
        p[0] = []
    elif len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 3:
        p[0] = p[3] + p[1]

def p_expression(p):
    '''exp  : NUM
            | ID
            | AT ID
            | exp PLUS exp
            | exp MINUS exp
            | exp MUL exp
            | exp DIV exp
            | exp AND exp
            | exp OR exp
            | exp XOR exp
            | LBRACKET ID RBRACKET
            | NOT exp
            | MINUS exp    %prec UMINUS
            | LPAREN exp RPAREN'''

    toks = p.slice
    if len(toks) == 2:
        if toks[1].type == "NUM": p[0] = Const(p[1])
        elif toks[1].type == "ID": p[0] = Var(p[1])
    elif len(toks) == 3:
        if toks[1].type == "AT": p[0] = Ref(p[2])
        elif toks[1].type == "NOT": p[0] = UnOp(Not, p[2])
        elif toks[1].type == "MINUS": p[0] = UnOp(Sub, p[2])
    elif len(toks) == 4:
        if p[2] == '+'  : p[0] = BinOp(p[1], Add, p[3])
        elif p[2] == '-': p[0] = BinOp(p[1], Sub, p[3])
        elif p[2] == '*': p[0] = BinOp(p[1], Mul, p[3])
        elif p[2] == '/': p[0] = BinOp(p[1], Div, p[3])
        elif p[2] == '&': p[0] = BinOp(p[1], And, p[3])
        elif p[2] == '|': p[0] = BinOp(p[1], Or, p[3])
        elif p[2] == '^': p[0] = BinOp(p[1], Xor, p[3])
        elif p[1] == '[': p[0] = ReadMem(p[2])
        elif p[1] == '(': p[0] = p[2]
    else:
        print "Bug in Rule: exp"


def p_error(t):
    if t is None:
        print "None type!"
    else:
        print "Syntax error at '%s'" % t.value

import ply.yacc as yacc
parser = yacc.yacc()


def debug_parser():
    s = "fun fib(n, out){ cmp n, 0}"
    print "\n", s
    parser.parse(s)

    s = "fun fib(n, out){ i = 100 + 10}"
    print "\n", s
    parser.parse(s)

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        debug_parser()


