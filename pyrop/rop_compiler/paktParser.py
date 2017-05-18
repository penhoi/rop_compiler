
# Parsing rules
from paktLexer import *
from paktAst import *

#(* get meta / save meta *)
def wrap(node, pos):
    m = meta(pos)
    return type_wrapped(node, m)

def only_small(l):
    return not any(map((lambda x: x>255), l))

def unescape(s):
    #Scanf.sscanf("\"" ^ s ^ "\"") "%S" (fun u -> u)
    return "\"" + s + "\"" 

def explode(s):
    return list(s) + ['\x00']

def str_to_byte_list(s):
    s = unescape(s)
    l = explode(s)
    l = map((lambda c: ord(c)), l)
    return l

def assign_tab(tagid, l):
    if only_small(l):
        s = AssignTab(tagid, l)
        return s
    else:
        raise Exception("Only byte values(0-255) allowed in tabs")

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
        p[1].reverse()
        p[0] = Prog_prime(p[1])

    if p[0] is None:
        print "Bug in Rule: input" 
        
def p_func_list(p):
    '''func_list : func_list func
                 | func'''

    toks = p.slice
    if len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 3:
        p[0] = [p[2]] + p[1]
    
    if p[0] is None:
        print "Bug in Rule: func_list" 

def p_func(p):
    '''func : FUN ID args func_body'''

    f = Fun_prime(p[2], p[3], p[4])
    p[0] = wrap(f, p.slice[1].lineno)

    if p[0] is None:
        print "Bug in Rule: func" 
        
def p_func_body(p):
    '''func_body : LCURLY stmt_list RCURLY'''

    p[2].reverse()
    p[0] = FunBody_prime(p[2])
    
    if p[0] is None:
        print "Bug in Rule: func_body" 
        
def p_args(p):
    '''args : LPAREN args_list RPAREN'''
    p[2].reverse()
    p[0] = Args(p[2])
    
    if p[0] is None:
        print "Bug in Rule: args" 

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

    if p[0] is None:
        print "Bug in Rule: args_list" 
        
def p_stmt_list(p):
    '''stmt_list    : stmt_list stmt
                    | stmt'''
    toks = p.slice
    if len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 3:
        p[0] = [p[2]] + p[1]
    
    if p[0] is None:
        print "Bug in Rule: stmt_list" 

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
        """LABEL"""
        if toks[1].type == "LABEL":
            s = Label(p[1])
            p[0] = wrap(s, p.slice[1].lineno)
    #end len(toks) == 2:

    elif len(toks) == 3: #{
        """BRANCH ID
        ID exp_args"""
        if toks[1].type == "BRANCH":
            cond = str_to_cond(p[1])
            s = Branch(cond, p[2])
            p[0] = wrap(s, p.slice[1].lineno)
        elif toks[1].type == "ID":
            s = Call(p[1], p[2])
            p[0] = wrap(s, p.slice[1].lineno)
    #end len(toks) == 3

    elif len(toks) == 4:
        """ID ASSIGN STR
        ID ASSIGN exp
        BANG ID exp_args
        """
        if toks[1].type == "BANG":
            s = ExtCall(p[2], p[3])
            p[0] = wrap(s, p.slice[1].lineno)
        elif toks[1].type == "ID":
            if toks[3] and toks[3].type == "STR":
                l = str_to_byte_list(p[3])
                s = assign_tab(p[1], l)
                p[0] = wrap(s, p.slice[1].lineno)
            else:
                s = Assign(p[1], p[3])
                p[0] = wrap(s, p.slice[1].lineno)
    #end len(toks) == 4
            
    elif len(toks) == 5:
        """DOLLAR ID ASSIGN exp
        CMP exp COMMA exp"""
        if toks[1].type == "DOLLAR":
            s = DerefAssign(p[2], p[4])
            p[0] = wrap(s, p.slice[1].lineno)
        elif toks[1].type == "CMP":
            s = Cmp(p[2], p[4])
            p[0] = wrap(s, p.slice[1].lineno)   
    #end len(toks) == 5
      
    elif len(toks) == 6:
        """ID ASSIGN LBRACKET num_list RBRACKET
        LBRACKET ID RBRACKET ASSIGN exp"""
        if toks[1].type == "ID":
            p[4].reverse()
            s = assign_tab(p[1], p[4])
            p[0] = wrap(s, p.slice[1].lineno)
        elif toks[1].type == "LBRACKET":
            s = WriteMem(p[2], p[5])
            p[0] = wrap(s, p.slice[1].lineno)
    #end len(toks) == 6
    
    if p[0] is None:
        print "Bug in Rule: stmt" 

def p_num_list(p):
    '''num_list : num_list COMMA NUM
                | NUM'''

    toks = p.slice
    if len(toks) == 2: p[0] = [p[1]]
    elif len(toks) == 4: p[0] = [p[3]] + p[1]
    
    if p[0] is None:
        print "Bug in Rule: num_list"

def p_exp_args(p):
    '''exp_args : LPAREN exp_args_list RPAREN'''

    p[2].reverse()
    p[0] = ExpArgs(p[2])
    
    if p[0] is None:
        print "Bug in Rule: exp_args"

def p_exp_args_list(p):
    '''exp_args_list    : exp_args_list COMMA exp
                        | exp
                        | '''
    toks = p.slice
    if len(toks) == 1:
        p[0] = []
    elif len(toks) == 2:
        p[0] = [p[1]]
    elif len(toks) == 4:
        p[0] = [p[3]] + p[1]
        
    if p[0] is None:
        print "Bug in Rule: exp_args_list"

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
        """NUM
        ID"""
        if toks[1].type == "NUM": p[0] = Const(p[1])
        elif toks[1].type == "ID": p[0] = Var(p[1])
        
    elif len(toks) == 3:
        """AT ID
        NOT exp
        MINUS exp"""
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
    
    if p[0] is None:
        print "Bug in Rule: exp"


def p_error(t):
    if t is None:
        print "None type!"
    else:
        print "Syntax error: line %d, cols %d, value '%s'" % (t.lineno, t.lexpos, t.value)

import ply.yacc as yacc
parser = yacc.yacc()

def debug_parser(ropl_file):
    f = open(ropl_file)
    if f is None:
        print "Failed to open file %s" % ropl_file
        sys.exit()
    
    data  = f.read()
    print data

    def deep_traversal(x):
        if x is None:
            return
        
        if type(x) == type:
            print x
            return
        
        if type(x) == type_wrapped:
            x = unwrap(x)
            print x
            
        if hasattr(x, "param"):
            x = x.param()
            if x is None:
                return
        #end if hasattr    
    
        if type(x) in [int, str]:
            print x
            return
    
        elif type(x) in [list, tuple] and (len(x) == 0):
            return
        
        if type(x) not in [list, tuple, map]:
            deep_traversal(x)
            return 
        
        for p in x:
            if type(p) == int:
                print p
            else:
                deep_traversal(p)

    # Give the lexer some input
    p = parser.parse(data)
    deep_traversal(p)
    
if __name__ == '__main__':
    import sys
    if len(sys.argv) == 2:
        fropl =  sys.argv[1]
        debug_parser(fropl)
    else:
        print "Usage:\n  %s <ropl file>" % sys.argv[0]
