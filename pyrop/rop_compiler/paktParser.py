tokens = (
    'NUM', 'PLUS', 'MINUS', 'MUL', 'DIV', 'AND', 'OR', 'NOT', 'XOR', 'ASSIGN',
    'LPAREN', 'RPAREN', 'LBRACKET', 'RBRACKET', 'LCURLY', 'RCURLY', 'COMMA',
    'ID',  'LABEL', 'BRANCH', 'STR', 'EOF',
    'DOLLAR', 'AT', 'BANG',
    'FUN', 'CMP',
    )

KEYWORDS = {'fun':"FUN", 'cmp':"CMP"}

# Tokens

t_PLUS      = r'\+'
t_MINUS     = r'-'
t_MUL       = r'\*'
t_DIV       = r'/'
t_AND       = r'&'
t_OR        = r'\|'
t_NOT       = r'~'
t_XOR       = r'\^'
t_ASSIGN    = r'='

t_LPAREN    = r'\('
t_RPAREN    = r'\)'
t_LBRACKET  = r'\['
t_RBRACKET  = r'\]'
t_LCURLY    = r'\{'
t_RCURLY    = r'\}'
t_COMMA     = r','
t_DOLLAR    = r'\$'
t_AT        = r'@'
t_BANG      = r'!'

def t_INUM(t):
    r'\d+'

    try:
        num = int(t.value, 10)
    except ValueError:
        print("Integer value too large %d", t.value)
        num = 0
    t.type = "NUM"
    t.value = num
    return t

def t_HNUM(t):
    r'0x[0-9afAF]+'

    try:
        num = int(t.value, 16)
    except ValueError:
        print("Integer value too large %d", t.value)
        num = 0
    t.type = "NUM"
    t.value = num
    return t

def t_STR(t):
    r'"[^"]*"'

    t.value = t.value[1:-1]
    return t

def t_COMMENT(t):
    r'\#[^\n]*'
    t.value = t.value[1:]
    print "comment:", t.value

def t_ID(t):
    r'[a-zA-Z][a-zA-Z0-9_]*[:]?'

    if t.value in KEYWORDS:
        t.type = KEYWORDS[t.value]
    elif t.value[-1] == ":":
        t.type = "LABEL"
        t.value = t.value[:-1]
    elif t.value[0] == "j":
        t.type = "BRANCH"
        t.value = t.value[1:]
    elif t.value == "eof":
        t.type = "EOF"
    return t


t_ignore = " \t"

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

# Build the lexer
import ply.lex as lex
lexer = lex.lex()

def debug_lexor(ropl_file):

    lines = None
    with open(ropl_file) as f:
        lines = f.readlines()

    for line in lines:

        # Give the lexer some input
        lexer.input(line)

        print line
        # Tokenize
        while True:
            tok = lexer.token()
            if not tok: break      # No more input
            print tok

            # Get the token map from the lexer.  This is required.


# Parsing rules
from paktAst import *

precedence = (
    ('left','PLUS','MINUS'),
    ('left','MUL','DIV', 'AND', 'OR', 'XOR'),
    ('right', 'NOT')
    )

# dictionary of names
names = { }

def p_expression(p):
    '''exp  : NUM
            | ID
            | AT ID
            | ASSIGN
            | exp PLUS exp
            | exp MINUS exp
            | exp MUL exp
            | exp DIV exp
            | exp AND exp
            | exp OR exp
            | exp XOR exp
            | LBRACKET ID RBRACKET
            | NOT exp
            | MINUS exp
            | LPAREN exp RPAREN'''

    print p.slice
    if len(p) == 1+1:
        if type(p[1]) == int:   p[0] = Const(p[1])
        elif type(p[1]) == str: p[0] = Var(p[1])
    elif len(p) == 2+1:
        if p[1] == '@': p[0] = Ref[p[2]]
        elif p[1] == '!': p[0] =  UnOp(Not, p[2])
        elif p[1] == '-': p[0] =  UnOp(Sub, p[2])
    elif len(p) == 3+1:
        if p[2] == '+'  : p[0] = BinOp(p[1], Add, p[3])
        elif p[2] == '-': p[0] = BinOp(p[1], Sub, p[3])
        elif p[2] == '*': p[0] = BinOp(p[1], Mul, p[3])
        elif p[2] == '/': p[0] = BinOp(p[1], Div, p[3])
        elif p[2] == '&': p[0] = BinOp(p[1], And, p[3])
        elif p[2] == '|': p[0] = BinOp(p[1], Or, p[3])
        elif p[2] == '^': p[0] = BinOp(p[1], Xor, p[3])
        elif p[1] == '[': p[0] = ReadMem(p[2])
        elif p[1] == '(': p[0] = p[2]


def p_num_list(p):
    '''num_list : num_list COMMA NUM
                | NUM'''

    if len(p) == 1+1:
        p[0] = [p[1]]
    elif len(p) > 2:
        p[0] = p[0].append(p[3])

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

    if len(p) == 1:
        pass
    elif len(p) == 2:
        pass

def p_stmt_list(p):
    '''stmt_list    : stmt_list COMMA NUM
                    | stmt'''
    pass

def p_args_list(p):
    '''args_list    : args_list COMMA ID
                    | ID'''
    pass

def p_exp_args_list(p):
    '''exp_args_list    : exp_args_list COMMA exp
                        | exp'''
    pass


def p_args(p):
    '''args : LPAREN args_list RPAREN'''
    pass

def p_exp_args(p):
    '''exp_args : LPAREN exp_args_list RPAREN'''
    pass

def p_func_body(p):
    '''func_body : LCURLY stmt_list RCURLY'''
    pass

def p_func(p):
    '''func : FUN ID args func_body'''
    pass

def p_func_list(p):
    '''func_list : func_list func
                 | func'''
    pass

def p_input(p):
    '''input    : EOF
                | func_list'''
    pass

def p_error(p):
    print("Syntax error at '%s'" % p.value)

import ply.yacc as yacc
parser = yacc.yacc()


while True:
    try:
        s = raw_input('ropl > ')   # Use raw_input on Python 2
    except EOFError:
        break

    lexer.input(s)
    while True:
        tok = lexer.token()
        if not tok: break      # No more input
        print tok

    parser.parse(s)

