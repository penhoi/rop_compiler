#
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
        t.value = t.value[1:]

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

def debug_lexer(ropl_file):
    f = open(ropl_file)
    if f is None:
        print "Failed to open file %s" % ropl_file
        sys.exit()
    
    data  = f.read()
    print data

    # Give the lexer some input
    lexer.input(data)
    # Tokenize
    while True:
        tok = lexer.token()
        if not tok: break   # No more input
        print tok

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 2:
        fropl =  sys.argv[1]
        debug_lexer(fropl)
    else:
        print "Usage:\n  %s <ropl file>" % sys.argv[0]


