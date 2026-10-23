import shlex
BS=chr(92)
def words2(command, depth=0):
    if depth>4: return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split=True; lex.commenters=""
        tokens=list(lex)
    except ValueError:
        tokens=command.split()
    out=[]
    for t_ in tokens:
        if not t_: continue
        cleaned=t_.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ")
        out.extend(cleaned.split())
        if any(c.isspace() for c in t_) or "`" in t_ or "$(" in t_:
            out.extend(words2(t_, depth+1))
    return out
