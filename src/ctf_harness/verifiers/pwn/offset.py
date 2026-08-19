def cyclic(length:int,alphabet:bytes=b"abcdefghijklmnopqrstuvwxyz")->bytes:
    if length<0:raise ValueError("length must be non-negative")
    out=bytearray()
    for a in alphabet:
        for b in alphabet.upper():
            for c in b"0123456789":
                out+=bytes((a,b,c))
                if len(out)>=length:return bytes(out[:length])
    if length>len(out):raise ValueError("requested pattern exceeds generator capacity")
    return bytes(out[:length])
def recover_offset(observed:bytes,*,pattern_length:int=8192)->int|None:
    if not observed:return None
    pattern=cyclic(pattern_length); pos=pattern.find(observed); return pos if pos>=0 else None
