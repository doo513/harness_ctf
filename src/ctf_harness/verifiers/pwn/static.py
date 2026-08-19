class StaticPwnVerifier:
    FIELDS={"ctf.pwn.arch":"architecture","ctf.pwn.bits":"bits","ctf.pwn.endianness":"endianness","ctf.pwn.nx":"nx","ctf.pwn.pie":"pie"}
    def verify(self,key,expected,snapshot):
        field=self.FIELDS.get(key)
        if field is None:return False,"unsupported static Pwn claim"
        actual=getattr(snapshot,field)
        if actual is None:return False,f"deterministic recon {field} is inconclusive"
        return actual==expected,f"deterministic recon {field}={actual!r}"
