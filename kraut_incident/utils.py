# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

def slicedict(d, s):
    return {k:v for k,v in d.iteritems() if k.startswith(s)}
