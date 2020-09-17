import copy

class LintDict(dict):
    def __init__(self,*args,**kwargs):
        dict.__init__(self,*args,**kwargs) 

    def __getitem__(self, key):
        if key in self:
            return super().__getitem__(key)
        return copy.deepcopy([])
