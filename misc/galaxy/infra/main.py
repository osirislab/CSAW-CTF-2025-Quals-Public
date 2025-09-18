import random

class galaxy_str:
    def __init__(self, s):
        self._s = s
    def __getitem__(self, key):
        if isinstance(key, int) and key >= 0:
            raise Exception("<galaxy hidden>")
        return self._s[key]
    def __str__(self):
        return "<galaxy hidden>"
    __repr__ = __str__

class galaxy_aura:
    def __init__(self):
        self.key = self._gen_key()
        self.map = dict(zip('abcdefghijklmnopqrstuvwxyz\'', self.key))
        self.reverse_map = dict(zip(self.key,'abcdefghijklmnopqrstuvwxyz\''))

    def _gen_key(self):
        letters = [letter for letter in 'abcdefghijklmnopqrstuvwxyz\'']
        random.shuffle(letters)
        key = ''.join(letters)
        return key
    
    def unwarp(self, provided_string):
        characters = [self.reverse_map.get(ch, ch) for ch in provided_string]
        return ''.join(characters)

    def warp(self, provided_string):
        characters = [self.map.get(ch, ch) for ch in provided_string]
        return ''.join(characters)
    
def sanitize(provided_string):
    cleaned_string = ''.join([_ for _ in provided_string if _ in allowed])
    return cleaned_string

if __name__ == "__main__":
    spiral = galaxy_str('csawctf{g@l@xy_0bserv3r$}')
    galaxy_base = galaxy_aura()

    starlight = 100
    allowed = '([<~abcdefghijklmnopqrstuvwxyz>+]/*\')'
    for _ in range(starlight):
        try:
            gathered_input = sanitize(galaxy_base.unwarp(input('> ')))
            if len(gathered_input)>150:
                gathered_input = gathered_input[:150]
            print(eval(gathered_input, {"__builtins__": {}, "spiral": spiral}))
        except Exception as e:
            print('no galaxy')