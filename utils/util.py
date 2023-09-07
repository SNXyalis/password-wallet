class Blacklist(set):

    def is_blacklisted(self,jti):
        return jti in self
    
    def add_jti(self, jti):
        self.add(jti)

blacklist = Blacklist()