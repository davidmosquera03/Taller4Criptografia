from Crypto.Util import number

class RSA:
    """
    Implementa RSA original
    """
    def Grsa(self, l, e):
        """
        Genera las llave privada sk
        y la publica pk

        Input
        l: longitud
        e: impar de entrada
        """
        p = number.getPrime(l)
        while number.GCD(p-1, e) != 1:
            p = number.getPrime(l)
        
        q = number.getPrime(l)
        while number.GCD(q-1, e) != 1 or p == q:
            q = number.getPrime(l)
        
        phi = (p-1) * (q-1)
        d = number.inverse(e, phi)
        n = p * q
        
        pk = (n, e)
        sk = (n, d)
        return sk, pk

    def Frsa(self, pk, x):
        """
        Implementa obtencion de mensaje cifrado
        """
        (n, e) = pk
        return pow(x, e, n)
    
    def Irsa(self, sk, y):
        """
        Implementa obtencion de mensaje plano
        """
        (n, d) = sk
        return pow(y, d, n)


class ModifiedRSA:
    """
    Implementa RSA alterado
    """
    def Grsa(self, l, e):
        """
        Genera las llave privada sk
        y la publica pk

        Input
        l: longitud
        e: impar de entrada
        """
        p = number.getPrime(l)
        while number.GCD(p-1, e) != 1:
            p = number.getPrime(l)
        
        q = number.getPrime(l)
        while number.GCD(q-1, e) != 1 or p == q:
            q = number.getPrime(l)
        
        phi = (p-1) * (q-1)
        d = number.inverse(e, phi)
        n = p * q
        
        # alteraciones
        dp = d % (p-1) 
        dq = d % (q-1)
        qinv = number.inverse(q, p)

        pk = (n, e)
        #sk = (n, d) original

        sk = (p, q, dp, dq, qinv)
        return sk, pk

    def Frsa(self, pk, x):
        """
        Implementa obtencion de mensaje cifrado
        """
        (n, e) = pk
        return pow(x, e, n)
    
    def IrsaCrt(self, sk, y):
        """
        Implementa obtencion de mensaje plano
        aplicando el teorema del resto chino
        """
        (p, q, dp, dq, qinv) = sk
        xp = pow(y,dp,p)
        xq = pow(y,dq,q)

         # aplicacion CRT
        xpp = (qinv*(xp-xq))%p
        x = xq+xpp*q
        return x
