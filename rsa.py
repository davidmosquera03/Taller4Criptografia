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
    
    def CorruptIrsa_a(self, sk, y):
        """
        Corrupcion de resultado intermedio
        Invierte bit de xp
        """
        (p, q, dp, dq, qinv) = sk
        xp = pow(y,dp,p)

        # Cambiar bit
        xp_corrupto = xp ^ (1 << 0)
        xq = pow(y,dq,q)

        xpp = (qinv*(xp_corrupto-xq))%p
        x_hat = xq+xpp*q
        return x_hat
    
    def CorruptIrsa_b(self, sk, y):
        """
        Corrupcion de entrada
        Invierte bit de y
        """
        y_corrupto = y ^ (1 << 0)
        (p, q, dp, dq, qinv) = sk
        xp = pow(y_corrupto,dp,p)
        xq = pow(y_corrupto,dq,q)

         # aplicacion CRT
        xpp = (qinv*(xp-xq))%p
        x_hat = xq+xpp*q
        return x_hat
    
    def CorruptIrsa_c(self, sk, y):
        """
        Corrupcion de exponente
        """
        return
    
    def CorruptIrsa_d(self, sk, y):
        """
        Corrupcion de qinv
        """
        return
    
