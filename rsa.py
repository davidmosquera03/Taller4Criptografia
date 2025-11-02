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

        print('q:=',q)


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
        print('\nxp_corrupto=',xp_corrupto)
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

        print('\ny_corrupto=',y_corrupto)

        (p, q, dp, dq, qinv) = sk
        xp = pow(y_corrupto,dp,p)
        xq = pow(y_corrupto,dq,q)

         # aplicacion CRT
        xpp = (qinv*(xp-xq))%p
        x_hat = xq+xpp*q
        return x_hat
    
    def CorruptIrsa_c(self, sk, y):
        """
        Implementa obtencion de mensaje plano
        aplicando el teorema del resto chino
        """
        (p, q, dp, dq, qinv) = sk

        #modificacion de dp
        dp_corrupto = dp ^ (1 << 0)
        print('\ndp_corrupto=',dp_corrupto)
        xp = pow(y,dp_corrupto,p)
        xq = pow(y,dq,q)

         # aplicacion CRT
        xpp = (qinv*(xp-xq))%p
        x_hat = xq+xpp*q
        return x_hat
    
    def CorruptIrsa_d(self, sk, y):
        """
        Corrupcion de qinv
        """
        (p, q, dp, dq, qinv) = sk
        xp = pow(y,dp,p)
        xq = pow(y,dq,q)
        #modificacion de qinv
        qinv_corrupto = qinv ^ (1 << 0)
        print('\nqinv_corrupto=',qinv_corrupto)
         # aplicacion CRT
        xpp = (qinv_corrupto*(xp-xq))%p
        x_hat = xq+xpp*q
        return x_hat

def ataque_rsa(sk, pk, y, e):
        """
        Implementa ataque para recuperar factor de n
        """
        rsa = ModifiedRSA()
        print('Que tipo de corrupcion se realizo?')
        print('\na) Corrupcion de xp')
        print('\nb) Corrupcion de y')
        print('\nc) Corrupcion de dp')
        print('\nd) Corrupcion de qinv')
        tipo = input('Ingrese el tipo de corrupcion: ')

        while tipo not in ['a','b','c','d']:
            print('Tipo invalido. Intente de nuevo.')
            tipo = input('Ingrese el tipo de corrupcion (a/b/c/d): ')
        if tipo == 'a':
            print('\nTipo de fallo: corrupcion de xp')

            x_hat = rsa.CorruptIrsa_a(sk, y)
        elif tipo == 'b':
            print('\nTipo de fallo: corrupcion de y')
            x_hat = rsa.CorruptIrsa_b(sk, y)
        elif tipo == 'c':
            print('\nTipo de fallo: corrupcion de dp')
            x_hat = rsa.CorruptIrsa_c(sk, y)
        else:
            print('\nTipo de fallo: corrupcion de qinv')
            x_hat = rsa.CorruptIrsa_d(sk, y)

        (n, e) = pk
        print('\nx_hat=', x_hat)
        x_he = pow(x_hat, e, n)

        print('\nContramedida')
        if x_he == y: 
            print('\nx^e == y, X no esta corrupto')
        else:
            print('\nx^e != y, X esta corrupto')

        r = x_he - y

        g = number.GCD(r, n)

        p = n // g       
        print('\nFactor encontrado g=', g)
        print('\nOtro factor p=', p)
        return g




rsa=ModifiedRSA()
e=65537
l=1024
# Genera las llaves privada y pública utilizando el método Grsa
sk, pk=rsa.Grsa(l, e)
# Simular el ataque
print('\n--- Simulacion de ataque ---')
x = 8
print('\nMensaje original x=', x)
y = rsa.Frsa(pk, x)
print('\nMensaje cifrado y=', y)

print('\nRecuperando factor de n...')

g = ataque_rsa(sk, pk, y, e)

print('\n--- Fin de simulacion ---')
