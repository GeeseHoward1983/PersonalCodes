import gmpy2

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def mod_inverse(a, m):
    """
    Modular multiplicative inverse of a modulo m
    """
    g, x, y = extended_gcd(a % m, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return (x % m + m) % m

def shamir_reconstruct(points, prime):
    """
    Reconstructs the secret using Lagrange interpolation in finite field
    points: list of tuples (x, y) where x is index and y is share
    prime: prime modulus
    """
    k = len(points)
    result = 0
    
    for i in range(k):
        xi, yi = points[i]
        
        numerator = 1
        denominator = 1
        
        for j in range(k):
            if i != j:
                xj, _ = points[j]
                numerator = (numerator * (xj)) % prime
                denominator = (denominator * (xj -xi)) % prime
                
        lagrange_coeff = (numerator * mod_inverse(denominator, prime)) % prime
        result = (result + (yi * lagrange_coeff)) % prime
    
    return int(result % prime)

def main():
    # Prime p from the problem
    p = int("C53094FE8C771AFC900555448D31B56CBE83CBBAE28B45971B5D504D859DBC9E00DF6B935178281B64AF7D4E32D331535F08FC6338748C8447E72763A07F8AF7", 16)
    #p = 1237
    # Shares from organization 1
    org1_shares = [
        (1, int("30A152322E40EEE5933DE433C93827096D9EBF6F4FDADD48A18A8A8EB77B6680FE08B4176D8DCF0B6BF50000B74A8B8D572B253E63473A0916B69878A779946A", 16)),  # Org1 member 1
        (2, int("1B309C79979CBECC08BD8AE40942AFFD17BBAFCAD3EEBA6B4DD652B5606A5B8B35B2C7959FDE49BA38F7BF3C3AC8CB4BAA6CB5C4EDACB7A9BBCCE774745A2EC7", 16)),  # Org1 member 2
        (4, int("1E2B6A6AFA758F331F2684BB75CC898FF501C4FCDD91467138C2F55F47EB4ED347334FAD3D80DB725ABF6546BD09720D5D5F3E7BC1A401C8BD7300C253927BBC", 16))   # Org1 member 4
        #(2, 1942),
        #(4, 3402),
        #(5, 4414)
        #(2, 705),
        #(4, 928),
        #(5, 703)
    ]
    
    # Shares from organization 2
    org2_shares = [
        (3, int("300991151BB6A52AEF598F944B4D43E02A45056FA39A71060C69697660B14E69265E35461D9D0BE4D8DC29E77853FB2391361BEB54A97F8D7A9D8C66AEFDF3DA", 16)),  # Org2 member 3
        (4, int("1AAC52987C69C8A565BF9E426E759EE3455D4773B01C7164952442F13F92621F3EE2F8FE675593AE2FD6022957B0C0584199F02790AAC61D7132F7DB6A8F77B9", 16)),  # Org2 member 4 (assigning index 6 to distinguish from Org1 member 4)
        (5, int("9288657962CCD9647AA6B5C05937EE256108DFCD580EFA310D4348242564C9C90FBD1003FF12F6491B2E67CA8F3CC3BC157E5853E29537E8B9A55C0CF927FE45", 16))   # Org2 member 5
        #(1, 257),
        #(3, 104),
        #(5, 703)
        #,(6, 5614)

    ]
    
    # Reconstruct secrets for each organization
    org1_secret = shamir_reconstruct(org1_shares, p)
    org2_secret = shamir_reconstruct(org2_shares, p)
    
    
    print(f"组织1恢复的秘密: {org1_secret, hex(org1_secret)[2:].upper()}")
    print(f"组织2恢复的秘密: {org2_secret, hex(org2_secret)[2:].upper()}")
    c1=(1,org1_secret)
    c2=(2,org2_secret)
    secrets=[c1,c2]
    secret = shamir_reconstruct(secrets, p)
    print(f"       最终印章: {secret}, {hex(secret)[2:].upper()}")
    # Try to convert to ASCII if possible
    try:
        # Make sure the hex string has even length
        final_hex = hex(secret)[2:]
        if len(final_hex) % 2:
            final_hex = '0' + final_hex
            
        flag = bytes.fromhex(final_hex).decode('ascii', errors='ignore')
        if flag:
            print(f"印章 (ASCII): {flag}")
    except ValueError:
        print("无法解码为ASCII")

if __name__ == "__main__":
    main()