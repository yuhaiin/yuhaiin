package native

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "testing"
    "time"
)

func TestClientCertificateChallenge(t *testing.T) {
    key,err:=rsa.GenerateKey(rand.Reader,2048)
    if err!=nil{t.Fatal(err)}
    crt:=&x509.Certificate{
        SerialNumber:big.NewInt(1),
        Subject:pkix.Name{CommonName:"SoftEther Client"},
        NotBefore:time.Now().Add(-time.Minute),
        NotAfter:time.Now().Add(time.Hour),
        KeyUsage:x509.KeyUsageDigitalSignature,
    }
    der,err:=x509.CreateCertificate(rand.Reader,crt,crt,&key.PublicKey,key)
    if err!=nil{t.Fatal(err)}
    private:=x509.MarshalPKCS1PrivateKey(key)
    cp:=string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}))
    kp:=string(pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY",Bytes:private}))
    challenge:=make([]byte,20)
    if _,err:=rand.Read(challenge);err!=nil{t.Fatal(err)}
    cert,sign,err:=signClientChallenge(cp,kp,challenge)
    if err!=nil{t.Fatal(err)}
    if string(cert)!=string(der){t.Fatal("unexpected certificate DER")}
    hashed:=sha1.Sum(challenge)
    if err:=rsa.VerifyPKCS1v15(&key.PublicKey,crypto.SHA1,hashed[:],sign);err!=nil{t.Fatal(err)}
    if _,_,err:=signClientChallenge(cp,kp,challenge[:19]);err==nil{t.Fatal("accepted short server challenge")}
    other,err:=rsa.GenerateKey(rand.Reader,2048)
    if err!=nil{t.Fatal(err)}
    wrongKey:=string(pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY",Bytes:x509.MarshalPKCS1PrivateKey(other)}))
    if _,_,err:=signClientChallenge(cp,wrongKey,challenge);err==nil{t.Fatal("accepted mismatched certificate key")}
}
