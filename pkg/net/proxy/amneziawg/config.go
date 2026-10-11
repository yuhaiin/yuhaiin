package amneziawg

import (
 "bytes"
 "encoding/base64"
 "encoding/hex"
 "fmt"
 "io"
 "net"
 "net/netip"
 "regexp"
 "strconv"
 "strings"

 contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var customTag=regexp.MustCompile(`<(?:b 0x(?:[a-fA-F0-9]{2})*|r [0-9]+|rd [0-9]+|rc [0-9]+|t)>`)

func parseRange(s string)error{
 if s==""{return nil}
 parts:=strings.Split(s,"-")
 if len(parts)>2{return fmt.Errorf("invalid range %q",s)}
 var min,max uint64
 for i,p:=range parts{
  n,e:=strconv.ParseUint(p,10,32)
  if e!=nil{return fmt.Errorf("invalid range %q",s)}
  if i==0{min=n}else{max=n}
 }
 if len(parts)==2&&min>max{return fmt.Errorf("descending range %q",s)}
 return nil
}

func validateConfig(c contractnode.AmneziaWG)error{
 if len(c.Endpoint)==0||len(c.Peers)==0{return fmt.Errorf("amneziawg: address and peer required")}
 mtu:=c.MTU
 if mtu==0{mtu=1400}
 if mtu<576||mtu>1500{return fmt.Errorf("amneziawg: MTU outside 576..1500")}
 if c.JC>100||c.JMin>1500||c.JMax>1500||c.JC>0&&(c.JMin==0||c.JMax==0||c.JMin>c.JMax) {
  return fmt.Errorf("amneziawg: unsafe junk packet bounds")
 }
 for _,s:=range []uint32{c.S1,c.S2,c.S3,c.S4}{if s>1500{return fmt.Errorf("amneziawg: padding exceeds 1500")}}
 for _,s:=range []string{c.H1,c.H2,c.H3,c.H4,c.ContentPaddingAddition}{
  if err:=parseRange(s);err!=nil{return err}
 }
 for _,s:=range []string{c.I1,c.I2,c.I3,c.I4,c.I5}{
  if len(s)>1024||strings.ContainsAny(s,"\r\n") {return fmt.Errorf("amneziawg: invalid custom packet pattern")}
  remain:=customTag.ReplaceAllString(s,"")
  if remain!=""{return fmt.Errorf("amneziawg: unsupported custom packet tag")}
 }
 if c.HeaderProtectionKey!=""{
  b,e:=hex.DecodeString(c.HeaderProtectionKey)
  if e!=nil||len(b)==0{return fmt.Errorf("amneziawg: invalid header protection key")}
 }
 if _,err:=decodeKey(c.SecretKey);err!=nil{return fmt.Errorf("amneziawg: private key: %w",err)}
 for _,p:=range c.Peers{
  if _,err:=decodeKey(p.PublicKey);err!=nil{return fmt.Errorf("amneziawg: peer key: %w",err)}
  if p.PreSharedKey!=""{if _,err:=decodeKey(p.PreSharedKey);err!=nil{return err}}
  if _,_,err:=net.SplitHostPort(p.Endpoint);err!=nil{return err}
  if p.KeepAlive<0||p.KeepAlive>65535{return fmt.Errorf("amneziawg: invalid keepalive")}
  for _,prefix:=range p.AllowedIPs{if _,err:=netip.ParsePrefix(prefix);err!=nil{return err}}
 }
 return nil
}

func decodeKey(s string)(string,error){
 b,err:=base64.StdEncoding.DecodeString(s)
 if err!=nil{return "",err}
 if len(b)!=32{return "",fmt.Errorf("expected 32 bytes, received %d",len(b))}
 return hex.EncodeToString(b),nil
}

func buildIPC(c contractnode.AmneziaWG)(io.Reader,error){
 if err:=validateConfig(c);err!=nil{return nil,err}
 key,_:=decodeKey(c.SecretKey)
 b:=&bytes.Buffer{}
 fmt.Fprintf(b,"private_key=%s\n",key)
 for _,item:=range []struct{name,value string}{
  {"jc",strconv.FormatUint(uint64(c.JC),10)},{"jmin",strconv.FormatUint(uint64(c.JMin),10)},{"jmax",strconv.FormatUint(uint64(c.JMax),10)},
  {"s1",strconv.FormatUint(uint64(c.S1),10)},{"s2",strconv.FormatUint(uint64(c.S2),10)},{"s3",strconv.FormatUint(uint64(c.S3),10)},{"s4",strconv.FormatUint(uint64(c.S4),10)},
  {"h1",c.H1},{"h2",c.H2},{"h3",c.H3},{"h4",c.H4},
  {"i1",c.I1},{"i2",c.I2},{"i3",c.I3},{"i4",c.I4},{"i5",c.I5},
  {"header_protection_key",c.HeaderProtectionKey},{"content_padding_addition",c.ContentPaddingAddition},
  {"random_trailers",strconv.FormatBool(c.RandomTrailers)},{"disable_cookies",strconv.FormatBool(c.DisableCookies)},
 }{
  if item.value!=""{fmt.Fprintf(b,"%s=%s\n",item.name,item.value)}
 }
 for _,peer:=range c.Peers{
  pub,_:=decodeKey(peer.PublicKey)
  fmt.Fprintf(b,"public_key=%s\nendpoint=%s\n",pub,peer.Endpoint)
  if peer.PreSharedKey!=""{psk,_:=decodeKey(peer.PreSharedKey);fmt.Fprintf(b,"preshared_key=%s\n",psk)}
  if peer.KeepAlive>0{fmt.Fprintf(b,"persistent_keepalive_interval=%d\n",peer.KeepAlive)}
  for _,prefix:=range peer.AllowedIPs{fmt.Fprintf(b,"allowed_ip=%s\n",prefix)}
 }
 return b,nil
}
