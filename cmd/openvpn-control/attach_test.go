package main
import ("strings";"testing")
func TestAttachProfilePreservesTLSAndRouting(t *testing.T){
 input:="client\nremote vpn.example.com 1194\nverb 3\n<tls-crypt-v2>\nexample-key\n</tls-crypt-v2>\n"
 got,err:=rewriteAttachProfile(input,"203.0.113.10",443,0)
 if err!=nil||!strings.Contains(got,"remote 203.0.113.10 443\nverb 0")||!strings.Contains(got,"<tls-crypt-v2>\nexample-key\n</tls-crypt-v2>")||strings.Contains(got,"redirect-gateway"){t.Fatalf("unexpected profile: %v %q",err,got)}
}
func TestAttachRejectsMultipleRemotes(t *testing.T){
 if _,err:=rewriteAttachProfile("remote vpn.example.com 1194\nremote vpn.example.net 1194\n","vpn.example.org",1194,3);err==nil{t.Fatal("multiple remotes accepted")}
}
