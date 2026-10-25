package main
import ("strings";"testing")
func TestPassword(t *testing.T){
 h:=hashPassword("correct example password 123")
 if !checkPassword("correct example password 123",h){t.Fatal("valid password rejected")}
 if checkPassword("wrong",h){t.Fatal("invalid password accepted")}
 if strings.Contains(h,"correct example"){t.Fatal("cleartext password leaked")}
}
func TestClientNames(t *testing.T){
 for _,s:=range []string{"alice","test-01","CLIENT_2"} {if !validName(s){t.Errorf("invalid valid CN %q",s)}}
 for _,s:=range []string{"","../foo","-bad","a b","a;touch /tmp/file",strings.Repeat("a",49)} {if validName(s){t.Errorf("accepted invalid CN %q",s)}}
}
func TestHumanBytes(t *testing.T){if humanBytes(2048)!="2.0 KiB"{t.Fatal(humanBytes(2048))}}
