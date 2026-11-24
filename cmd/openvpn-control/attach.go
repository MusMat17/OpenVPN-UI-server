package main

import (
 "bufio"
 "context"
 "crypto/x509"
 "encoding/pem"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "strings"
 "time"
)

const attachPKI = "/etc/openvpn/server/easy-rsa/pki"
func (a *App) attached() bool { return a.cfg.Backend == "angristan" }

// Read the EasyRSA index, not the presence of a private key. Never import the
// server certificate or accept names that cannot safely be used in a path.
func readAttachInventory(pki string) (map[string]Client,error) {
 b,err:=os.ReadFile(filepath.Join(pki,"index.txt")); if err!=nil{return nil,err}
 out:=map[string]Client{}
 for _,line:=range strings.Split(string(b),"\n") {
  f:=strings.Split(line,"\t"); if len(f)<6 || f[0]!="V" {continue}
  dn:=f[5]; if !strings.HasPrefix(dn,"/CN=") {continue}
  name:=strings.TrimPrefix(dn,"/CN="); if !validName(name){continue}
  crt,err:=os.ReadFile(filepath.Join(pki,"issued",name+".crt")); if err!=nil {continue}
  block,_:=pem.Decode(crt); if block==nil {continue}
  cert,err:=x509.ParseCertificate(block.Bytes); if err!=nil || cert.IsCA || cert.Subject.CommonName!=name || time.Now().After(cert.NotAfter) {continue}
  client,server:=false,false
  for _,eku:=range cert.ExtKeyUsage {if eku==x509.ExtKeyUsageClientAuth {client=true}; if eku==x509.ExtKeyUsageServerAuth {server=true}}
  if !client || server {continue}
  out[name]=Client{Name:name,CreatedAt:cert.NotBefore,ExpiresAt:cert.NotAfter,Days:int(cert.NotAfter.Sub(cert.NotBefore).Hours()/24)}
 }
 return out,nil
}
// Caller holds a.mu after startup. Metadata never overrides certificate status.
func (a *App) syncAttached() error {
 current,err:=readAttachInventory(attachPKI); if err!=nil{return err}
 for name,c:=range current {if old,ok:=a.clients[name];ok {c.Comment=old.Comment;c.LastConnectedAt=old.LastConnectedAt};current[name]=c}
 a.clients=current
 return nil
}
func (a *App) installer(args ...string) error {
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,"/bin/bash",append([]string{a.cfg.Installer},args...)...)
 cmd.Dir="/etc/openvpn/server"
 cmd.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin","HOME=/root","LANG=C","LOG_FILE="}
 // No CLI output goes to HTTP or journal; it may contain sensitive data.
 cmd.Stdout=io.Discard;cmd.Stderr=io.Discard
 return cmd.Run()
}
func (a *App) profilePath(name string) string {return filepath.Join(a.cfg.ProfileDir,name+".ovpn")}
func (a *App) createAttached(w http.ResponseWriter,r *http.Request,name,comment string,days int,host string,port,verb int) {
 if err:=a.syncAttached();err!=nil {http.Error(w,"inventory unavailable",503);return}
 if _,ok:=a.clients[name];ok {http.Error(w,"name already used",409);return}
 path:=a.profilePath(name)
 if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){http.Error(w,"profile already exists or unavailable",409);return}
 // Keep server-provided template, including tls-crypt-v2, and rewrite only
 // the three explicitly editable fields in the new profile.
 if err:=a.installer("client","add",name,"--cert-days",strconv.Itoa(days),"--output",path);err!=nil {http.Error(w,"installer failed; inspect PKI before retry",500);return}
 b,err:=os.ReadFile(path);if err==nil {var updated string; updated,err=rewriteAttachProfile(string(b),host,port,verb);if err==nil {err=atomicWrite(path,[]byte(updated),0600)}}
 if err!=nil {http.Error(w,"certificate created; profile requires manual inspection",500);return}
 if err=a.syncAttached();err!=nil {http.Error(w,"certificate created; inventory unavailable",500);return}
 c,ok:=a.clients[name];if !ok {http.Error(w,"certificate created; inventory mismatch",500);return}
 c.Comment=comment;a.clients[name]=c
 if err=a.save();err!=nil {http.Error(w,"metadata save failed",500);return}
 audit("attach-create",name);http.Redirect(w,r,"/?msg=created#clients",303)
}
func rewriteAttachProfile(body,host string,port,verb int)(string,error){
 if !validProfileInputs(host,port,verb){return "",errors.New("invalid profile settings")}
 lines:=strings.Split(body,"\n");remote,verbosity:=0,0;inline:=false
 for i,line:=range lines {t:=strings.TrimSpace(line);if strings.HasPrefix(t,"</"){inline=false;continue};if strings.HasPrefix(t,"<"){inline=true;continue};if inline{continue};f:=strings.Fields(t);if len(f)==0{continue};switch f[0]{case "remote":remote++;lines[i]=fmt.Sprintf("remote %s %d",host,port);case "verb":verbosity++;lines[i]=fmt.Sprintf("verb %d",verb)}}
 if remote!=1||verbosity>1{return "",errors.New("unsupported profile layout")}
 if verbosity==0 {lines=append(lines,fmt.Sprintf("verb %d",verb))}
 return strings.Join(lines,"\n"),nil
}
func (a *App) revokeAttached(w http.ResponseWriter,r *http.Request,c Client){
 if err:=a.installer("client","revoke",c.Name,"--force");err!=nil {http.Error(w,"revocation failed; inspect PKI before retry",500);return}
 if err:=a.syncAttached();err!=nil {http.Error(w,"revoked; inventory unavailable",500);return}
 if _,ok:=a.clients[c.Name];ok {http.Error(w,"revocation not confirmed",500);return}
 _=os.Remove(a.profilePath(c.Name))
 if err:=a.save();err!=nil {http.Error(w,"metadata save failed",500);return}
 audit("attach-revoke",c.Name);http.Redirect(w,r,"/?msg=deleted",303)
}
func (a *App) downloadAttached(w http.ResponseWriter,name string){
 a.mu.Lock();defer a.mu.Unlock()
 if err:=a.syncAttached();err!=nil {http.Error(w,"inventory unavailable",503);return}
 if _,ok:=a.clients[name];!ok {http.NotFound(w,nil);return}
 path:=a.profilePath(name);info,err:=os.Lstat(path)
 if err!=nil||!info.Mode().IsRegular()||info.Size()>1<<20 {http.Error(w,"existing profile unavailable; import the original profile",404);return}
 b,err:=os.ReadFile(path);if err!=nil {http.Error(w,"profile unavailable",500);return}
 w.Header().Set("Content-Type","application/x-openvpn-profile")
 w.Header().Set("Content-Disposition",fmt.Sprintf("attachment; filename=%q",name+".ovpn"))
 w.Header().Set("Cache-Control","no-store");w.Write(b)
}
func (a *App) unixStatus()(map[string]Live,error){
 conn,err:=net.DialTimeout("unix",a.cfg.ManagementSocket,2*time.Second);if err!=nil{return nil,err};defer conn.Close()
 if err=conn.SetDeadline(time.Now().Add(4*time.Second));err!=nil{return nil,err}
 if _,err=io.WriteString(conn,"status 2\n");err!=nil{return nil,err}
 scanner:=bufio.NewScanner(io.LimitReader(conn,1<<20));scanner.Buffer(make([]byte,4096),1<<20)
 var body strings.Builder
 for scanner.Scan(){line:=strings.TrimSuffix(scanner.Text(),"\r");body.WriteString(line+"\n");if line=="END"{return parseManagementStatus(body.String())}}
 if err=scanner.Err();err!=nil{return nil,err};return nil,errors.New("incomplete UNIX management status")
}
