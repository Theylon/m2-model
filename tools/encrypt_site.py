#!/usr/bin/env python3
"""Build the gated site: encrypt src/*.html under a master key, wrap the key per user.

Usage:  python3 tools/encrypt_site.py
Inputs:  src/index.html, src/analysis.html   (plaintext app — gitignored)
         src/users.txt                        (one email per line — gitignored)
         credentials.txt                      (email<TAB>password; reused if present,
                                               generated for new emails — gitignored)
Outputs: index.html (gate), analysis.html (loader), payload_app.js, payload_analysis.js

Scheme: random 32-byte master key K. Each payload = AES-256-GCM(K). Per user:
PBKDF2-HMAC-SHA256(password, salt, 300k iters) -> K_u; wrapped = AES-GCM(K_u, K).
The gate ships only { SHA256(email) -> {salt, nonce, wrapped} } — no raw emails.
"""
import base64, hashlib, json, os, secrets, sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
ITERS = 300_000

WORDS = ("amber basalt cobalt copper delta ember falcon garnet harbor indigo jasper "
         "kestrel lumen marble nickel onyx pewter quartz raven slate topaz umber "
         "vertex willow zephyr argon bronze cedar dune ferrite gale").split()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def gen_password() -> str:
    return "-".join(secrets.choice(WORDS) for _ in range(4))


def derive(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS)
    return kdf.derive(password.encode())


def main() -> None:
    emails = [l.strip().lower() for l in open(os.path.join(SRC, "users.txt"))
              if l.strip() and not l.startswith("#")]
    if not emails:
        sys.exit("src/users.txt is empty")

    # load / generate credentials
    cred_path = os.path.join(ROOT, "credentials.txt")
    creds = {}
    if os.path.exists(cred_path):
        for line in open(cred_path):
            if "\t" in line:
                e, p = line.rstrip("\n").split("\t", 1)
                creds[e.lower()] = p
    for e in emails:
        creds.setdefault(e, gen_password())
    with open(cred_path, "w") as f:
        for e in emails:
            f.write(f"{e}\t{creds[e]}\n")

    K = secrets.token_bytes(32)

    users = {}
    for e in emails:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        users[hashlib.sha256(e.encode()).hexdigest()] = {
            "s": b64(salt), "n": b64(nonce),
            "w": b64(AESGCM(derive(creds[e], salt)).encrypt(nonce, K, None)),
        }

    def enc_payload(name: str, out: str) -> None:
        html = open(os.path.join(SRC, name), "rb").read()
        nonce = secrets.token_bytes(12)
        ct = AESGCM(K).encrypt(nonce, html, None)
        with open(os.path.join(ROOT, out), "w") as f:
            f.write("window.__PAYLOAD={n:%s,c:%s};" % (json.dumps(b64(nonce)), json.dumps(b64(ct))))

    enc_payload("index.html", "payload_app.js")
    enc_payload("analysis.html", "payload_analysis.js")

    gate_js = GATE_JS.replace("__USERS__", json.dumps(users)).replace("__ITERS__", str(ITERS))
    open(os.path.join(ROOT, "index.html"), "w").write(
        PAGE.format(payload="payload_app.js", body=GATE_BODY, js=gate_js))
    open(os.path.join(ROOT, "analysis.html"), "w").write(
        PAGE.format(payload="payload_analysis.js", body=LOADER_BODY, js=LOADER_JS))

    print(f"Built gate for {len(emails)} users. Credentials in credentials.txt (gitignored).")


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>m2 model</title>
<script src="{payload}"></script>
<style>
  :root{{--bg:#FBFAF5;--surface:#FFFFFF;--surface2:#F1EFE8;--text:#2C2C2A;--muted:#5F5E5A;
    --border:rgba(44,44,42,0.14);--accent:#1D9E75;--neg:#C0532F;}}
  @media (prefers-color-scheme: dark){{
    :root{{--bg:#1A1A18;--surface:#242422;--surface2:#2C2C2A;--text:#F1EFE8;--muted:#B4B2A9;
      --border:rgba(241,239,232,0.16);--accent:#5DCAA5;--neg:#E08763;}}}}
  *{{box-sizing:border-box;}}
  body{{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;}}
  .box{{background:var(--surface2);border-radius:12px;padding:2rem;width:100%;max-width:360px;}}
  h1{{font-size:18px;font-weight:600;margin:0 0 4px;}}
  p{{font-size:13px;color:var(--muted);margin:0 0 1.25rem;}}
  label{{display:block;font-size:12.5px;color:var(--muted);margin:0 0 4px;}}
  input{{width:100%;padding:9px 11px;font-size:14px;margin-bottom:12px;
    background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;}}
  input:focus{{outline:none;border-color:var(--accent);}}
  button{{width:100%;padding:10px;font-size:14px;font-weight:600;border:0;border-radius:8px;
    background:var(--accent);color:var(--bg);cursor:pointer;}}
  button:disabled{{opacity:0.6;cursor:wait;}}
  .err{{color:var(--neg);font-size:12.5px;min-height:18px;margin-top:10px;}}
</style>
</head>
<body>
{body}
<script>
{js}
</script>
</body>
</html>
"""

GATE_BODY = """<div class="box">
  <h1>m2 model</h1>
  <p>Access is limited to invited participants.</p>
  <form id="f">
    <label for="e">Email</label>
    <input id="e" type="email" autocomplete="email" required>
    <label for="p">Password</label>
    <input id="p" type="password" autocomplete="current-password" required>
    <button id="b" type="submit">Open the model</button>
    <div class="err" id="err"></div>
  </form>
</div>"""

GATE_JS = """
const USERS=__USERS__, ITERS=__ITERS__;
const b2a=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function sha256hex(s){
  const h=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
  return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function unwrap(email,pw){
  const u=USERS[await sha256hex(email.trim().toLowerCase())];
  if(!u) throw 0;
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  const kd=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b2a(u.s),iterations:ITERS,hash:'SHA-256'},
      km,{name:'AES-GCM',length:256},false,['decrypt']);
  const K=await crypto.subtle.decrypt({name:'AES-GCM',iv:b2a(u.n)},kd,b2a(u.w));
  return new Uint8Array(K);
}
async function show(K){
  const key=await crypto.subtle.importKey('raw',K,'AES-GCM',false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b2a(window.__PAYLOAD.n)},key,b2a(window.__PAYLOAD.c));
  const html=new TextDecoder().decode(pt);
  document.open(); document.write(html); document.close();
  const t=document.querySelectorAll('title'); if(t.length>1) document.title=t[t.length-1].textContent;
}
(async()=>{
  const k=sessionStorage.getItem('m2k');
  if(k){ try{ await show(b2a(k)); }catch(e){ sessionStorage.removeItem('m2k'); } }
})();
document.getElementById('f').addEventListener('submit',async ev=>{
  ev.preventDefault();
  const b=document.getElementById('b'),err=document.getElementById('err');
  b.disabled=true; err.textContent='';
  try{
    const K=await unwrap(document.getElementById('e').value,document.getElementById('p').value);
    sessionStorage.setItem('m2k',btoa(String.fromCharCode.apply(null,K)));
    sessionStorage.setItem('m2e',document.getElementById('e').value.trim().toLowerCase());
    await show(K);
  }catch(e){
    err.textContent='That email / password combination does not work.';
    b.disabled=false;
  }
});
"""

LOADER_BODY = """<div class="box"><h1>m2 model</h1><p id="msg">Unlocking…</p></div>"""

LOADER_JS = """
const b2a=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
(async()=>{
  const k=sessionStorage.getItem('m2k');
  if(!k){ window.location.replace('index.html'); return; }
  try{
    const key=await crypto.subtle.importKey('raw',b2a(k),'AES-GCM',false,['decrypt']);
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b2a(window.__PAYLOAD.n)},key,b2a(window.__PAYLOAD.c));
    document.open(); document.write(new TextDecoder().decode(pt)); document.close();
    const t=document.querySelectorAll('title'); if(t.length>1) document.title=t[t.length-1].textContent;
  }catch(e){ sessionStorage.removeItem('m2k'); window.location.replace('index.html'); }
})();
"""

if __name__ == "__main__":
    main()
