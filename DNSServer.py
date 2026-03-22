import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rrset
import socket
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def gen_key(p,s):
    k=PBKDF2HMAC(algorithm=hashes.SHA256(),iterations=100000,salt=s,length=32)
    return base64.urlsafe_b64encode(k.derive(p.encode()))

salt=b'Tandon'
pw='mme324@nyu.edu'
fernet=Fernet(gen_key(pw,salt))
token=fernet.encrypt(b'AlwaysWatching').decode()

records={
 'nyu.edu.':{
  dns.rdatatype.A:'192.168.1.106',
  dns.rdatatype.TXT:(token,),
  dns.rdatatype.MX:[(10,'mxa-00256a01.gslb.pphosted.com.')],
  dns.rdatatype.AAAA:'2001:0db8:85a3:0000:0000:8a2e:0373:7312',
  dns.rdatatype.NS:'ns1.nyu.edu.'
 }
}

sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind(('127.0.0.1',53))

while True:
 data,addr=sock.recvfrom(1024)
 req=dns.message.from_wire(data)
 res=dns.message.make_response(req)
 q=req.question[0]
 name=q.name.to_text()
 typ=q.rdtype
 if name in records and typ in records[name]:
  val=records[name][typ]
  if typ==dns.rdatatype.MX:
   for pref,host in val:
    rr=dns.rrset.from_text(name,60,dns.rdataclass.IN,'MX',f"{pref} {host}")
    res.answer.append(rr)
  else:
   for v in (val if isinstance(val,tuple) else (val,)):
    rr=dns.rrset.from_text(name,60,dns.rdataclass.IN,dns.rdatatype.to_text(typ),v)
    res.answer.append(rr)
 res.flags|=1<<10
 sock.sendto(res.to_wire(),addr)
