from pydantic import BaseModel, Field

class dns(BaseModel):
    dnsID: int = Field(ge=0, le=0xffffffff)
    qr: int = Field(ge=0, le=1)
    opcode: int = Field(ge=0, le=15)
    aa: int = Field(ge=0, le=1)
    tc: int = Field(ge=0, le=1)
    rd: int = Field(ge=0, le=1)
    ra: int = Field(ge=0, le=1)
    z: int = Field(ge=0, le=7)
    rcode: int = Field(ge=0, le=15)
    nQuery: int
    nAnswer: int
    nAuthority: int
    nAdditional: int
    query: list[str]
    answer: list[str]
    authority: list[str]
    additional: list[str]

class get_entry(BaseModel):
    ID: str
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dns: dns

class get_analyse(BaseModel):
    ID: str
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dns: dns

class post_entry(BaseModel):
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dns: dns

class post_stats(BaseModel):
    tld: str
    fqdn: str
    ipsrc: str
    ipdst: str
