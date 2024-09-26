from pydantic import BaseModel, Field

class dhcp(BaseModel):
    op: int = Field(ge=0, le=255)
    htype: int = Field(ge=0, le=255)
    hlen: int = Field(ge=0, le=255)
    hops: int = Field(ge=0, le=255)
    xid: int = Field(ge=0, le=0xffffffff)
    secs: int = Field(ge=0, le=65535)
    flags: int = Field(ge=0, le=65535)
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: str
    magicCookie: int
    options: dict[int|str, str|list|int]

class post_entry(BaseModel):
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dhcp: dhcp

class get_entry(BaseModel):
    ID: str
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dhcp: dhcp

class get_analyse(BaseModel):
    ID: str
    timestamp: float
    macsrc: str
    macdst: str
    ipsrc: str
    ipdst: str
    portsrc: int = Field(ge=1, le=65535)
    portdst: int = Field(ge=1, le=65535)
    dhcp: dhcp

class get_stats(BaseModel):
    available: int = Field(ge=1)
    used: int = Field(ge=0)

class post_stats_used(BaseModel):
    used: int = Field(ge=0)
    
class post_stats_available(BaseModel):
    available: int = Field(ge=1)

class get_alerts(BaseModel):
    type: str
    description: str
    frame: str

class post_alerts(BaseModel):
    type: str
    description: str
    frame: str

class post_allowed(BaseModel):
    ip: str
