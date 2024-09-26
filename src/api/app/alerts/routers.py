from fastapi import APIRouter
from ..types import dhcp, dns, prefix
from ..db_connection import client

dhcp_alerts_collection = client.db.sae.dhcp_alerts

router = APIRouter(prefix=prefix+"/alerts")

@router.get("/dhcp")
async def dhcp_alerts(limit:int = 50) -> list[dhcp.get_alerts]:
    # Getting multiple analyzed frames
    resp = dhcp_alerts_collection.find(limit=limit)
    ret = []

    # Formating each alerts for response
    for r in resp:
        del r['_id']
        ret.append(r)

    return ret

@router.get("/dns")
async def dns_alerts():
    return {
        "ID": 6,
        "type":"bureau",
        "messageIDs":[10, 12, 14],
    }

@router.post("/dhcp")
async def post_dhcp_alerts(item: dhcp.post_alerts):
    dhcp_alerts_collection.insert_one(dict(item))
    return {"OK"}
