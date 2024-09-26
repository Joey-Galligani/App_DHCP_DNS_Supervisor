from fastapi import APIRouter
from ..types import dns, dhcp, prefix
from ..db_connection import client

router = APIRouter(prefix=prefix+"/analyse")

dhcp_frame_collection = client.db.sae.dhcp_frame
dns_frame_collection = client.db.sae.dns_frame
dhcp_allowed_collection = client.db.sae.dhcp_allowed

@router.get("/dhcp")
async def dhcp_analyse() -> dhcp.get_analyse | None:
    try:
        # Getting the oldest frame that isn't analyzed
        resp = dhcp_frame_collection.find({'analyzed' : False}).sort('timestamp', 1)[0]
    except IndexError:
        # If there is no frame we return nothing
        return None
    else:
        # Mark it as analyzed
        newval = { "$set": { "analyzed": True } }
        query = { "_id": resp['_id'] }
        dhcp_frame_collection.update_one(query, newval)

        # Converting new id
        id = str(resp['_id'])
        
        # Formating the response
        ret = resp
        ret['ID'] = id
        del ret['_id']

        return ret

@router.get("/dns")
async def dns_analyse() -> dns.get_analyse | None:
    try:
        # Getting the oldest frame that isn't analyzed
        resp = dns_frame_collection.find({'analyzed' : False}).sort('timestamp', 1)[0]
    except IndexError:
        # If there is no frame we return nothing
        return None
    else:
        # Mark it as analyzed
        newval = { "$set": { "analyzed": True } }
        query = { "_id": resp['_id'] }
        dns_frame_collection.update_one(query, newval)

        # Converting new id
        id = str(resp['_id'])
        
        # Formating the response
        ret = resp
        ret['ID'] = id
        del ret['_id']

        return ret

@router.get("/dhcp/allowed")
async def dhcp_allowed(limit:int = 50) -> list[str]:
    resp = dhcp_allowed_collection.find(limit=limit)

    return [ r['ip'] for r in resp ]

@router.post("/dhcp/allowed")
async def post_dhcp_allowed(item: dhcp.post_allowed):
    dhcp_allowed_collection.insert_one({'ip': item.ip})
    return {'OK'}
