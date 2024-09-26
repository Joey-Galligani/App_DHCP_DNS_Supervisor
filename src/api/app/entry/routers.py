from fastapi import APIRouter
from ..types import dns, dhcp, prefix
from ..db_connection import client

router = APIRouter(prefix=prefix+"/entry")

dhcp_frame_collection = client.db.sae.dhcp_frame
dns_frame_collection = client.db.sae.dns_frame

@router.get("/dhcp")
async def dhcp_entry(limit:int=50) -> list[dhcp.get_entry]:
    # Getting multiple analyzed frames
    resp = dhcp_frame_collection.find({'analyzed': True}, limit=limit)
    ret = []

    # Formating each frames for response
    for r in resp:
        id = str(r['_id'])
        del r['_id']
        del r['analyzed']
        r['ID'] = id

        ret.append(r)

    return ret

@router.get("/dns")
async def dns_entry(limit:int=50) -> list[dns.get_entry]:
    # Getting multiple analyzed frames
    resp = dns_frame_collection.find({'analyzed': True}, limit=limit)
    ret = []

    # Formating each frames for response
    for r in resp:
        id = str(r['_id'])
        del r['_id']
        del r['analyzed']
        r['ID'] = id

        ret.append(r)

    return ret

@router.post("/dhcp")
async def post_dhcp_entry(item: dhcp.post_entry):
    # Formating the item for mongo
    new_item = dict(item)
    new_item['dhcp'] = dict(item.dhcp)
    # Mark it has unanalyzed
    new_item['analyzed'] = False

    # Insert into mongo
    dhcp_frame_collection.insert_one(new_item)

    return 'OK'

@router.post("/dns")
async def post_dns_entry(item: dns.post_entry):
    # Formating the item for mongo
    new_item = dict(item)
    new_item['dns'] = dict(item.dns)
    # Mark it has unanalyzed
    new_item['analyzed'] = False


    # Insert into mongo
    dns_frame_collection.insert_one(new_item)

    return {'OK'}
