from fastapi import APIRouter
from ..types import dhcp, dns, prefix
from ..db_connection import client

router = APIRouter(prefix=prefix+"/stats")

dns_stats_collection = client.db.sae.dns_stats
dhcp_stats_collection = client.db.sae.dhcp_stats

@router.get("/dhcp")
async def dhcp_stats() -> dhcp.get_stats:
    ret = {}

    used = dhcp_stats_collection.find_one({'_id': 'used'})
    available = dhcp_stats_collection.find_one({'_id': 'available'})

    if used == None:
        dhcp_stats_collection.update_one({'_id': 'used'}, {'$set': {'count': 0}}, upsert=True)
        ret['used'] = 0
    else:
        ret['used'] = used['count']

    if available == None:
        dhcp_stats_collection.update_one({'_id': 'available'}, {'$set': {'count': 1}}, upsert=True)
        ret['available'] = 1
    else:
        ret['available'] = available['count']

    return ret

@router.get("/dns")
async def dns_stats(type: str):
    return {"type":type}

@router.post("/dhcp/used")
async def post_dhcp_stats_used(item: dhcp.post_stats_used):
    dhcp_stats_collection.update_one({'_id': 'used'}, {'$set': {'count': item.used}}, upsert=True)

    return {"OK"}

@router.post("/dhcp/available")
async def post_dhcp_stats_available(item: dhcp.post_stats_available):
    dhcp_stats_collection.update_one({'_id': 'available'}, {'$set': {'count': item.available}}, upsert=True)

    return {"OK"}

@router.post("/dns")
async def post_dns_stats(item: dns.post_stats):
    dns_stats_collection.update_one({'_id': item.ipdst, type: 'ipdst'}, {'$inc': {'count':1}}, upsert=True)
    dns_stats_collection.update_one({'_id': item.ipsrc, type: 'ipsrc'}, {'$inc': {'count':1}}, upsert=True)
    dns_stats_collection.update_one({'_id': item.tld, type: 'tld'}, {'$inc': {'count':1}}, upsert=True)
    dns_stats_collection.update_one({'_id': item.fqdn, type: 'fqdn'}, {'$inc': {'count':1}}, upsert=True)

    return {"OK"}

