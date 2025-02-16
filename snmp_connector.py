import asyncio
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, \
    ContextData, ObjectType, ObjectIdentity, get_cmd

COMMUNITY = "huawei_router"

async def main(oid):
    # Await the UDP target creation
    udp_target = await UdpTransportTarget.create(('192.168.10.100', 161), timeout=1, retries=5, tagList='')

    # Await the get_cmd coroutine
    result = await get_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        udp_target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    # Unpack the result tuple
    errorIndication, errorStatus, errorIndex, varBinds = result

    if errorIndication:
        print(f"SNMP Error: {errorIndication}")
    elif errorStatus:
        print(f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
    else:
        for oid, val in varBinds:
            print(f'{oid.prettyPrint()} = {decode_sysdescr(val.prettyPrint())}')

def decode_sysdescr(sysdescr):
    # Check if the string is hex-encoded (common if it starts with "0x")
    if sysdescr.startswith("0x") or sysdescr.startswith("0X"):
        # Remove the leading "0x"
        hex_str = sysdescr[2:]
        try:
            # Convert hex to bytes and decode as UTF-8 (replace errors if any)
            decoded = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
            return decoded
        except Exception as e:
            return f"Error decoding hex: {e}"
    else:
        # If it's not hex, return the original string
        return sysdescr


asyncio.run(main('1.3.6.1.2.1.1.1.0'))
asyncio.run(main('1.3.6.1.2.1.1.2.0'))
asyncio.run(main('1.3.6.1.2.1.1.3.0'))
asyncio.run(main('1.3.6.1.2.1.1.4.0'))
asyncio.run(main('1.3.6.1.2.1.1.5.0'))
