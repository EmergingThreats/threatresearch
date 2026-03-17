#!/usr/bin/env python3
import json
import urllib.parse
import base64
import sys

def create_deeplink(mcp_file: str) -> str:
    with open(mcp_file, 'r') as f:
        config = json.load(f)
    
    name = config.pop("name", "MCP Server")
    
    config_json = json.dumps(config)
    config_b64 = base64.b64encode(config_json.encode('utf-8')).decode('utf-8')
    
    name_encoded = urllib.parse.quote(name)
    config_encoded = urllib.parse.quote(config_b64)
    
    deeplink = f"cursor://anysphere.cursor-deeplink/mcp/install?name={name_encoded}&config={config_encoded}"
    return deeplink

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_deeplink.py <mcp.json>")
        sys.exit(1)
    
    mcp_file = sys.argv[1]
    deeplink = create_deeplink(mcp_file)
    print(deeplink)
