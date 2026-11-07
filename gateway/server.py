from fastmcp import FastMCP

mcp = FastMCP("AgentLedger Gateway")

@mcp.tool
def agentledger_ping() -> dict:
    """Check that Kiro can reach the AgentLedger gateway."""
    return {
        "connected": True,
        "service": "AgentLedger",
        "auth_mode": "development_connectivity_only",
    }

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000)
