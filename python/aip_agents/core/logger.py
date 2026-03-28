class AIPLogger:
    """Structured logging for AIP token operations."""

    def __init__(self, enabled: bool = False):
        self._enabled = enabled

    def identity_created(self, name: str, aip_id: str) -> None:
        if self._enabled:
            print(f"[AIP] Identity created: {name} -> {aip_id}")

    def token_issued(self, agent_name: str, scope: list[str], mode: str) -> None:
        if self._enabled:
            print(f"[AIP] Token issued: {agent_name} scope={scope} mode={mode}")

    def delegation(self, parent: str, child: str, scope: list[str], chain_depth: int) -> None:
        if self._enabled:
            print(
                f"[AIP] Delegation: {parent} -> {child} "
                f"[scope: {','.join(scope)}] [chain depth: {chain_depth}]"
            )

    def tool_call(self, agent_name: str, tool_name: str, chain_depth: int) -> None:
        if self._enabled:
            print(
                f"[AIP] Tool call: {agent_name} -> {tool_name} "
                f"[chain depth: {chain_depth}]"
            )
