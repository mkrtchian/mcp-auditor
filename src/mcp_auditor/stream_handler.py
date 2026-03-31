# pyright: reportUnknownArgumentType=false
from typing import Any

from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import ToolDefinition


class AuditProgressReporter:
    def __init__(self, display: AuditDisplay) -> None:
        self._display = display
        self._tool_index = 0
        self._tool_count = 0
        self._active_progress: Any = None

    def on_stream_event(self, event: tuple[tuple[str, ...], dict[str, Any]]) -> None:
        namespace, updates = event
        for node_name, state_update in updates.items():
            if not isinstance(state_update, dict):
                continue
            if namespace == ():
                self._on_parent_event(node_name, state_update)
            elif len(namespace) == 1:
                self._on_subgraph_event(node_name, state_update)
            else:
                self._on_chain_event(node_name, state_update)

    def _on_parent_event(self, node_name: str, state_update: dict[str, Any]) -> None:
        if node_name == "discover_tools":
            tools: list[ToolDefinition] = state_update.get("discovered_tools", [])
            self._tool_count = len(tools)
            self._display.print_discovery(len(tools), [t.name for t in tools])
        elif node_name == "prepare_tool":
            tool: ToolDefinition | None = state_update.get("current_tool")
            if tool:
                self._tool_index += 1
        elif node_name == "build_tool_report":
            if self._active_progress:
                self._active_progress.stop()
                self._active_progress = None

    def _on_chain_event(self, node_name: str, state_update: dict[str, Any]) -> None:
        if node_name == "plan_chains":
            pending = state_update.get("pending_chains", [])
            if pending:
                self._display.print_info(f"Planning {len(pending)} attack chain(s)")
        elif node_name == "execute_step":
            steps = state_update.get("current_chain_steps", [])
            if steps:
                self._display.print_info(f"  Chain step {len(steps)} executed")
        elif node_name == "judge_chain":
            chains = state_update.get("completed_chains", [])
            if chains:
                last = chains[-1]
                verdict = last.eval_result.verdict if last.eval_result else "?"
                self._display.print_info(f"  Chain judged: {verdict}")

    def _on_subgraph_event(self, node_name: str, state_update: dict[str, Any]) -> None:
        if node_name == "generate_test_cases":
            pending = state_update.get("pending_cases", [])
            if pending:
                tool_name = pending[0].payload.tool_name
                progress = self._display.create_tool_progress(
                    self._tool_index, self._tool_count, tool_name, len(pending)
                )
                progress.start()
                self._active_progress = progress
        elif node_name == "judge_response":
            judged = state_update.get("judged_cases", [])
            if judged:
                last_case = judged[-1]
                if last_case.eval_result is not None and self._active_progress:
                    self._active_progress.advance(last_case.eval_result)
