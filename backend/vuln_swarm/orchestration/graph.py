from __future__ import annotations

from pathlib import Path
from typing import Callable, Awaitable

from langgraph.graph import END, START, StateGraph

from vuln_swarm.agents.agent_a import OffensiveSecurityAgent
from vuln_swarm.agents.agent_b import RemediationAgent
from vuln_swarm.agents.agent_c import ValidationAgent
from vuln_swarm.schemas import AgentName, JobStatus, TraceEvent, ValidationStatus
from vuln_swarm.orchestration.state import SwarmState

TraceCallback = Callable[[TraceEvent, JobStatus | None, str | None], Awaitable[None]]


class SwarmGraph:
    def __init__(
        self,
        *,
        agent_a: OffensiveSecurityAgent,
        agent_b: RemediationAgent,
        agent_c: ValidationAgent,
        trace_callback: TraceCallback | None = None,
    ):
        self.agent_a = agent_a
        self.agent_b = agent_b
        self.agent_c = agent_c
        self.trace_callback = trace_callback
        self.graph = self._build().compile()

    async def ainvoke(self, state: SwarmState) -> SwarmState:
        return await self.graph.ainvoke(state, config={"recursion_limit": 20})

    def _build(self) -> StateGraph:
        graph = StateGraph(SwarmState)
        graph.add_node("agent_a", self._run_agent_a)
        graph.add_node("agent_b", self._run_agent_b)
        graph.add_node("agent_c", self._run_agent_c)
        graph.add_edge(START, "agent_a")
        graph.add_edge("agent_a", "agent_b")
        graph.add_edge("agent_b", "agent_c")
        graph.add_conditional_edges("agent_c", self._route_after_validation, {"agent_b": "agent_b", END: END})
        return graph

    async def _run_agent_a(self, state: SwarmState) -> SwarmState:
        await self._trace(state, AgentName.agent_a, "scan", "running", "Agent A scanning repository.")
        report = await self.agent_a.run(
            run_id=state["run_id"],
            repo_path=Path(state["repository_path"]),
            repository=state["repository"],
            commit_sha=state.get("commit_sha"),
        )
        await self._trace(
            state,
            AgentName.agent_a,
            "scan",
            "completed",
            f"Agent A produced {len(report.vulnerabilities)} findings.",
        )
        return {"vulnerability_report": report, "validation_status": ValidationStatus.pending}

    async def _run_agent_b(self, state: SwarmState) -> SwarmState:
        await self._trace(state, AgentName.agent_b, "remediate", "running", "Agent B applying fixes.")
        report = await self.agent_b.run(
            run_id=state["run_id"],
            repo_path=Path(state["repository_path"]),
            report=state["vulnerability_report"],
            retry_count=state.get("retry_count", 0),
            feedback=state.get("remediation_feedback"),
        )
        await self._trace(
            state,
            AgentName.agent_b,
            "remediate",
            "completed",
            f"Agent B status: {report.status}.",
        )
        return {"fix_report": report}

    async def _run_agent_c(self, state: SwarmState) -> SwarmState:
        await self._trace(state, AgentName.agent_c, "validate", "running", "Agent C validating fixes.")
        request = state["request"]
        retry_count = state.get("retry_count", 0)
        report = await self.agent_c.run(
            run_id=state["run_id"],
            repo_path=Path(state["repository_path"]),
            original_report=state["vulnerability_report"],
            fix_report=state["fix_report"],
            retry_count=retry_count,
            create_pr=request.create_pr,
            github_repository=request.github_repository,
            base_branch=request.base_branch,
            fork_owner=request.fork_owner,
        )
        next_retry_count = retry_count if report.fixed else retry_count + 1
        await self._trace(
            state,
            AgentName.agent_c,
            "validate",
            "completed",
            f"Agent C status: {report.validation_status}.",
        )
        return {
            "validation_report": report,
            "validation_status": report.validation_status,
            "retry_count": next_retry_count,
            "remediation_feedback": report.feedback_to_remediation,
        }

    def _route_after_validation(self, state: SwarmState) -> str:
        if state.get("validation_status") in {ValidationStatus.fixed, ValidationStatus.needs_human}:
            return END
        if state.get("retry_count", 0) >= state.get("max_retry_count", 0):
            return END
        return "agent_b"

    async def _trace(
        self,
        state: SwarmState,
        agent: AgentName,
        step: str,
        status: str,
        message: str,
    ) -> None:
        event = TraceEvent(agent=agent, step=step, status=status, message=message)
        if self.trace_callback:
            await self.trace_callback(event, JobStatus.running, step)
