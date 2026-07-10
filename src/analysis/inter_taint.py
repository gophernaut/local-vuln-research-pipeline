"""Inter-procedural taint propagation — tracks tainted data through function calls.

When function A passes a tainted variable to function B as an argument, B's
corresponding parameter becomes tainted. When B returns a tainted value, A's
caller receives a tainted variable.

Algorithm:
1. For every function, know which parameters are tainted (from sources) and
   which return values are tainted.
2. For every call site, match the call's argument variables to the callee's
   parameter names. Propagate taint.
3. If callee's return is tainted, mark the call expression as tainted in caller.
4. Recompute until fixed point.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.analysis.intra_taint import IntraTaintTracker, TaintState, trace_function_fully


@dataclass
class InterTaintState:
    function_taint: dict[str, TaintState] = field(default_factory=dict)
    param_sources: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    sink_reaches: list[dict] = field(default_factory=list)
    iterations: int = 0


class InterTaintPropagator:
    def __init__(self, max_iterations: int = 10):
        self.max_iterations = max_iterations
        self.intra = IntraTaintTracker()

    def propagate(
        self,
        functions: dict[str, dict],
        source_tag_vars_by_file: dict[str, set[str]],
    ) -> InterTaintState:
        """functions: {func_key: {file, name, body, language, params: [name, ...]}}"""
        state = InterTaintState()

        for func_key, func_info in functions.items():
            file_path = func_info["file"]
            source_vars = source_tag_vars_by_file.get(file_path, set())
            param_names = set(func_info.get("params", []))

            tstate = self.intra.trace_function(
                function_body=func_info["body"],
                function_name=func_info["name"],
                file=file_path,
                language=func_info["language"],
                source_tag_vars=source_vars,
                param_names=param_names,
            )
            state.function_taint[func_key] = tstate
            state.sink_reaches.extend(tstate.sink_reaches)

        for iteration in range(self.max_iterations):
            changed = False
            new_sink_reaches = []

            for func_key, func_info in functions.items():
                file_path = func_info["file"]
                tstate = state.function_taint[func_key]
                call_sites = func_info.get("call_sites", [])

                for call in call_sites:
                    called_func = call.get("function_name", "")
                    args = call.get("arguments", [])
                    if not called_func or not args:
                        continue

                    callee_key = self._resolve_callee(called_func, func_info, functions)
                    if not callee_key:
                        continue

                    callee_state = state.function_taint[callee_key]
                    callee_params = functions[callee_key].get("params", [])

                    for i, arg in enumerate(args):
                        if i >= len(callee_params):
                            continue
                        param = callee_params[i]
                        if arg in tstate.tainted_vars:
                            if param not in callee_state.tainted_vars:
                                callee_state.tainted_vars.add(param)
                                changed = True

                            if param in callee_state.return_taint:
                                call_var = f"call_{called_func}_{i}"
                                if call_var not in tstate.tainted_vars:
                                    tstate.tainted_vars.add(call_var)
                                    changed = True

                                new_sink_reaches.append({
                                    "function": called_func,
                                    "argument_index": i,
                                    "line": call.get("line", 0),
                                    "tainted_vars": [arg],
                                    "is_sanitized": False,
                                    "note": "propagated_through_return",
                                })

            state.iterations = iteration + 1
            state.sink_reaches.extend(new_sink_reaches)
            if not changed:
                break

        return state

    def _resolve_callee(self, func_name: str, caller_info: dict,
                        functions: dict[str, dict]) -> str | None:
        caller_file = caller_info.get("file", "")

        for func_key, func_info in functions.items():
            if func_info["name"] == func_name:
                if caller_file and func_info.get("file") == caller_file:
                    return func_key
                return func_key
        return None

    def get_sink_reaches_for_func(self, state: InterTaintState, func_key: str) -> list[dict]:
        reaches = []
        for reach in state.sink_reaches:
            if reach.get("function_name") == func_key or func_key in str(reach):
                reaches.append(reach)
        return reaches


def propagate_taint(functions: dict[str, dict],
                    source_tag_vars_by_file: dict[str, set[str]],
                    max_iterations: int = 10) -> InterTaintState:
    propagator = InterTaintPropagator(max_iterations=max_iterations)
    return propagator.propagate(functions, source_tag_vars_by_file)
