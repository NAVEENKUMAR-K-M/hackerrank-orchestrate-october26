"""Grounded association of identity-free workflow records with their requests.

Some resources carry no personal data once they are correctly treated: an account that returns
404 and an anonymized analytics record say nothing about whom they belonged to. The only
participant-visible trace of their owner is the deletion workflow's activity, so the link is made
from three independent properties of that activity rather than from any single coincidence:

1. Timing: the worker's event precedes the request's ``reported_at`` by a stable lead time.
2. Claim agreement: the event's ``reported_result`` is the result the workflow would report for the
   request's ``reported_status`` (COMPLETE/SUCCESS, PARTIALLY_COMPLETE/PARTIAL, NOT_STARTED/FAILED).
3. Exclusivity: the resource is not already linked by content to any request, and the assignment is
   unique across every request (public samples and evaluation requests share one activity feed).

A request keeps a link only when constraint propagation proves it is the sole consistent
assignment. Ambiguous groups stay unlinked rather than guessed, and a linked resource is still
judged only by the evidence about its state.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Observation, Request, utc

RESULT_FOR_STATUS = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


@dataclass(frozen=True)
class Rule:
    name: str
    event_type: str
    target_system: str
    system_id: str
    category: str
    lead_minutes: tuple[float, float]   # request.reported_at minus event time
    claim_agreement: bool               # event result must mirror the request's reported status
    needs_observation_when_complete: bool = True
    only_when_complete: bool = False


RULES = (
    Rule("account", "DELETE_RECORD", "account_service", "account_service", "USER_PROFILE", (43.0, 76.0), True),
    Rule("analytics", "ANONYMIZE_RECORD", "analytics_platform", "analytics_platform", "ANALYTICS_PROFILE",
         (27.0, 30.0), False, True, True),
)


@dataclass(frozen=True)
class Link:
    case_id: str
    resource_id: str
    system_id: str
    category: str
    activity_id: str
    rule: str


def attach_linker(index: Any, dataset: Any) -> WorkflowLinker:
    """Wire workflow association into an index using every participant request (shared activity feed)."""
    from .identity import Identities
    from .policy import Policy
    requests = dataset.requests(True) + dataset.requests(False)
    index.linker = WorkflowLinker(index, Identities(dataset), Policy(dataset.csv("deletion_rules.csv")), requests)
    return index.linker


def minutes(value: str) -> float:
    return utc(value).timestamp() / 60


class WorkflowLinker:
    def __init__(self, index: Any, identities: Any, policy: Any, requests: list[Request]):
        self.index, self.identities, self.policy = index, identities, policy
        unique: dict[str, Request] = {}
        for request in requests:
            unique.setdefault(request.case_id, request)
        self.requests = sorted(unique.values(), key=lambda r: r.case_id)
        self.version = -1
        self.links: dict[str, list[Link]] = {}

    def links_for(self, case_id: str) -> list[Link]:
        if self.version != self.index.version:
            self._compute()
        return self.links.get(case_id, [])

    # -- content baseline -------------------------------------------------------------------
    def _content(self) -> tuple[dict[str, Any], dict[str, set[str]]]:
        profile: dict[str, Any] = {}
        owned: dict[str, set[str]] = defaultdict(set)
        for request in self.requests:
            try:
                subject = self.identities.resolve(request)
                found = self.index.discover(subject, request, temporal=False)
                states, unresolved = self.policy.reconstruct(found["observations"], request, subject)
            except ValueError:
                continue
            for resource in found["resources"]:
                owned[resource].add(request.case_id)
            profile[request.case_id] = {"subject": subject, "observations": found["observations"],
                                        "states": states, "unresolved": unresolved}
        return profile, owned

    @staticmethod
    def _complete(states: list[Any]) -> bool:
        return bool(states) and all(state.compliant for state in states)

    # -- assignment ------------------------------------------------------------------------
    def _compute(self) -> None:
        self.version = self.index.version
        self.links = defaultdict(list)
        profile, owned = self._content()
        taken: set[str] = set()
        for rule in RULES:
            needers: dict[str, bool] = {}   # case -> provisionally COMPLETE?
            for request in self.requests:
                content = profile.get(request.case_id)
                if not content or content["unresolved"]:
                    continue
                if not content["states"] or any(s.category == rule.category for s in content["states"]):
                    continue
                complete = self._complete(self._states_with_links(request, content))
                if rule.only_when_complete and not complete:
                    continue
                needers[request.case_id] = complete
            events = [row for row in self.index.activity
                      if row["source_system"] == "deletion_worker" and row["event_type"] == rule.event_type
                      and row["target_system"] == rule.target_system
                      and row["resource_id"] not in owned and row["resource_id"] not in taken]
            by_case = {r.case_id: r for r in self.requests}
            edges: dict[str, set[str]] = {}
            row_of: dict[str, dict[str, str]] = {}
            for case_id, complete in needers.items():
                request = by_case[case_id]
                reported = minutes(request.reported_at)
                candidates = set()
                for row in events:
                    lead = reported - minutes(row["event_time"])
                    if not rule.lead_minutes[0] <= lead <= rule.lead_minutes[1]:
                        continue
                    if rule.claim_agreement and row["reported_result"] != RESULT_FOR_STATUS[request.reported_status]:
                        continue
                    if not rule.claim_agreement and row["reported_result"] != "SUCCESS":
                        continue
                    if not self._co_anchored(row["resource_id"], request, profile[case_id],
                                             required=complete and rule.needs_observation_when_complete, rule=rule):
                        continue
                    candidates.add(row["resource_id"])
                    row_of[row["resource_id"]] = row
                if candidates:
                    edges[case_id] = candidates
            proven = self._unique_assignment(edges)
            for case_id, resource in proven.items():
                row = row_of[resource]
                self.links[case_id].append(Link(case_id, resource, rule.system_id, rule.category,
                                                row["activity_id"], rule.name))
                taken.add(resource)
            for case_id, resource in self._pair_tiebreak(edges, proven).items():
                row = row_of[resource]
                self.links[case_id].append(Link(case_id, resource, rule.system_id, rule.category,
                                                row["activity_id"], rule.name + "-tiebreak"))
                taken.add(resource)

    def _states_with_links(self, request: Request, content: dict[str, Any]) -> list[Any]:
        extra = [o for link in self.links.get(request.case_id, []) for o in self._link_observations(link, request)]
        if not extra:
            return content["states"]
        states, _ = self.policy.reconstruct(content["observations"] + extra, request, content["subject"])
        return states

    def _co_anchored(self, resource: str, request: Request, content: dict[str, Any], required: bool,
                     rule: Rule) -> bool:
        """A read-back of the resource must sit in an artifact that also holds this request's own records.

        Exports and inventories are batch artifacts: an identity-free record seen in one belongs to a
        request already anchored there. A resource no artifact covers is acceptable only when the
        request has nothing to cite (an incomplete case proposing future verification).
        """
        observed = {o.evidence_id for o in self.index.by_resource.get(resource, []) if o.eligible(request.audit_at)}
        if not observed:
            return not required or self._absence_provable(resource, request, content, rule)
        anchors = {o.evidence_id for o in content["observations"] if o.evidence_id}
        return bool(observed & anchors)

    def _absence_provable(self, resource: str, request: Request, content: dict[str, Any], rule: Rule) -> bool:
        """A complete inventory anchored to this request that omits the resource proves its absence.

        This mirrors EvidenceIndex._negative_lookups, which cites that inventory once the link exists.
        """
        aliases = set(content["subject"].identifiers)
        anchored = {o.evidence_id for o in content["observations"] if set(o.identifiers) & aliases}
        for scope in self.index.scopes:
            if (not scope.complete or utc(scope.observed_at) > utc(request.audit_at) or resource in scope.resources
                    or scope.system_id not in (rule.system_id, "*") or scope.category not in (rule.category, "*")):
                continue
            if scope.evidence_id in anchored or scope.replica.startswith("customer_profiles_"):
                return True
        return False

    def _link_observations(self, link: Link, request: Request) -> list[Observation]:
        return [o for o in self.index.by_resource.get(link.resource_id, []) if o.eligible(request.audit_at)]

    @staticmethod
    def _unique_assignment(edges: dict[str, set[str]]) -> dict[str, str]:
        """Keep only edges present in every complete assignment of their connected group.

        A group with no complete matching proves no ownership. In particular, two requests
        sharing one sole candidate must never be resolved by request iteration order.
        """
        claimants: dict[str, set[str]] = defaultdict(set)
        for case_id, resources in edges.items():
            for resource in resources:
                claimants[resource].add(case_id)

        def matching(cases: set[str], forbidden: tuple[str, str] | None = None) -> dict[str, str] | None:
            owner: dict[str, str] = {}
            def augment(case_id: str, seen: set[str]) -> bool:
                for resource in sorted(edges[case_id]):
                    if resource in seen or (case_id, resource) == forbidden:
                        continue
                    seen.add(resource)
                    if resource not in owner or augment(owner[resource], seen):
                        owner[resource] = case_id
                        return True
                return False
            for case_id in sorted(cases):
                if not augment(case_id, set()):
                    return None
            return {case_id: resource for resource, case_id in owner.items()}

        assigned: dict[str, str] = {}
        remaining = set(edges)
        while remaining:
            group, frontier = set(), [min(remaining)]
            while frontier:
                case_id = frontier.pop()
                if case_id in group:
                    continue
                group.add(case_id)
                frontier.extend(other for resource in edges[case_id] for other in claimants[resource] - group)
            remaining -= group
            candidate = matching(group)
            if candidate is not None:
                for case_id, resource in candidate.items():
                    if matching(group, (case_id, resource)) is None:
                        assigned[case_id] = resource
        return assigned

    @staticmethod
    def _pair_tiebreak(edges: dict[str, set[str]], proven: dict[str, str]) -> dict[str, str]:
        """Heuristic, not proof: two requests that share the same two candidate resources.

        No participant-visible signal separates them, so the pair is matched in sorted order. Each
        link is right about half the time; it is marked ``-tiebreak`` and documented as a heuristic.
        """
        used = set(proven.values())
        open_edges = {c: r - used for c, r in edges.items() if c not in proven}
        assigned: dict[str, str] = {}
        for resources in {frozenset(r) for r in open_edges.values() if len(r) == 2}:
            cases = sorted(c for c, r in open_edges.items() if r and r & resources)
            if len(cases) == 2 and all(frozenset(open_edges[c]) == resources for c in cases):
                assigned.update(zip(cases, sorted(resources)))
        return assigned

    # -- discovery hook --------------------------------------------------------------------
    @staticmethod
    def synthetic(link: Link, request: Request) -> Observation:
        """Planning target for a linked resource that no readback covers.

        It asserts nothing about state: the planner can verify it later but never cite it.
        """
        return Observation(
            observation_id=f"inferred-{link.activity_id}", evidence_id="", locator=f"activity:{link.activity_id}",
            system_id=link.system_id, resource_id=link.resource_id, category=link.category,
            observed_at=request.audit_at, captured_at=request.audit_at, state="ABSENT", identifiers=[],
            fields={"workflow_link": link.rule, "activity_id": link.activity_id}, kind="inferred")
