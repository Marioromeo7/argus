"""
ARGUS Layer 1 — Graph Schema
=============================
Defines the Node and Edge structures that are ARGUS's core contribution.
Do NOT simplify these structures. The grain_confidence + open_questions
fields on nodes, and context_conditions + confidence on edges, are
the novel epistemological contribution of the system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class EdgeDirectionality(str, Enum):
    UNIDIRECTIONAL = "unidirectional"
    BIDIRECTIONAL  = "bidirectional"
    CONDITIONAL    = "conditional"


class NodeSource(str, Enum):
    NVD          = "nvd"
    ATTACK       = "attack"
    AGENT        = "agent_derived"
    WEB          = "web"
    CHALLENGER   = "challenger_refined"


@dataclass
class ChallengerLogEntry:
    """Records a single grain refinement event on a node or edge."""
    timestamp:    datetime
    question:     str        # the open question that triggered refinement
    proposal:     str        # what the challenger proposed
    accepted:     bool       # whether the primary agent accepted
    agent_id:     str        # which agent triggered this


@dataclass
class TemporalValidity:
    """Time window during which an edge is considered valid."""
    valid_from:   datetime
    valid_until:  Optional[datetime] = None  # None = indefinitely valid


# ── NODE ──────────────────────────────────────────────────────────────────────

@dataclass
class Node:
    """
    ARGUS-LAYER-1: Socratic Node
    A node that knows what it doesn't know about itself.
    grain_confidence drives the challenger loop — low confidence
    means the node is too coarse and needs subdivision.
    """
    # Identity
    node_id:          str
    label:            str                        # e.g. "heap_overflow_glibc_2.35"
    node_type:        str                        # "vulnerability" | "technique" | "software" | "tactic"

    # Facts
    properties:       dict = field(default_factory=dict)

    # Epistemological state — THE NOVEL PART
    grain_confidence: float = 0.1               # 0.0 = undefined, 1.0 = maximally specific
    open_questions:   list  = field(default_factory=list)  # what would make this more precise?
    challenger_log:   list  = field(default_factory=list)  # history of ChallengerLogEntry dicts

    # Provenance
    source:           str   = NodeSource.NVD
    created_at:       datetime = field(default_factory=datetime.utcnow)
    last_updated:     datetime = field(default_factory=datetime.utcnow)

    def to_neo4j(self) -> dict:
        """Serialize for Neo4j CREATE/MERGE."""
        return {
            "node_id":          self.node_id,
            "label":            self.label,
            "node_type":        self.node_type,
            "properties":       str(self.properties),   # stored as JSON string in Neo4j
            "grain_confidence": self.grain_confidence,
            "open_questions":   self.open_questions,
            "challenger_log":   str(self.challenger_log),
            "source":           self.source,
            "created_at":       self.created_at.isoformat(),
            "last_updated":     self.last_updated.isoformat(),
        }

    def needs_refinement(self, threshold: float = 0.6) -> bool:
        """True if this node's grain is not specific enough for confident retrieval."""
        return self.grain_confidence < threshold

    def add_open_question(self, question: str) -> None:
        """ARGUS-LAYER-3: Called by challenger agent when grain is insufficient."""
        if question not in self.open_questions:
            self.open_questions.append(question)
            self.last_updated = datetime.utcnow()


# ── EDGE ──────────────────────────────────────────────────────────────────────

@dataclass
class Edge:
    """
    ARGUS-LAYER-1: Conditional Edge
    An edge that carries the conditions under which it holds,
    not just a flat verb label. context_conditions and confidence
    are what make multi-hop attack reasoning precise.
    """
    # Identity
    edge_id:            str
    source_id:          str
    target_id:          str
    relation_type:      str              # "exploits" | "enables" | "mitigates" | "requires" | "patches"

    # Conditionality — THE NOVEL PART
    context_conditions: list = field(default_factory=list)   # ["only if pre-auth", "requires subnet access"]
    confidence:         float = 0.5     # updated by agent traversal outcomes
    directionality:     str   = EdgeDirectionality.UNIDIRECTIONAL
    open_questions:     list  = field(default_factory=list)  # "does this hold post-patch?"
    challenger_log:     list  = field(default_factory=list)

    # Temporal validity
    temporal_validity:  dict  = field(default_factory=lambda: {
        "valid_from":  datetime.utcnow().isoformat(),
        "valid_until": None
    })

    # Provenance
    source:             str   = NodeSource.NVD
    created_at:         datetime = field(default_factory=datetime.utcnow)
    last_updated:       datetime = field(default_factory=datetime.utcnow)

    def to_neo4j(self) -> dict:
        """Serialize for Neo4j relationship CREATE."""
        return {
            "edge_id":            self.edge_id,
            "relation_type":      self.relation_type,
            "context_conditions": self.context_conditions,
            "confidence":         self.confidence,
            "directionality":     self.directionality,
            "open_questions":     self.open_questions,
            "challenger_log":     str(self.challenger_log),
            "temporal_validity":  str(self.temporal_validity),
            "source":             self.source,
            "created_at":         self.created_at.isoformat(),
            "last_updated":       self.last_updated.isoformat(),
        }

    def is_traversable(self, context: dict, confidence_threshold: float = 0.3) -> bool:
        """
        ARGUS-LAYER-5: Called by red/blue agents before traversing.
        Returns True only if confidence is above threshold and
        all context_conditions are satisfied by the current engagement state.
        """
        if self.confidence < confidence_threshold:
            return False
        for condition in self.context_conditions:
            if condition not in context.get("satisfied_conditions", []):
                return False
        return True

    def update_confidence(self, traversal_succeeded: bool, delta: float = 0.05) -> None:
        """ARGUS-LAYER-5: Called after agent traversal. Bayesian-style confidence update."""
        if traversal_succeeded:
            self.confidence = min(1.0, self.confidence + delta)
        else:
            self.confidence = max(0.0, self.confidence - delta)
        self.last_updated = datetime.utcnow()
