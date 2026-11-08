"""AgentLedger provenance: a read-only consumer of the gateway audit stream.

Nothing here writes to the audit file, the gateway or any AWS service. It turns audit events
into a typed graph of artifacts, activities, agents, grants and humans, then answers
questions about it. A dependency link is a record of verified influence, not a share of value.
"""

from .build import Declaration, build_graph
from .evidence import acceptance_state, validate_artifact
from .impact import regression_impact, reuse_credits
from .lineage import trace_downstream, trace_upstream
from .metrics import metrics_for_workflow
from .models import Edge, Node, ProvenanceGraph

__all__ = ["Declaration", "Edge", "Node", "ProvenanceGraph", "acceptance_state", "build_graph",
           "metrics_for_workflow", "regression_impact", "reuse_credits", "trace_downstream",
           "trace_upstream", "validate_artifact"]
