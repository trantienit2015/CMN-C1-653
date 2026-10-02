"""AgentCore Platform v1.0 — CMN-C1-653 AWSIAMPermissionAuditAgent graph.

Cat 1 — single technical capability (AWS IAM least-privilege + FISC/ISMAP audit),
generic and use-case-agnostic. Flat 3-slot AgentBaseGraph pipeline (NOT a Cat 2
GraphNode/inner-subgraph composition):

  START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
                                      \\_ (RETRY, max 3) _/ pre_process

  pre_process  = Step 1 InputValidate   (S-1 INTERNAL + S-2 credential scan)
  main         = Steps 2-5              (IAMPolicyFetch / LeastPrivilegeCheck /
                                          FISCCloudCheck / RemediationReport)
  post_process = Step 6 OutputValidate  (S-3 identifier redaction + S-4)
"""

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.main_node import MainNode
from src.nodes.post_process_node import OutputValidateNode
from src.nodes.pre_process_node import InputValidateNode
from src.schemas.state import State


class Graph(AgentBaseGraph):
    """AWS IAM least-privilege + FISC/ISMAP cloud governance audit agent."""

    @property
    def name(self) -> str:
        return "cmn-c1-653"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        llm = self.config.get("llm")
        iam_client = self.config.get("iam_client")

        self._nodes["pre_process"] = InputValidateNode()
        self._nodes["main"] = MainNode(llm=llm, iam_client=iam_client)
        self._nodes["post_process"] = OutputValidateNode()
