# SPDX-License-Identifier: Apache-2.0
from pydantic import BaseModel


class ApprovalDecisionRequest(BaseModel):
    comment: str | None = None
