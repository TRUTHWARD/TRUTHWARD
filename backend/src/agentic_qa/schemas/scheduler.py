# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from pydantic import BaseModel


class SchedulerAutomationRequest(BaseModel):
    runAt: datetime | None = None
