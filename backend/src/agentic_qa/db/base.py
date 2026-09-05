# SPDX-License-Identifier: Apache-2.0
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base declarative model."""


def register_orm_metadata() -> None:
    """Import the canonical ORM module so every mapped table is registered."""
    from agentic_qa.domain import models as _domain_models

    assert _domain_models is not None
