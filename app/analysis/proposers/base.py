from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProposer(ABC):
   
    provider_name = "UNKNOWN"

    @abstractmethod
    def propose(
        self,
        *,
        application_name: str,
        contexts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:


        raise NotImplementedError


class StaticProposer(LLMProposer):

    @abstractmethod
    def propose(
        self,
        *,
        application_name: str,
        chunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        

        raise NotImplementedError