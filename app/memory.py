"""
Decoupled Session State & Memory Store with Context Boundary Hardening (3Cs: CURATE).
Supports horizontal scaling across serverless Cloud Run instances and prevents
OWASP ASI06 (Memory & Context Poisoning) via bounded sliding context windows
and pre-persistence injection quarantine.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.config import settings
from app.tools import model_armor_screen_input

MAX_CONTEXT_WINDOW = 6


class SessionStore(ABC):
    @abstractmethod
    def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def append_message(self, session_id: str, role: str, content: str) -> Dict[str, Any]:
        pass


class InMemorySessionStore(SessionStore):
    def __init__(self, max_window: int = MAX_CONTEXT_WINDOW):
        self._store: Dict[str, List[Dict[str, Any]]] = {}
        self._max_window = max_window

    def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        return list(self._store.get(session_id, []))

    def append_message(self, session_id: str, role: str, content: str) -> Dict[str, Any]:
        if session_id not in self._store:
            self._store[session_id] = []

        # OWASP ASI06 Defense: Do not allow poisoned/goal-hijack prompts to contaminate session memory
        if role == "user":
            armor_check = model_armor_screen_input(content)
            if armor_check["model_armor_status"] != "CLEAN":
                quarantined_entry = {
                    "role": role,
                    "content": "[QUARANTINED BY MODEL ARMOR — OWASP ASI06 MEMORY POISONING PREVENTED]",
                    "asi06_quarantined": True,
                }
                self._store[session_id].append(quarantined_entry)
                self._store[session_id] = self._store[session_id][-self._max_window :]
                return quarantined_entry

        entry = {"role": role, "content": content, "asi06_quarantined": False}
        self._store[session_id].append(entry)
        # Enforce strict context boundary window (3Cs: CURATE)
        self._store[session_id] = self._store[session_id][-self._max_window :]
        return entry


def get_session_store() -> SessionStore:
    # Pluggable backend: In production, switch to AlloyDB/Cloud SQL pgvector client
    return InMemorySessionStore()


session_store = get_session_store()


