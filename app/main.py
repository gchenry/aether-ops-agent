"""
FastAPI Application Entrypoint for Cloud Run & Gemini Enterprise Agent Runtime
"""
import os
import httpx
from fastapi import FastAPI, Depends, Header, status
from pydantic import BaseModel
from app.config import settings
from app.auth import verify_agent_identity
from app.agent import run_agent_turn, _get_gcp_access_token_and_project
from app.memory import session_store

app = FastAPI(
    title="Aether Ops Agent Service",
    version="2.0.0",
    description="Autonomous Multi-Agent Security & Release Gate for Google Cloud"
)


class AgentRequest(BaseModel):
    prompt: str
    session_id: str = "default-session"


class ReasoningEngineInvokeRequest(BaseModel):
    prompt: str
    session_id: str = "default-session"
    spiffe_authorization: str


class AgentResponse(BaseModel):
    response: str
    session_id: str
    actor_spiffe_id: str
    status: str


@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    res = {
        "status": "healthy",
        "service": "aether-ops-agent",
        "environment": settings.ENVIRONMENT,
        "model": settings.GEMINI_MODEL,
    }
    re_id = os.getenv("REASONING_ENGINE_ID", "")
    if re_id:
        res["reasoning_engine_id"] = re_id
    return res


@app.post("/api/v1/agent/invoke", response_model=AgentResponse)
def invoke_agent(
    req: AgentRequest,
    authorization: str = Header(None),
    auth_ctx: dict = Depends(verify_agent_identity),
):
    re_id = os.getenv("REASONING_ENGINE_ID", "").strip()
    if re_id and os.getenv("RUNNING_IN_REASONING_ENGINE", "").lower() != "true":
        access_token, project_id = _get_gcp_access_token_and_project()
        re_short_id = re_id.split("/")[-1]
        re_url = (
            f"https://us-central1-aiplatform.googleapis.com/reasoningEngines/v1/"
            f"projects/{project_id}/locations/us-central1/reasoningEngines/{re_short_id}/api/re-invoke"
        )
        with httpx.Client(timeout=60.0) as client:
            re_resp = client.post(
                re_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-Goog-User-Project": project_id,
                },
                json={
                    "prompt": req.prompt,
                    "session_id": req.session_id,
                    "spiffe_authorization": authorization or "",
                },
            )
            if re_resp.status_code == 200:
                return AgentResponse(**re_resp.json())
            raise RuntimeError(
                f"Gemini Enterprise Agent Runtime invocation failed (HTTP {re_resp.status_code}): {re_resp.text}"
            )

    actor_id = auth_ctx.get("spiffe_id", auth_ctx.get("sub", "anonymous"))

    # Save user message to decoupled store
    session_store.append_message(req.session_id, "user", req.prompt)

    # Run agent loop
    agent_output = run_agent_turn(req.prompt, actor_id=actor_id, session_id=req.session_id)

    # Save assistant response to decoupled store
    session_store.append_message(req.session_id, "assistant", agent_output)

    return AgentResponse(
        response=agent_output,
        session_id=req.session_id,
        actor_spiffe_id=actor_id,
        status="SUCCESS",
    )


@app.post("/re-invoke", response_model=AgentResponse)
def invoke_agent_in_runtime(req: ReasoningEngineInvokeRequest):
    """Entrypoint invoked inside Gemini Enterprise Agent Runtime governed by Agent Gateway."""
    auth_ctx = verify_agent_identity(authorization=req.spiffe_authorization)
    actor_id = auth_ctx.get("spiffe_id", auth_ctx.get("sub", "anonymous"))

    session_store.append_message(req.session_id, "user", req.prompt)
    agent_output = run_agent_turn(req.prompt, actor_id=actor_id, session_id=req.session_id)
    session_store.append_message(req.session_id, "assistant", agent_output)

    return AgentResponse(
        response=agent_output,
        session_id=req.session_id,
        actor_spiffe_id=actor_id,
        status="SUCCESS",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=True)


