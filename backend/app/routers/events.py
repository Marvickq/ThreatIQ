import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from sqlmodel import Session

from app.auth.deps import resolve_principal
from app.database import engine
from app.errors import AppError
from app.events import bus

router = APIRouter(tags=["events"])

HEARTBEAT_SECONDS = 15


@router.get("/events/stream", summary="Server-Sent Events: live alerts and job progress for the caller's organization")
async def stream(request: Request) -> StreamingResponse:
    # Authenticate with a short-lived DB session, then release it so a long-lived stream does not pin a connection.
    with Session(engine) as session:
        principal = resolve_principal(request, session)
    if not principal.can("alerts:read"):
        raise AppError("FORBIDDEN", "You do not have permission to view live updates.", 403)
    sub_id, queue = bus.subscribe(principal.organization_id)

    async def events():
        try:
            yield "retry: 5000\n\n: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield f"event: {message['type']}\ndata: {json.dumps(message['data'], default=str)}\n\n"
        finally:
            bus.unsubscribe(sub_id)

    return StreamingResponse(
        events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
