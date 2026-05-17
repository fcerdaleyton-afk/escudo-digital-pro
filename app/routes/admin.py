from fastapi import APIRouter
router = APIRouter()

@router.get("/status")
async def admin_status():
    return {"admin": "active"}
