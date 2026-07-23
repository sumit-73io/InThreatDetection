import os
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
from app.routers.auth import verify_admin
from google import genai 

router = APIRouter(prefix="/api/ai", tags=["AI Engine"])

# 1. Load the secrets from your existing .env file
load_dotenv()

# 2. Fetch the key out of system memory securely
API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("GEMINI_API_KEY is missing from your environment variables!")

# 3. Spin up the modern AI client cleanly
client = genai.Client(api_key=API_KEY)

# 2. Define the expected payload from the frontend
class ThreatAnalysisRequest(BaseModel):
    employee_id: str
    role: str
    risk_score: int
    timeline: List[Dict[str, Any]]

# 3. The Analysis Route
@router.post("/analyze", dependencies=[Depends(verify_admin)])
async def generate_threat_report(req: ThreatAnalysisRequest):
    try:
        # Construct the strict prompt for the LLM
        prompt = f"""
        You are an elite Lead Cybersecurity Analyst reviewing a User and Entity Behavior Analytics (UEBA) log.
        
        USER CONTEXT:
        - Employee ID: {req.employee_id}
        - Role: {req.role}
        - Total Risk Score: {req.risk_score}
        
        ACTIVITY TIMELINE (Chronological JSON):
        {req.timeline}
        
        TASK:
        Analyze this timeline and write a highly concise, professional 3-paragraph forensic report.
        1. Context: What did the user do chronologically?
        2. Threat Assessment: Does this align with their role ({req.role}), or is it suspicious? (e.g. HR downloading code, or a dev downloading payroll).
        3. Recommendation: What should the SOC do? (e.g. Isolate endpoint, force password reset, or mark as false positive).
        
        Keep it sharp, technical, and under 150 words. Do not use markdown headers.
        """
        
        # Call the LLM using the NEW syntax
        response = client.models.generate_content(
            model='gemini-3.5-flash', 
            contents=prompt
        )
        
        return {"status": "success", "analysis": response.text}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Engine Error: {str(e)}")
    