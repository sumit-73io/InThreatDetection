import asyncio
import random
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorClient

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.core.config import settings
from app.services.anomaly_engine import ROLE_NORMAL_ACTIONS
from app.services.quantum_crypto import quantum_engine
import hashlib

async def main():
    print("Connecting to MongoDB...")
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.DATABASE_NAME]
    # No need to initialize quantum_engine here, script just creates synthetic hashes.
    print("Fetching employees...")
    cursor = db["employees"].find({}, {"_id": 0, "password": 0})
    employees = await cursor.to_list(length=1000)
    
    if not employees:
        print("No employees found. Please create some employees in the UI first.")
        return

    print(f"Found {len(employees)} employees. Generating 14 days of synthetic baseline data...")
    
    activities_to_insert = []
    api_logs_to_insert = []
    
    now = datetime.now(timezone.utc)
    
    for emp in employees:
        emp_id = emp["employee_id"]
        role = emp.get("role", "User")
        
        # Get normal actions for this role (excluding LOGIN/LOGOUT which we handle specifically)
        normal_actions = list(ROLE_NORMAL_ACTIONS.get(role, {"VIEW_CUSTOMER"}))
        normal_actions = [a for a in normal_actions if a not in ("LOGIN", "LOGOUT", "FAILED_LOGIN")]
        if not normal_actions:
            normal_actions = ["VIEW_CUSTOMER"]
            
        for days_ago in range(14, 0, -1):
            # Base date for this iteration
            base_date = now - timedelta(days=days_ago)
            
            # Login time: between 8:00 and 9:30 AM UTC
            login_hour = random.randint(8, 9)
            login_minute = random.randint(0, 59)
            login_time = base_date.replace(hour=login_hour, minute=login_minute, second=0, microsecond=0)
            
            # Logout time: between 4:00 and 6:00 PM UTC
            logout_hour = random.randint(16, 17)
            logout_minute = random.randint(0, 59)
            logout_time = base_date.replace(hour=logout_hour, minute=logout_minute, second=0, microsecond=0)
            
            # Helper to create an activity log
            def create_activity(action, timestamp):
                # Generate a dummy hash so it passes quantum checks if needed
                data_str = f"{emp_id}{action}{timestamp.isoformat()}192.168.1.100"
                full_hash = hashlib.sha256(data_str.encode()).hexdigest()
                return {
                    "employee_id": emp_id,
                    "action": action,
                    "timestamp": timestamp.isoformat(),
                    "device_ip": "192.168.1.100",
                    "details": "Synthetic Training Data",
                    "risk_score": 0,
                    "integrity_hash": full_hash,
                    "integrity_hash_short": full_hash[:8],
                    "integrity_verified": "verified"
                }
            
            # Helper to create an API log
            def create_api_log(path, timestamp, method="POST"):
                return {
                    "method": method,
                    "path": path,
                    "identity": emp_id,
                    "status_code": 200,
                    "timestamp": timestamp.isoformat()
                }

            # 1. Add LOGIN
            activities_to_insert.append(create_activity("LOGIN", login_time))
            api_logs_to_insert.append(create_api_log("/api/employees/login", login_time, "POST"))
            
            # 2. Add random normal actions during the day
            num_actions = random.randint(5, 15)
            for _ in range(num_actions):
                # Random time between login and logout
                total_seconds = int((logout_time - login_time).total_seconds())
                random_seconds = random.randint(1, total_seconds - 1)
                action_time = login_time + timedelta(seconds=random_seconds)
                action = random.choice(normal_actions)
                
                activities_to_insert.append(create_activity(action, action_time))
                api_logs_to_insert.append(create_api_log(f"/api/activities/synthetic", action_time, "POST" if action != "VIEW_CUSTOMER" else "GET"))
                
            # 3. Add LOGOUT
            activities_to_insert.append(create_activity("LOGOUT", logout_time))
            api_logs_to_insert.append(create_api_log("/api/employees/logout", logout_time, "POST"))

    print(f"Prepared {len(activities_to_insert)} activities and {len(api_logs_to_insert)} API logs.")
    
    if activities_to_insert:
        await db["activities"].insert_many(activities_to_insert)
    if api_logs_to_insert:
        await db["api_access_logs"].insert_many(api_logs_to_insert)
        
    print("Training data generated successfully! The Anomaly Engine now has a strong baseline.")
    
if __name__ == "__main__":
    asyncio.run(main())
