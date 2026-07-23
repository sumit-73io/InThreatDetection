from fastapi import APIRouter, HTTPException, Depends
from app.models.employee import Employee, EmployeeLogin 
from app.database.mongodb import db_instance
from app.routers.auth import verify_admin
from fastapi.encoders import jsonable_encoder

router = APIRouter(prefix="/api/employees", tags=["Employees"])

# 1. ADMIN ROUTE: Create a new employee (Protected by JWT)
@router.post("/create", dependencies=[Depends(verify_admin)])
async def create_employee(emp: Employee):
    try:
        # Check if employee already exists
        existing = await db_instance.db["employees"].find_one({"employee_id": emp.employee_id})
        if existing:
            raise HTTPException(status_code=400, detail="Employee ID already exists")
        
        # Save to database
        emp_dict = jsonable_encoder(emp)
        await db_instance.db["employees"].insert_one(emp_dict)
        return {"status": "success", "message": f"Employee {emp.employee_id} provisioned."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 2. SIMULATOR ROUTE: Employee Login (Public)
@router.post("/login")
async def login_employee(emp: EmployeeLogin): 
    try:
        user = await db_instance.db["employees"].find_one({
            "employee_id": emp.employee_id, 
            "password": emp.password
        })
        if not user:
            raise HTTPException(status_code=401, detail="Invalid Employee ID or Password")
        
        return {"status": "success", "employee_id": user["employee_id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3. DIRECTORY ROUTE: Fetch all employees for the dashboard (Protected by JWT)
@router.get("/", dependencies=[Depends(verify_admin)])
async def get_all_employees():
    try:
        # Fetch all employees, but exclude their passwords and MongoDB ObjectIds
        cursor = db_instance.db["employees"].find({}, {"_id": 0, "password": 0})
        employees = await cursor.to_list(length=1000)
        return employees
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))