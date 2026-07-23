from pydantic import BaseModel

# Used for Admin Provisioning
class Employee(BaseModel):
    employee_id: str
    name: str
    password: str
    role: str = "User"

# Used for Simulator Login
class EmployeeLogin(BaseModel):
    employee_id: str
    password: str