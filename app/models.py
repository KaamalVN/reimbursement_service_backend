# app/models.py
from werkzeug.security import check_password_hash
from datetime import datetime
from .extensions import db  # Import db from extensions.py

class Company(db.Model):
    __tablename__ = 'companies'
    CompanyID = db.Column(db.Integer, primary_key=True)
    CompanyName = db.Column(db.String(100), nullable=False)
    Address = db.Column(db.String(200), nullable=False)
    ContactEmail = db.Column(db.String(100), nullable=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'users'
    UserID = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    PasswordHash = db.Column(db.String(200), nullable=False)
    Role = db.Column(db.String(50), nullable=False)
    CompanyID = db.Column(db.Integer, db.ForeignKey('companies.CompanyID'), nullable=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt = db.Column(db.DateTime, onupdate=datetime.utcnow)
    def verify_password(self, password):
        """Verify the provided password against the stored hash."""
        return check_password_hash(self.PasswordHash, password)

class Role(db.Model):
    __tablename__ = 'roles'
    RoleID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    RoleName = db.Column(db.String(255), nullable=False)
    CompanyID = db.Column(db.Integer, nullable=False)
    PermissionLevel = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return {
            'RoleID': self.RoleID,
            'RoleName': self.RoleName,
            'CompanyID': self.CompanyID,
            'PermissionLevel': self.PermissionLevel
        }
    
class Employees(db.Model):
    EmployeeID = db.Column(db.Integer, primary_key=True)
    CompanyID = db.Column(db.Integer, db.ForeignKey('companies.CompanyID'), nullable=False)
    CompanyEmployeeID = db.Column(db.String(50), nullable=False)
    Name = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), nullable=False)
    RoleID = db.Column(db.Integer, db.ForeignKey('roles.RoleID'), nullable=False)
    ManagerID = db.Column(db.Integer, db.ForeignKey('employees.EmployeeID'))

class ReimbursementRequest(db.Model):
    __tablename__ = 'ReimbursementRequests'

    RequestID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EmployeeID = db.Column(db.Integer, db.ForeignKey('employees.EmployeeID'), nullable=False)
    CompanyID = db.Column(db.Integer, db.ForeignKey('companies.CompanyID'), nullable=False)
    ExpenseTypes = db.Column(db.JSON, nullable=False)  # JSON array of expense types
    Amounts = db.Column(db.JSON, nullable=False)  # JSON array of amounts corresponding to expense types
    TravelStartDate = db.Column(db.Date, nullable=False)
    TravelEndDate = db.Column(db.Date, nullable=False)
    Purpose = db.Column(db.Text, nullable=False)
    Description = db.Column(db.String(255), nullable=False)
    Receipts = db.Column(db.JSON, nullable=True)  # JSON array for storing receipt paths
    Status = db.Column(db.String(50), default='Pending')
    SubmissionDate = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ReimbursementRequest(RequestID={self.RequestID}, EmployeeID={self.EmployeeID}, CompanyID={self.CompanyID}, ExpenseTypes={self.ExpenseTypes}, Amounts={self.Amounts}, TravelStartDate={self.TravelStartDate}, TravelEndDate={self.TravelEndDate}, Purpose='{self.Purpose}', Description='{self.Description}', Status='{self.Status}', SubmissionDate={self.SubmissionDate})>"


class ApprovalWorkflow(db.Model):
    __tablename__ = 'ApprovalWorkflow'

    WorkflowID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    RequestID = db.Column(db.Integer, db.ForeignKey('ReimbursementRequests.RequestID'), nullable=False)
    ApproverID = db.Column(db.Integer, db.ForeignKey('employees.EmployeeID'), nullable=False)
    Sequence = db.Column(db.Integer, nullable=False)  # Approval order
    Status = db.Column(db.String(50), default='Pending')  # Pending, Approved, Rejected
    ApprovalDate = db.Column(db.DateTime, nullable=True)  # Date of approval or rejection

    def __repr__(self):
        return f"<ApprovalWorkflow(WorkflowID={self.WorkflowID}, RequestID={self.RequestID}, ApproverID={self.ApproverID}, Sequence={self.Sequence}, Status='{self.Status}', ApprovalDate={self.ApprovalDate})>"
