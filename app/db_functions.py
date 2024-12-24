# app/db_functions.py
import random
import string
import csv
from .models import Company, User, Role, Employees, ReimbursementRequest, ApprovalWorkflow
from .extensions import db, mail  # Import db and mail from extensions.py
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from .config import Config  # Import the Config class

def configure_mail(app):
    """Configure Flask-Mail with the app."""
    app.config['MAIL_SERVER'] = Config.MAIL_SERVER  # Load from Config
    app.config['MAIL_PORT'] = Config.MAIL_PORT  # Load from Config
    app.config['MAIL_USE_TLS'] = Config.MAIL_USE_TLS  # Load from Config
    app.config['MAIL_USERNAME'] = Config.MAIL_USERNAME  # Load from Config
    app.config['MAIL_PASSWORD'] = Config.MAIL_PASSWORD  # Load from Config
    app.config['MAIL_DEFAULT_SENDER'] = Config.MAIL_DEFAULT_SENDER  # Load from Config
    mail.init_app(app)


def generate_random_password(length=12):
    """Generate a random password with a mix of letters, digits, and punctuation."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def insert_company(company_name, address, contact_email):
    new_company = Company(
        CompanyName=company_name,
        Address=address,
        ContactEmail=contact_email
    )
    db.session.add(new_company)
    db.session.commit()
    return new_company.CompanyID

def insert_user(email, password_hash, role, company_id):
    new_user = User(
        Email=email,
        PasswordHash=password_hash,
        Role=role,
        CompanyID=company_id
    )
    db.session.add(new_user)
    db.session.commit()

def send_email(recipient, subject, body):
    """Send an email with the given subject and body to the recipient."""
    msg = Message(subject, recipients=[recipient])
    msg.html = body
    mail.send(msg)

def send_bulk_emails(recipients, subject):
    for recipient in recipients:
        body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to Your Company!</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #372c2e;
                    color: #ffffff;
                    margin: 0;
                    padding: 0;
                }}
                .email-container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #563727;
                    border-radius: 10px;
                    overflow: hidden;
                }}
                .header {{
                    background-color: #de9e48;
                    padding: 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: #ffffff;
                    font-size: 24px;
                    margin: 0;
                }}
                .content {{
                    padding: 20px;
                }}
                .content p {{
                    font-size: 16px;
                    line-height: 1.5;
                    color: #ffffff;
                }}
                .cta {{
                    display: block;
                    text-align: center;
                    margin: 20px 0;
                }}
                .cta a {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #de9e48;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                }}
                .footer {{
                    background-color: #7a431d;
                    padding: 10px;
                    text-align: center;
                }}
                .footer p {{
                    font-size: 12px;
                    color: rgba(255, 255, 255, 0.7);
                    margin: 0;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <h1>Welcome to Your Company!</h1>
                </div>
                <div class="content">
                    <p>Dear {recipient['name']},</p>
                    <p>Your company account has been successfully created!</p>
                    <p><strong>Email:</strong> {recipient['email']}</p>
                    <p><strong>Password:</strong> {recipient['password']}</p>
                    <p>Please keep your login credentials secure and do not share them with others.</p>
                    <div class="cta">
                        <a href="#">Login to Your Account</a>
                    </div>
                    <p>If you have any questions, feel free to reach out to our support team.</p>
                    <p>Best regards,<br>Your Company Team</p>
                </div>
                <div class="footer">
                    <p>© 2024 Your Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create the email message
        msg = Message(
            subject=subject,
            recipients=[recipient['email']],  # Set the recipient email
            html=body  # Use the HTML body for the email
        )
        
        # Send the email
        try:
            mail.send(msg)
            print(f"Email sent to {recipient['email']}")
        except Exception as e:
            print(f"Failed to send email to {recipient['email']}: {str(e)}")

def get_roles_by_company(company_id):
    return Role.query.filter_by(CompanyID=company_id).all()

def add_role(role_name, company_id, permission_level):
    new_role = Role(RoleName=role_name, CompanyID=company_id, PermissionLevel=permission_level)
    db.session.add(new_role)
    db.session.commit()
    return new_role

def delete_role(role_id):
    role = Role.query.get(role_id)
    if role:
        db.session.delete(role)
        db.session.commit()
        return True
    return False

def populate_roles_and_employees(file_stream, company_id): 
    # Read CSV file
    reader = csv.DictReader(file_stream)
    role_name_to_role_id = {}
    roles_inserted = set()  # To avoid inserting duplicates
    employees = []  # Collect employee data for sending emails
    employee_id_to_company_id = {}

    # First Pass - Insert Users
    for row in reader:
        # Normalize keys by stripping spaces and converting to lowercase
        normalized_row = {key.strip().lower(): value for key, value in row.items()}
        
        employee_email = normalized_row['employeeemail']
        employee_password = generate_random_password(length=12) 
        password_hash = generate_password_hash(employee_password)  # Create a password hash

        new_user = User(
            Email=employee_email,
            PasswordHash=password_hash,
            Role='Employee',  # Set appropriate role or adjust as necessary
            CompanyID=company_id
        )
        db.session.add(new_user)
        db.session.commit()

        # Store employee details for sending emails
        employees.append({
            'name': normalized_row['employeename'],
            'email': employee_email,
            'password': employee_password  # Store plain password before hashing
        })
        
        # Store the mapping for later use
        employee_id_to_company_id[normalized_row['companyemployeeid']] = new_user.UserID

    # Reset file stream for second pass
    file_stream.seek(0)
    reader = csv.DictReader(file_stream)

    # Second Pass - Insert Roles
    for row in reader:
        normalized_row = {key.strip().lower(): value for key, value in row.items()}
        
        role_name = normalized_row['rolename']  # Adjusted to lowercase
        permission_level = normalized_row['permissionlevel']  # Adjusted to lowercase
        
        if role_name not in roles_inserted:
            # Insert into Roles table
            new_role = Role(RoleName=role_name, CompanyID=company_id, PermissionLevel=permission_level)
            db.session.add(new_role)
            db.session.commit()
            role_name_to_role_id[role_name] = new_role.RoleID  # Store mapping
            roles_inserted.add(role_name)  # Mark this role as inserted

    # Reset file stream again for third pass
    file_stream.seek(0)  # Reset file stream for the third pass
    reader = csv.DictReader(file_stream)

    # Third Pass - Insert Employees and Update Manager IDs
    for row in reader:
        normalized_row = {key.strip().lower(): value for key, value in row.items()}  # Normalize again
        
        company_employee_id = normalized_row['companyemployeeid']  # Adjusted to lowercase
        name = normalized_row['employeename']  # Adjusted to lowercase
        email = normalized_row['employeeemail']  # Adjusted to lowercase
        role_id = role_name_to_role_id.get(normalized_row['rolename'])  # Get RoleID from mapping

        # Insert into Employees table without ManagerID
        new_employee = Employees(
            CompanyID=company_id,
            CompanyEmployeeID=company_employee_id,
            Name=name,
            Email=email,
            RoleID=role_id,
            ManagerID=None  # No manager ID initially
        )
        db.session.add(new_employee)
        db.session.commit()

        # Update the employee ID mapping for later use
        employee_id_to_company_id[company_employee_id] = new_employee.EmployeeID

        # Store employee details for sending emails

    # Reset file stream again for fourth pass to update Manager IDs
    file_stream.seek(0)  # Reset file stream for the fourth pass
    reader = csv.DictReader(file_stream)
    print(employee_id_to_company_id)
    for row in reader:
        normalized_row = {key.strip().lower(): value for key, value in row.items()}  # Normalize again
        
        company_employee_id = normalized_row['companyemployeeid']  # Adjusted to lowercase
        manager_company_employee_id = normalized_row['managerid']  # Adjusted to lowercase
        
        if manager_company_employee_id:
            manager_employee_id = employee_id_to_company_id.get(manager_company_employee_id)
            if manager_employee_id:  # Check if manager exists in the mapping
                employee_to_update = Employees.query.filter_by(CompanyEmployeeID=company_employee_id).first()
                if employee_to_update:  # Check if the employee exists
                    employee_to_update.ManagerID = manager_employee_id
                    db.session.commit()

    # Return the collected employees for sending emails
    return employees

def create_reimbursement_request(data):
    """
    Inserts a new reimbursement request into the database.

    :param data: Dictionary containing request data.
    :return: Newly created ReimbursementRequest object.
    """
    try:
        new_request = ReimbursementRequest(
            EmployeeID=data['EmployeeID'],
            CompanyID=data['CompanyID'],
            ExpenseTypes=data['ExpenseTypes'],
            Amounts=data['Amounts'],
            TravelStartDate=data['TravelStartDate'],
            TravelEndDate=data['TravelEndDate'],
            Purpose=data['Purpose'],
            Description=data['Description'],
            Receipts=data['Receipts']
        )
        db.session.add(new_request)
        db.session.commit()
        return new_request
    except Exception as e:
        db.session.rollback()
        raise e
    
def get_approval_hierarchy(employee_id, company_id):
    """
    Retrieves the approval hierarchy for a given employee.
    
    :param employee_id: EmployeeID of the requester.
    :param company_id: CompanyID of the requester.
    :return: List of tuples [(ManagerID, PermissionLevel), ...] sorted by PermissionLevel.
    """
    try:
        # Get the immediate manager of the employee
        employee = Employees.query.filter_by(EmployeeID=employee_id, CompanyID=company_id).first()
        if not employee:
            raise ValueError("Employee not found")

        manager_hierarchy = []
        current_manager_id = employee.ManagerID

        while current_manager_id:
            manager = Employees.query.filter_by(EmployeeID=current_manager_id, CompanyID=company_id).first()
            if not manager:
                break

            role = Role.query.filter_by(RoleID=manager.RoleID, CompanyID=company_id).first()
            if role:
                manager_hierarchy.append((manager.EmployeeID, role.PermissionLevel))

            current_manager_id = manager.ManagerID  # Move to the next manager in the hierarchy

        # Sort by PermissionLevel (ascending)
        manager_hierarchy.sort(key=lambda x: x[1])
        return manager_hierarchy
    except Exception as e:
        raise e

def create_approval_workflow(request_id, approval_hierarchy):
    """
    Populates the ApprovalWorkflow table based on the approval hierarchy.

    :param request_id: RequestID for the reimbursement request.
    :param approval_hierarchy: List of tuples [(ManagerID, PermissionLevel), ...].
    """
    try:
        sequence = 1
        for approver_id, _ in approval_hierarchy:
            new_workflow = ApprovalWorkflow(
                RequestID=request_id,
                ApproverID=approver_id,
                Sequence=sequence,
                Status='Pending'
            )
            db.session.add(new_workflow)
            sequence += 1
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e

def get_requests_by_employee(employee_id):
    try:
        # Get all request IDs for the given employee from the ApprovalWorkflow table
        request_ids = db.session.query(ApprovalWorkflow.RequestID).filter_by(ApproverID=employee_id).all()
        request_ids = [request_id[0] for request_id in request_ids]  # Extract the IDs from the tuples

        if not request_ids:
            return []  # No requests found

        # Get all reimbursement request details for those request IDs
        requests = ReimbursementRequest.query.filter(ReimbursementRequest.RequestID.in_(request_ids)).all()
        return requests
    except Exception as e:
        raise e

def get_previous_approver_status(request_id, employee_id): 
    # Fetch all approval workflows for the given request ID
    approvals = ApprovalWorkflow.query.filter_by(RequestID=request_id).order_by(ApprovalWorkflow.Sequence).all()
    print("Approvals fetched for RequestID {}: {}".format(request_id, approvals))

    # If there are no approvals found, this means this is the first approver
    if not approvals:
        print("No approvals found for RequestID {}, returning True".format(request_id))
        return True  # No previous approvers, so return True

    # Find the approval for the current employee
    current_approver = None
    for approval in approvals:
        print("Checking approval for ApproverID {}: {}".format(approval.ApproverID, approval.Status))
        if approval.ApproverID == employee_id:
            current_approver = approval
            break

    # If the employee is not found in the approvals, return False or handle as needed
    if current_approver is None:
        print("EmployeeID {} not found in approvals for RequestID {}, returning False".format(employee_id, request_id))
        return False

    # Check the sequence of the current approver
    if current_approver.Sequence == 1:
        print("ApproverID {} is the first approver for RequestID {}, returning True".format(employee_id, request_id))
        return True  # First approver always returns True

    # Check the previous approver's status
    previous_approver = approvals[current_approver.Sequence - 2]  # Get the previous approval
    print("Checking previous approver status for ApproverID {}: {}".format(previous_approver.ApproverID, previous_approver.Status))

    if previous_approver.Status == 'Approved':
        print("Previous approver (ID {}) has approved for RequestID {}, returning True".format(previous_approver.ApproverID, request_id))
        return True
    else:
        print("Previous approver (ID {}) has not approved for RequestID {}, returning False".format(previous_approver.ApproverID, request_id))
        return False  # Previous approver has not approved


def handle_approval_rejection(request_id, action, employee_id):
    """
    Handle the approval or rejection of a reimbursement request.

    :param request_id: ID of the reimbursement request.
    :param action: 'approve' or 'reject'.
    :param employee_id: ID of the employee taking the action.
    :return: Tuple containing response message and status code.
    """
    # Fetch all workflows for the given request ID
    workflows = ApprovalWorkflow.query.filter_by(RequestID=request_id).all()

    # Check if there are any workflows
    if not workflows:
        return "No workflows found for the request ID", 404

    # Find the specific workflow for the employee ID
    current_workflow = None
    for workflow in workflows:
        if workflow.ApproverID == employee_id:
            current_workflow = workflow
            break

    # If no matching workflow found for the employee ID
    if not current_workflow:
        return "Employee is not an approver for this request", 403

    # Determine if this is the last approver
    is_last_approver = (current_workflow.Sequence == len(workflows))

    # Set the status based on the action value
    if action == "approve":
        current_workflow.Status = "Approved"
    elif action == "reject":
        current_workflow.Status = "Rejected"
    else:
        return "Invalid action specified", 400  # Handle invalid action

    # Commit the changes to the workflow
    db.session.commit()

    # If this is the last approver, update the request status as well
    if is_last_approver:
        reimbursement_request = ReimbursementRequest.query.get(request_id)
        reimbursement_request.Status = current_workflow.Status  # Sync the request status with the workflow status
        db.session.commit()

    return "Request processed successfully", 200

