from flask import Blueprint, request, jsonify
import jwt, datetime, csv, traceback
from io import StringIO
from werkzeug.security import generate_password_hash
from .db_functions import insert_company, insert_user, send_email, generate_random_password, get_roles_by_company, add_role, delete_role, populate_roles_and_employees, send_bulk_emails,create_reimbursement_request, get_approval_hierarchy, create_approval_workflow, get_requests_by_employee,get_previous_approver_status, handle_approval_rejection
from .models import Company, User, Employees, Role, ReimbursementRequest
from .config import Config

main = Blueprint('main', __name__)
SECRET_KEY = Config.SECRET_KEY

# Dummy users with roles

@main.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    print(f"Received login request for email: {email}")  # Log the received email

    # Check if the user is the fixed product admin
    if email == 'admin@reimburse.com' and password == 'admin2311':
        token = jwt.encode(
            {
                'email': email,
                'role_id': 'productAdmin',
                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm='HS256'
        )
        print('Generated Token for Product Admin:', token)  # Log the generated token
        return jsonify({'token': token, 'user': {'email': email, 'name': 'Product Admin', 'role_id': 'productAdmin'}})

    # For other users, query the database
    user = User.query.filter_by(Email=email).first()  # Fetch user by email
    print(f"User found in database: {user}")  # Log the user object (it will print None if not found)

    # Validate user and password
    if user:
        print(f"User role: {user.Role}, Company ID: {user.CompanyID}")  # Log user role and company ID
        if user.verify_password(password):  # Use the verify_password method
            if user.Role == 'companyAdmin':
                # Handle companyAdmin login
                token = jwt.encode(
                    {
                        'email': email,
                        'role_id': user.Role,
                        'company_id': user.CompanyID,
                        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                    },
                    SECRET_KEY,
                    algorithm='HS256'
                )
                print('Generated Token for Company Admin:', token)  # Log the generated token
                return jsonify({'token': token, 'user': {'email': email, 'role_id': user.Role, 'company_id': user.CompanyID}})

            elif user.Role == 'Employee':
                # Handle employee login
                # Assuming you have an Employee model and Role model
                employee = Employees.query.filter_by(Email=email, CompanyID=user.CompanyID).first()
                
                if employee:
                    # Fetch role details from the roles table
                    role = Role.query.filter_by(RoleID=employee.RoleID).first()
                    if role:
                        token = jwt.encode(
                            {
                                'email': email,
                                'role_id': employee.RoleID,
                                'employee_id': employee.EmployeeID,
                                'permission_level': role.PermissionLevel,
                                'company_id': user.CompanyID,
                                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                            },
                            SECRET_KEY,
                            algorithm='HS256'
                        )
                        print('Generated Token for Employee:', token)  # Log the generated token
                        return jsonify({'token': token, 'user': {'email': email, 'role_id': employee.RoleID,'employee_id': employee.EmployeeID, 'permission_level': role.PermissionLevel, 'company_id': user.CompanyID}})

                print(f"No employee found for email: {email} in company ID: {user.CompanyID}")  # Log if no employee found
            else:
                print(f"Invalid role for user: {email}")  # Log if the role is not recognized
        else:
            print(f"Invalid password for user: {email}")  # Log invalid password attempt
    else:
        print(f"No user found for email: {email}")  # Log if no user is found

    return jsonify({'message': 'Invalid credentials'}), 401




@main.route('/validate-token', methods=['GET'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return jsonify({'message': 'Authorization header is missing'}), 401

    try:
        token = auth_header.split(' ')[1]  # Extract the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if decoded['role_id'] == 'productAdmin':
            company_id = ''  # Set to empty string for Product Admin
        else:
            company_id = decoded['company_id']  # Use company_id for other roles
        return jsonify({'user': {'email': decoded['email'], 'role_id': decoded['role_id'], 'company_id': company_id}})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        print(f"Invalid token error: {str(e)}")  # Log the specific error
        return jsonify({'message': 'Invalid token'}), 401


@main.route('/create-company', methods=['POST'])
def create_company():
    data = request.json
    company_name = data.get('companyName')
    address = data.get('address')
    contact_email = data.get('contactEmail')
    admin_email = data.get('adminEmail')

    # Generate a password for the company admin
    admin_password = generate_random_password(length=12)
    hashed_password = generate_password_hash(admin_password)

    # Insert company into the database
    company_id = insert_company(company_name, address, contact_email)

    # Insert user as the company admin
    insert_user(admin_email, hashed_password, 'companyAdmin', company_id)

    # Prepare the email content
    subject = "Your Company Account Credentials"
    body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to {company_name}!</title>
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
                <h1>Welcome to {company_name}!</h1>
            </div>
            <div class="content">
                <p>Dear Company Admin,</p>
                <p>Your company account has been successfully created!</p>
                <p><strong>Company Name:</strong> {company_name}</p>
                <p><strong>Admin Email:</strong> {admin_email}</p>
                <p><strong>Password:</strong> {admin_password}</p>
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

    # Send the email with login credentials
    try:
        send_email(admin_email, subject, body)
    except Exception as e:
        print(f"Error sending email: {str(e)}")  # Log the error
        return jsonify({'message': 'Company created but failed to send email.'}), 201

    return jsonify({'message': 'Company created successfully!'}), 201


@main.route('/company/<int:company_id>', methods=['GET'])
def get_company_details(company_id):  # Use company_id instead of CompanyID for the parameter
    company = Company.query.filter_by(CompanyID=company_id).first()  # Use CompanyID for filtering

    if not company:
        return jsonify({'error': 'Company not found'}), 404

    # Construct the response based on the Company model attributes
    company_data = {
        'companyName': company.CompanyName,
        'companyEmail': company.ContactEmail,
        'companyAddress': company.Address
    }

    return jsonify(company_data), 200

@main.route('/companies', methods=['GET'])
def get_companies():
    companies = Company.query.all()  # Fetch all companies from the database
    company_list = [
        {
            'companyID': company.CompanyID,
            'companyName': company.CompanyName,
            'address': company.Address,
            'contactEmail': company.ContactEmail,
            'createdAt': company.CreatedAt
        }
        for company in companies
    ]
    return jsonify(company_list), 200

@main.route('/roles/<int:company_id>', methods=['GET'])
def fetch_roles(company_id):
    roles = get_roles_by_company(company_id)
    return jsonify([role.to_dict() for role in roles]), 200

@main.route('/roles', methods=['POST'])
def create_role():
    data = request.get_json()
    
    # Debug: Print the incoming JSON data
    print("Received data:", data)

    role_name = data.get('roleName')
    company_id = data.get('companyID')
    permission_level = data.get('permissionLevel')

    # Debug: Print the extracted values
    print("Role Name:", role_name)
    print("Company ID:", company_id)
    print("Permission Level:", permission_level)

    if not role_name or not company_id or permission_level is None:
        print("Error: Invalid data")
        return jsonify({'error': 'Invalid data'}), 400

    new_role = add_role(role_name, company_id, permission_level)
    return jsonify(new_role.to_dict()), 201


@main.route('/roles/<int:role_id>', methods=['DELETE'])
def remove_role(role_id):
    success = delete_role(role_id)
    if success:
        return jsonify({'message': 'Role deleted successfully'}), 200
    return jsonify({'error': 'Role not found'}), 404

@main.route('/upload-employees', methods=['POST'])
def upload_employees():
    company_id = request.form.get('companyID')  # Get company ID from the form data
    file = request.files.get('file')  # Get the uploaded file

    if not file:
        return jsonify({'message': 'No file provided.'}), 400

    try:
        # Read and decode the file contents
        contents = file.read().decode('utf-8')  # Decode the file contents
        file_stream = StringIO(contents)  # Create a stream from the string
    except Exception as e:
        return jsonify({'message': f'Error reading file: {str(e)}'}), 400

    # Process the CSV file and populate the database
    try:
        print("Received file contents:")
        print(contents)

        # Assuming populate_roles_and_employees returns a list of employees
        employees = populate_roles_and_employees(file_stream, company_id)  # Get employee details

        # Prepare to send emails to each employee
        subject = "Your Company Account Credentials"

        print("Email list for employees:")
        # Loop through the employees to print their details and prepare for sending emails
        for employee in employees:
            print(f"{employee['name']} <{employee['email']}>")
        
        # Call the send_bulk_emails function with the employee list
        send_bulk_emails(employees, subject)

        return jsonify({'message': 'Employees uploaded and emails sent successfully.'}), 200

    except Exception as e:
        print(f"Error processing CSV: {str(e)}")  # Log the error for debugging
        return jsonify({'message': str(e)}), 500
    
@main.route('/reimbursement-request', methods=['POST'])
def create_request():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = [
            "EmployeeID", "CompanyID", "ExpenseTypes", "Amounts",
            "TravelStartDate", "TravelEndDate", "Purpose", "Description", "Receipts"
        ]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Insert the request into the database
        new_request = create_reimbursement_request(data)

        # Generate approval hierarchy
        approval_hierarchy = get_approval_hierarchy(data["EmployeeID"], data["CompanyID"])
        if not approval_hierarchy:
            return jsonify({"error": "Failed to generate approval hierarchy"}), 500

        # Populate the ApprovalWorkflow table
        create_approval_workflow(new_request.RequestID, approval_hierarchy)

        return jsonify({
            "message": "Reimbursement request created successfully!",
            "RequestID": new_request.RequestID
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@main.route('/get-reimbursement-requests', methods=['POST'])  
def get_reimbursement_requests():
    try:
        # Get JSON data from the request body
        json_data = request.get_json()  # Use a different variable name
        
        # Check if data is valid
        if json_data is None:
            return jsonify({'error': 'Request body must be JSON'}), 400

        # Get companyID and employeeID from the JSON data
        company_id = json_data.get('companyID')
        employee_id = json_data.get('employeeID')

        # Check if both parameters are provided
        if not company_id or not employee_id:
            return jsonify({'error': 'companyID and employeeID are required'}), 400
        
        # Query the reimbursement requests table
        requests = ReimbursementRequest.query.filter_by(CompanyID=company_id, EmployeeID=employee_id).all()

        # Prepare the response data
        request_data = []
        for req in requests:  # Avoid using 'request' as a variable name
            request_data.append({
                'RequestID': req.RequestID,
                'EmployeeID': req.EmployeeID,
                'CompanyID': req.CompanyID,
                'ExpenseTypes': req.ExpenseTypes,
                'Amounts': req.Amounts,
                'TravelStartDate': req.TravelStartDate.isoformat(),
                'TravelEndDate': req.TravelEndDate.isoformat(),
                'Purpose': req.Purpose,
                'Description': req.Description,
                'Receipts': req.Receipts,
                'Status': req.Status,
                'SubmissionDate': req.SubmissionDate.isoformat()
            })

        return jsonify(request_data), 200
    except Exception as e:
        # Log the error for debugging
        print("Error occurred:", str(e))
        print(traceback.format_exc())  # Print the stack trace for detailed error info
        return jsonify({'error': 'An internal error occurred, please try again later.'}), 500

@main.route('/my-team-requests', methods=['POST'])
def get_my_team_requests():
    """
    Fetches reimbursement requests for the team members of a given employee.
    
    :return: JSON response with the list of requests.
    """
    try:
        data = request.get_json()
        employee_id = data.get('EmployeeID')  # Extract employee ID from the request body

        if not employee_id:
            return jsonify({"error": "Missing EmployeeID"}), 400

        # Get requests for the given employee ID
        requests = get_requests_by_employee(employee_id)

        # Prepare the response data with sequential visibility
        requests_data = []
        for req in requests:  # Change 'request' to 'req'
            # Fetch the CompanyEmployeeID from the Employee table
            employee = Employees.query.filter_by(EmployeeID=req.EmployeeID).first()
            company_employee_id = employee.CompanyEmployeeID if employee else None

            # Check if previous approvers have approved or if there are no previous approvers
            previous_approver_status = get_previous_approver_status(req.RequestID, employee_id)

            if previous_approver_status:  # All previous approvers have approved or no previous approvers
                requests_data.append({
                    "RequestID": req.RequestID,
                    "EmployeeID": req.EmployeeID,
                    "CompanyEmployeeID": company_employee_id,  # Add CompanyEmployeeID here
                    "CompanyID": req.CompanyID,
                    "ExpenseTypes": req.ExpenseTypes,
                    "Amounts": req.Amounts,
                    "TravelStartDate": req.TravelStartDate.isoformat(),
                    "TravelEndDate": req.TravelEndDate.isoformat(),
                    "Purpose": req.Purpose,
                    "Description": req.Description,
                    "Status": req.Status,
                    "SubmissionDate": req.SubmissionDate.isoformat()
                })

        return jsonify(requests_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/approve-reject', methods=['POST'])
def approve_or_reject():
    """
    Approve or reject a reimbursement request based on the employee's action.
    
    :return: JSON response indicating success or failure.
    """
    data = request.get_json()
    request_id = data.get('RequestID')
    action = data.get('Action')
    employee_id = data.get('EmployeeID')

    if not request_id or not action or not employee_id:
        return jsonify({"error": "Missing parameters"}), 400

    try:
        # Call the function to handle the approval/rejection logic
        message, status_code = handle_approval_rejection(request_id, action, employee_id)
        return jsonify({"message": message}), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

