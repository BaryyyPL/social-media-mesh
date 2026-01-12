# social-media-mesh
A modular Python microservice application implementing a service mesh architecture. Includes user authentication, post management, and file upload services with secure communication via symmetric and asymmetric encryption.

# Service Mesh App

## Overview
This project is a Python microservice platform built with a service mesh architecture. It includes services for:
- User authentication (login/registration)
- Post management (upload, read)
- File upload and management

## Architecture
- Manager: orchestrates agents and services
- Agents: handle secure communication with services
- Services: dedicated microservices with single responsibility
- Communication: secure via symmetric/asymmetric keys

## Getting Started
1. Clone the repository
```
git clone https://github.com/<your-username>/service-mesh-app.git
```

2. Set up Python environment
python -m venv .venv
source .venv/bin/activate  # Linux / Mac
.venv\Scripts\activate     # Windows
pip install -r requirements.txt

4. Configure database: service_mesh_app_db with tables users, posts, files
5. 
6. Run Manager, Agents and Clients
