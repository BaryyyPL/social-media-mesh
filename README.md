# Social Media Service Mesh
## Python-based decentralized microservices platform implementing custom Service Mesh architecture. No Kubernetes required!

----------
### Quick Start
#### 1. Clone & setup
git clone https://github.com/BaryyyPL/social-media-mesh.git
cd social-media-mesh
python -m venv venv

#### Windows
venv\Scripts\activate
#### Mac/Linux
source venv/bin/activate

pip install -r requirements.txt

#### 2. Start XAMPP → MySQL
#### (Ensure MySQL is running on port 3306)

#### 3. Run components (separate terminals):
python manager.py
python agent_auth.py
python agent_file.py
python agent_post.py
python api_gateway.py

#### 4. Connect client:
python client.py

----------
### What It Does
- User accounts: Register, login, delete
- Text posts: Create and browse posts
- File sharing: Upload/download any files
- Secure comms: AES-256 + RSA encryption

----------
### Architecture
Client → API Gateway → Manager → [Agents] → [Services] → MySQL

- manager.py - Brain of the system (control plane)
- agent_*.py - Service managers (auth/file/post)
- service_*.py - Business logic microservices
- api_gateway.py - Single entry point
- client.py - User interface

----------
### Security Features
- Custom handshake protocol (PGP-like)
- AES-256 for data encryption
- RSA for key exchange
- bcrypt password hashing
- Database encryption at rest

----------
### Testing
- After running all components:
- Register new user
- Login
- Create post
- Upload file
- Browse content

----------
### About
Engineering thesis project - University of Siedlce, 2026
"Design and Implementation of Decentralized Communication Infrastructure in Cloud Computing"
