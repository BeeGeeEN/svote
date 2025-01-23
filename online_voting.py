from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from cryptography.fernet import Fernet
import uuid

app = Flask(__name__)

# Secret key for JWT and encryption
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Replace with a secure random key
jwt = JWTManager(app)

# Encryption key for votes
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# In-memory database (for simplicity)
users = {"voter1": "password123"}  # username: password
votes = []  # List of encrypted votes

@app.route('/login', methods=['POST'])
def login():
    """Authenticate voter and return a JWT token."""
    username = request.json.get('username')
    password = request.json.get('password')

    if users.get(username) == password:
        access_token = create_access_token(identity=username)
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/vote', methods=['POST'])
@jwt_required()
def cast_vote():
    """Accept and encrypt a vote."""
    vote_data = request.json.get('vote')

    if not vote_data:
        return jsonify({"msg": "Vote data is required"}), 400

    # Encrypt the vote
    encrypted_vote = cipher.encrypt(vote_data.encode())

    # Generate a unique vote ID (to decouple vote from voter identity)
    vote_id = str(uuid.uuid4())

    # Store the encrypted vote
    votes.append({"vote_id": vote_id, "encrypted_vote": encrypted_vote})

    return jsonify({"msg": "Vote cast successfully", "vote_id": vote_id}), 200

@app.route('/results', methods=['GET'])
def view_results():
    """View all encrypted votes (for demonstration purposes)."""
    return jsonify({"votes": votes}), 200

if __name__ == '__main__':
    app.run(debug=True)
