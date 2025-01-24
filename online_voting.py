from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from cryptography.fernet import Fernet
from datetime import timedelta
import uuid
import base64

app = Flask(__name__)

# Secret key for JWT and encryption
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Replace with a secure random key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
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

    # Convert the encrypted vote to a base64-encoded string
    encrypted_vote_base64 = base64.b64encode(encrypted_vote).decode('utf-8')

    # Generate a unique vote ID (to decouple vote from voter identity)
    vote_id = str(uuid.uuid4())

    # Store the encrypted vote
    votes.append({"vote_id": vote_id, "encrypted_vote": encrypted_vote_base64})

    return jsonify({"msg": "Vote cast successfully", "vote_id": vote_id, "encrypted_vote": encrypted_vote_base64}), 200

@app.route('/results', methods=['GET'])
def view_results():
    """View all encrypted votes (for demonstration purposes)."""
    # Convert encrypted votes to base64 strings
    result_votes = [{"vote_id": v["vote_id"], "encrypted_vote": v["encrypted_vote"]} for v in votes]
    return jsonify({"votes": result_votes}), 200

@app.route('/tally', methods=['GET'])
def tally_votes():
    """Decrypt and count votes."""
    decrypted_votes = [cipher.decrypt(base64.b64decode(v['encrypted_vote'])).decode() for v in votes]
    results = {}
    for vote in decrypted_votes:
        results[vote] = results.get(vote, 0) + 1

    return jsonify({"results": results}), 200

@app.route('/all_votes', methods=['GET'])
@jwt_required()  # Ensure the user is authenticated with a valid JWT token
def view_all_votes():
    """Return all encrypted votes (requires valid JWT token)."""
    # Convert encrypted votes to base64 strings
    result_votes = [{"vote_id": v["vote_id"], "encrypted_vote": v["encrypted_vote"]} for v in votes]
    return jsonify({"votes": result_votes}), 200

if __name__ == '__main__':
    app.run(debug=True)
