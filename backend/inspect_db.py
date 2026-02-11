
from app import create_app, mongo
import json
from bson import json_util

app = create_app('development')

with app.app_context():
    print("--- USERS ---")
    users = list(mongo.db.users.find({}, {'username': 1, 'email': 1, '_id': 0}))
    print(json.dumps(users, default=json_util.default, indent=2))
    
    print("\n--- PENDING REGISTRATIONS ---")
    pending = list(mongo.db.pending_registrations.find({}, {'username': 1, 'email': 1, 'status': 1, '_id': 0}))
    print(json.dumps(pending, default=json_util.default, indent=2))
