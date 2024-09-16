from flask import Blueprint, jsonify
from state_lga_data import get_all_states, get_lgas_by_state

api = Blueprint('api', __name__)

@api.route('/api/states', methods=['GET'])
def get_states():
    # Fetch the states dynamically using the API
    states_data = get_all_states()
    if states_data:
        states = [state['name'] for state in states_data]
        return jsonify(states)
    return jsonify({"error": "Unable to fetch states"}), 500

@api.route('/api/lgas/<state_name>', methods=['GET'])
def get_lgas(state_name):
    # Fetch all states to find the state code for the given state name
    states_data = get_all_states()
    if states_data:
        state = next((s for s in states_data if s['name'].lower() == state_name.lower()), None)
        if state:
            lgas = get_lgas_by_state(state['code'])
            return jsonify(lgas)
        return jsonify({"error": "State not found"}), 404
    return jsonify({"error": "Unable to fetch LGAs"}), 500
