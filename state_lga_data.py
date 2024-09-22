#!/usr/bin/env python3
"""state_lga_data.py to get states and LGA from the API"""

import requests

BASE_URL = "https://nigeria-states-towns-lgas.onrender.com/api"

# Function to get all states
def get_all_states():
    try:
        response = requests.get(f"{BASE_URL}/all")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error: {err}")
    except Exception as err:
        print(f"Error: {err}")

# Function to get LGAs for a specific state using its state code
def get_lgas_by_state(state_code):
    try:
        response = requests.get(f"{BASE_URL}/{state_code}/lgas")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error: {err}")
    except Exception as err:
        print(f"Error: {err}")

# Example usage
if __name__ == "__main__":
    states = get_all_states()
    if states:
        for state in states:
            print(f"State: {state['name']}")
            lgas = get_lgas_by_state(state['code'])
            if lgas:
                print(f"LGAs in {state['name']}: {lgas}")

