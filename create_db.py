from app import app, db  # Import the app and db from your Flask application

# Ensure that Flask application context is available
with app.app_context():
    db.create_all()  # Create the database tables
    print("Database and tables created!")
