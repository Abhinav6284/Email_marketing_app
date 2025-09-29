from mark_app import create_app, db

# Create the Flask app instance using your factory
app = create_app()

if __name__ == "__main__":
    # Establish an application context to work with the database
    with app.app_context():
        print("--- Running database schema check ---")

        # This single command creates all necessary tables AND adds any missing columns.
        db.create_all()

        print("--- Database schema is up to date. ---")

    print("🚀 Mark Email Marketing Application Started!")
    app.run(debug=True, host="0.0.0.0", port=5000)
