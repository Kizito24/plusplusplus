from pymongo import MongoClient

def clear_database():
    # Replace with your MongoDB URI and database name
    mongo_uri = "mongodb://localhost:27017/"
    database_name = "your_database"

    # Connect to MongoDB
    client = MongoClient(mongo_uri)

    # Access the specified database
    db = client[database_name]

    # Drop all collections in the database
    collections = db.list_collection_names()
    if not collections:
        print(f"The database '{database_name}' is already empty.")
    else:
        for collection in collections:
            db[collection].drop()
            print(f"Dropped collection: {collection}")

    # Close the connection
    client.close()
    print(f"The database '{database_name}' has been cleared.")

if __name__ == "__main__":
    clear_database()
