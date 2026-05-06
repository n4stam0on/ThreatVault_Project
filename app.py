import sqlite3
from pathlib import Path

DATABASE_PATH = Path("database") / "threatvault.db"
SQL_SETUP_PATH = Path("database_setup.sql")


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection


def setup_database():
    try:
        DATABASE_PATH.parent.mkdir(exist_ok=True)

        with open(SQL_SETUP_PATH, "r", encoding="utf-8") as file:
            sql_script = file.read()

        with connect_db() as connection:
            connection.executescript(sql_script)

        print("Database created successfully.")

    except FileNotFoundError:
        print("Error: database_setup.sql was not found.")
    except sqlite3.Error as error:
        print("Database error:", error)
    except Exception as error:
        print("Unexpected error:", error)


def display_rows(headers, rows):
    if not rows:
        print("No records found.")
        return

    print("\n" + " | ".join(headers))
    print("-" * 100)

    for row in rows:
        print(" | ".join(str(item) if item is not None else "NULL" for item in row))


def view_all_incidents():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT IncidentID, IncidentTitle, IncidentType, Severity, Status, DateOpened
                FROM Incidents
                ORDER BY IncidentID;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["ID", "Title", "Type", "Severity", "Status", "Date Opened"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def view_open_incidents():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT IncidentID, IncidentTitle, Severity, Status, DateOpened
                FROM Incidents
                WHERE Status != 'Resolved'
                ORDER BY Severity;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["ID", "Title", "Severity", "Status", "Date Opened"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def add_new_incident():
    try:
        title = input("Incident title: ")
        incident_type = input("Incident type: ")
        severity = input("Severity (Low/Medium/High/Critical): ")
        status = input("Status (Open/Investigating/Resolved): ")
        date_opened = input("Date opened (YYYY-MM-DD): ")
        description = input("Description: ")
        asset_id = int(input("Asset ID: "))
        analyst_id = int(input("Analyst ID: "))

        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO Incidents 
                (IncidentTitle, IncidentType, Severity, Status, DateOpened, DateClosed, Description, AssetID, AnalystID)
                VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?);
            """, (title, incident_type, severity, status, date_opened, description, asset_id, analyst_id))

            connection.commit()

        print("Incident added successfully.")

    except ValueError:
        print("Error: Asset ID and Analyst ID must be numbers.")
    except sqlite3.Error as error:
        print("Database error:", error)


def update_incident_status():
    try:
        incident_id = int(input("Enter Incident ID to update: "))
        new_status = input("New status: ")
        date_closed = input("Date closed if resolved, otherwise leave blank: ")

        if date_closed.strip() == "":
            date_closed = None

        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE Incidents
                SET Status = ?, DateClosed = ?
                WHERE IncidentID = ?;
            """, (new_status, date_closed, incident_id))

            connection.commit()

            if cursor.rowcount == 0:
                print("No incident found with that ID.")
            else:
                print("Incident status updated successfully.")

    except ValueError:
        print("Error: Incident ID must be a number.")
    except sqlite3.Error as error:
        print("Database error:", error)


def view_high_risk_indicators():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT IndicatorID, IndicatorType, IndicatorValue, ThreatType, RiskLevel, Source
                FROM ThreatIndicators
                WHERE RiskLevel IN ('High', 'Critical')
                ORDER BY RiskLevel;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["ID", "Type", "Value", "Threat Type", "Risk", "Source"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def view_full_incident_report():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT 
                    i.IncidentID,
                    i.IncidentTitle,
                    i.Severity,
                    i.Status,
                    a.DeviceName,
                    a.IPAddress,
                    an.FirstName || ' ' || an.LastName AS Analyst
                FROM Incidents i
                JOIN Assets a ON i.AssetID = a.AssetID
                JOIN Analysts an ON i.AnalystID = an.AnalystID
                ORDER BY i.IncidentID;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["ID", "Incident", "Severity", "Status", "Device", "IP Address", "Analyst"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def view_incident_count_by_severity():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT Severity, COUNT(*) AS TotalIncidents
                FROM Incidents
                GROUP BY Severity
                ORDER BY TotalIncidents DESC;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["Severity", "Total Incidents"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def view_repeated_indicators():
    try:
        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                SELECT 
                    ti.IndicatorValue,
                    ti.IndicatorType,
                    COUNT(ii.IncidentID) AS TimesLinked
                FROM ThreatIndicators ti
                JOIN IncidentIndicators ii ON ti.IndicatorID = ii.IndicatorID
                GROUP BY ti.IndicatorValue, ti.IndicatorType
                HAVING COUNT(ii.IncidentID) > 1;
            """)
            rows = cursor.fetchall()

        display_rows(
            ["Indicator Value", "Type", "Times Linked"],
            rows
        )

    except sqlite3.Error as error:
        print("Database error:", error)


def add_response_action():
    try:
        incident_id = int(input("Incident ID: "))
        action_taken = input("Action taken: ")
        action_date = input("Action date (YYYY-MM-DD): ")
        action_status = input("Action status: ")
        notes = input("Notes: ")

        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO ResponseActions
                (IncidentID, ActionTaken, ActionDate, ActionStatus, Notes)
                VALUES (?, ?, ?, ?, ?);
            """, (incident_id, action_taken, action_date, action_status, notes))

            connection.commit()

        print("Response action added successfully.")

    except ValueError:
        print("Error: Incident ID must be a number.")
    except sqlite3.Error as error:
        print("Database error:", error)


def delete_test_incident():
    try:
        incident_id = int(input("Enter Incident ID to delete: "))

        confirm = input("Are you sure? Type YES to delete: ")

        if confirm != "YES":
            print("Delete canceled.")
            return

        with connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("""
                DELETE FROM Incidents
                WHERE IncidentID = ?;
            """, (incident_id,))

            connection.commit()

            if cursor.rowcount == 0:
                print("No incident found with that ID.")
            else:
                print("Incident deleted successfully.")

    except ValueError:
        print("Error: Incident ID must be a number.")
    except sqlite3.Error as error:
        print("Database error:", error)


def show_menu():
    print("\n========== ThreatVault Menu ==========")
    print("1. Set up/reset database")
    print("2. View all incidents")
    print("3. View open incidents")
    print("4. Add new incident")
    print("5. Update incident status")
    print("6. View high-risk threat indicators")
    print("7. View full incident report")
    print("8. View incident count by severity")
    print("9. View repeated threat indicators")
    print("10. Add response action")
    print("11. Delete test incident")
    print("12. Exit")


def main():
    while True:
        show_menu()
        choice = input("Choose an option: ")

        if choice == "1":
            setup_database()
        elif choice == "2":
            view_all_incidents()
        elif choice == "3":
            view_open_incidents()
        elif choice == "4":
            add_new_incident()
        elif choice == "5":
            update_incident_status()
        elif choice == "6":
            view_high_risk_indicators()
        elif choice == "7":
            view_full_incident_report()
        elif choice == "8":
            view_incident_count_by_severity()
        elif choice == "9":
            view_repeated_indicators()
        elif choice == "10":
            add_response_action()
        elif choice == "11":
            delete_test_incident()
        elif choice == "12":
            print("Exiting ThreatVault.")
            break
        else:
            print("Invalid option. Please choose a number from 1 to 12.")


if __name__ == "__main__":
    main()