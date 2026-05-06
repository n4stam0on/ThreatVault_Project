PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS ResponseActions;
DROP TABLE IF EXISTS IncidentIndicators;
DROP TABLE IF EXISTS Incidents;
DROP TABLE IF EXISTS ThreatIndicators;
DROP TABLE IF EXISTS Assets;
DROP TABLE IF EXISTS Analysts;

CREATE TABLE Analysts (
    AnalystID INTEGER PRIMARY KEY AUTOINCREMENT,
    FirstName TEXT NOT NULL,
    LastName TEXT NOT NULL,
    Email TEXT NOT NULL UNIQUE,
    Role TEXT NOT NULL
);

CREATE TABLE Assets (
    AssetID INTEGER PRIMARY KEY AUTOINCREMENT,
    DeviceName TEXT NOT NULL,
    IPAddress TEXT NOT NULL UNIQUE,
    DeviceType TEXT NOT NULL,
    OperatingSystem TEXT NOT NULL,
    Department TEXT NOT NULL
);

CREATE TABLE ThreatIndicators (
    IndicatorID INTEGER PRIMARY KEY AUTOINCREMENT,
    IndicatorType TEXT NOT NULL,
    IndicatorValue TEXT NOT NULL UNIQUE,
    ThreatType TEXT NOT NULL,
    RiskLevel TEXT NOT NULL,
    DateDetected TEXT NOT NULL,
    Source TEXT NOT NULL
);

CREATE TABLE Incidents (
    IncidentID INTEGER PRIMARY KEY AUTOINCREMENT,
    IncidentTitle TEXT NOT NULL,
    IncidentType TEXT NOT NULL,
    Severity TEXT NOT NULL,
    Status TEXT NOT NULL,
    DateOpened TEXT NOT NULL,
    DateClosed TEXT,
    Description TEXT NOT NULL,
    AssetID INTEGER NOT NULL,
    AnalystID INTEGER NOT NULL,
    FOREIGN KEY (AssetID) REFERENCES Assets(AssetID),
    FOREIGN KEY (AnalystID) REFERENCES Analysts(AnalystID)
);

CREATE TABLE IncidentIndicators (
    IncidentID INTEGER NOT NULL,
    IndicatorID INTEGER NOT NULL,
    PRIMARY KEY (IncidentID, IndicatorID),
    FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID),
    FOREIGN KEY (IndicatorID) REFERENCES ThreatIndicators(IndicatorID)
);

CREATE TABLE ResponseActions (
    ActionID INTEGER PRIMARY KEY AUTOINCREMENT,
    IncidentID INTEGER NOT NULL,
    ActionTaken TEXT NOT NULL,
    ActionDate TEXT NOT NULL,
    ActionStatus TEXT NOT NULL,
    Notes TEXT,
    FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID)
);

INSERT INTO Analysts (FirstName, LastName, Email, Role) VALUES
('Mia', 'Carter', 'mia.carter@threatvault.local', 'SOC Analyst'),
('Jordan', 'Lee', 'jordan.lee@threatvault.local', 'Incident Responder'),
('Avery', 'Stone', 'avery.stone@threatvault.local', 'Security Engineer');

INSERT INTO Assets (DeviceName, IPAddress, DeviceType, OperatingSystem, Department) VALUES
('FIN-WKS-01', '192.168.10.25', 'Workstation', 'Windows 11', 'Finance'),
('HR-WKS-02', '192.168.10.30', 'Workstation', 'Windows 11', 'Human Resources'),
('WEB-DMZ-01', '172.16.5.10', 'Server', 'Ubuntu Server 22.04', 'DMZ'),
('DB-SRV-01', '192.168.20.15', 'Database Server', 'Windows Server 2022', 'IT'),
('SEC-MON-01', '192.168.30.50', 'Monitoring Server', 'Ubuntu Server 22.04', 'Security');

INSERT INTO ThreatIndicators (IndicatorType, IndicatorValue, ThreatType, RiskLevel, DateDetected, Source) VALUES
('IP Address', '45.83.22.91', 'Brute Force Attempt', 'High', '2026-05-01', 'Firewall Logs'),
('Domain', 'secure-login-update.com', 'Phishing', 'Critical', '2026-05-01', 'Email Gateway'),
('File Hash', 'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3', 'Malware', 'Critical', '2026-05-02', 'Endpoint Detection'),
('URL', 'http://fakebank-login.net/reset', 'Credential Theft', 'High', '2026-05-02', 'User Report'),
('IP Address', '185.199.108.153', 'Suspicious Connection', 'Medium', '2026-05-03', 'Network Monitor'),
('Email Address', 'support@secure-login-update.com', 'Phishing', 'High', '2026-05-03', 'Email Gateway');

INSERT INTO Incidents (IncidentTitle, IncidentType, Severity, Status, DateOpened, DateClosed, Description, AssetID, AnalystID) VALUES
('Phishing email targeting finance user', 'Phishing', 'High', 'Open', '2026-05-01', NULL, 'A finance employee received a suspicious email asking for password verification.', 1, 1),
('Malware detected on HR workstation', 'Malware', 'Critical', 'Investigating', '2026-05-02', NULL, 'Endpoint detection flagged a suspicious executable on the HR workstation.', 2, 2),
('Brute force attempts against DMZ web server', 'Unauthorized Access', 'High', 'Open', '2026-05-01', NULL, 'Multiple failed login attempts were detected against the public web server.', 3, 3),
('Suspicious outbound traffic from database server', 'Network Anomaly', 'Medium', 'Resolved', '2026-05-03', '2026-05-04', 'Database server attempted outbound connections to an unknown external IP.', 4, 1),
('Credential theft URL reported by user', 'Credential Theft', 'High', 'Open', '2026-05-02', NULL, 'A user reported a suspicious password reset link.', 1, 2);

INSERT INTO IncidentIndicators (IncidentID, IndicatorID) VALUES
(1, 2),
(1, 6),
(2, 3),
(3, 1),
(4, 5),
(5, 4),
(5, 2);

INSERT INTO ResponseActions (IncidentID, ActionTaken, ActionDate, ActionStatus, Notes) VALUES
(1, 'Blocked phishing domain at email gateway', '2026-05-01', 'Completed', 'Domain added to blocklist.'),
(2, 'Isolated workstation from network', '2026-05-02', 'In Progress', 'Device removed from LAN pending malware review.'),
(3, 'Added firewall rule to block attacking IP', '2026-05-01', 'Completed', 'Repeated login attempts stopped.'),
(4, 'Reviewed outbound traffic logs', '2026-05-04', 'Completed', 'Traffic was confirmed suspicious and blocked.'),
(5, 'Submitted malicious URL for blocking', '2026-05-02', 'Completed', 'URL added to web filter.');