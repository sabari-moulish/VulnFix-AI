-- Synthetic Testbed Schema for Authorized Lab
-- All data is completely synthetic and strictly for local authorized testing.

DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS products;

CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    organization_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    organization_id INTEGER NOT NULL,
    owner_user_id INTEGER NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL
);

-- Seed Synthetic Data
INSERT INTO organizations (id, name) VALUES 
    (1, 'Organization A'),
    (2, 'Organization B');

INSERT INTO users (id, username, organization_id, role) VALUES 
    (1, 'User A', 1, 'Lab Tester'),
    (2, 'User B', 2, 'Lab Tester');

INSERT INTO records (id, record_code, title, content, organization_id, owner_user_id) VALUES 
    (1, 'REC-001', 'Test Record 001', 'Confidential synthetic diagnostic report for Organization A.', 1, 1),
    (2, 'REC-002', 'Test Record 002', 'Confidential synthetic financial telemetry for Organization B.', 2, 2);

INSERT INTO products (id, name, description, category) VALUES 
    (1, 'Diagnostic Sensor', 'Synthetic test sensor module for lab experiments', 'Hardware'),
    (2, 'Calibration Toolkit', 'Standard lab calibration suite for benchmark evaluation', 'Software'),
    (3, 'Loopback Probe', 'Virtual loopback testing utility for network simulation', 'Network');
