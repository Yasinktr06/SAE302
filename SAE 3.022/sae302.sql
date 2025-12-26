CREATE DATABASE IF NOT EXISTS sae302;
USE sae302;

CREATE TABLE IF NOT EXISTS routeurs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(50),
    port INT,
    public_key TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(50),
    destination VARCHAR(50),
    route TEXT,
    payload TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS router_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    router_port INT,
    next_port INT,
    action VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS master_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
