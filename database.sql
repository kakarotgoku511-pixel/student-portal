CREATE DATABASE IF NOT EXISTS student_portal;

USE student_portal;


-- =========================================
-- STUDENTS TABLE
-- =========================================

CREATE TABLE users (

    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(100) NOT NULL,

    email VARCHAR(150) NOT NULL UNIQUE,

    password VARCHAR(255) NOT NULL,

    class_name VARCHAR(10) NOT NULL,

    profile_picture VARCHAR(255),

    failed_attempts INT DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


-- =========================================
-- MIDTERM RESULTS
-- =========================================

CREATE TABLE midterm_results (

    id INT AUTO_INCREMENT PRIMARY KEY,

    student_id INT NOT NULL,

    subject VARCHAR(100) NOT NULL,

    score DECIMAL(5,2) NOT NULL,

    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES users(id)
        ON DELETE CASCADE

);


-- =========================================
-- EXAM RESULTS
-- =========================================

CREATE TABLE exam_results (

    id INT AUTO_INCREMENT PRIMARY KEY,

    student_id INT NOT NULL,

    subject VARCHAR(100) NOT NULL,

    score DECIMAL(5,2) NOT NULL,

    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES users(id)
        ON DELETE CASCADE

);