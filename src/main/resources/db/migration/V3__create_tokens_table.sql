CREATE TABLE tokens (
       id INT AUTO_INCREMENT PRIMARY KEY,
       user_id INTEGER,
       token VARCHAR(255),
       token_type ENUM('BEARER'),
       expired TINYINT(1) DEFAULT 0,
       revoked TINYINT(1) DEFAULT 0,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);