CREATE TABLE users (
   id INT AUTO_INCREMENT PRIMARY KEY,
   name VARCHAR(255),
   email VARCHAR(255),
   email_verified_at VARCHAR(255),
   password VARCHAR(255),
   remember_token VARCHAR(255),
   created_at TIMESTAMP NULL,
   updated_at TIMESTAMP NULL
);