ALTER TABLE users
    ADD COLUMN role ENUM('USER', 'ADMIN') AFTER remember_token;