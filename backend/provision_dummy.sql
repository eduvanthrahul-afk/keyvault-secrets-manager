DELETE FROM users WHERE email = 'dummy@demo.com';

INSERT INTO
    users (
        id,
        email,
        password_hash,
        salt,
        public_key,
        encrypted_private_key,
        created_at
    )
VALUES (
        UUID_TO_BIN(UUID()),
        'dummy@demo.com',
        '$2a$10$bBzF/uirOPU4IP1GYLSEOO/f.TTfqA64ROWL3hSNfRAto.bAtHixq',
        '44454d4f5f53414c545f5859313233',
        NULL,
        NULL,
        NOW()
    );