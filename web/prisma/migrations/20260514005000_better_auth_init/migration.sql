CREATE TABLE [user] (
    [id] NVARCHAR(255) NOT NULL,
    [name] NVARCHAR(255) NOT NULL,
    [email] NVARCHAR(320) NOT NULL,
    [emailVerified] BIT NOT NULL CONSTRAINT [user_emailVerified_df] DEFAULT 0,
    [image] NVARCHAR(1024) NULL,
    [role] NVARCHAR(32) NOT NULL CONSTRAINT [user_role_df] DEFAULT N'Admin',
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [user_createdAt_df] DEFAULT SYSUTCDATETIME(),
    [updatedAt] DATETIME2 NOT NULL,
    CONSTRAINT [user_pkey] PRIMARY KEY CLUSTERED ([id]),
    CONSTRAINT [user_email_key] UNIQUE NONCLUSTERED ([email])
);

CREATE TABLE [session] (
    [id] NVARCHAR(255) NOT NULL,
    [expiresAt] DATETIME2 NOT NULL,
    [token] NVARCHAR(512) NOT NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [session_createdAt_df] DEFAULT SYSUTCDATETIME(),
    [updatedAt] DATETIME2 NOT NULL,
    [ipAddress] NVARCHAR(64) NULL,
    [userAgent] NVARCHAR(1024) NULL,
    [userId] NVARCHAR(255) NOT NULL,
    CONSTRAINT [session_pkey] PRIMARY KEY CLUSTERED ([id]),
    CONSTRAINT [session_token_key] UNIQUE NONCLUSTERED ([token]),
    CONSTRAINT [session_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [user]([id]) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX [session_userId_idx] ON [session]([userId]);

CREATE TABLE [account] (
    [id] NVARCHAR(255) NOT NULL,
    [accountId] NVARCHAR(255) NOT NULL,
    [providerId] NVARCHAR(64) NOT NULL,
    [userId] NVARCHAR(255) NOT NULL,
    [accessToken] NVARCHAR(MAX) NULL,
    [refreshToken] NVARCHAR(MAX) NULL,
    [idToken] NVARCHAR(MAX) NULL,
    [accessTokenExpiresAt] DATETIME2 NULL,
    [refreshTokenExpiresAt] DATETIME2 NULL,
    [scope] NVARCHAR(1024) NULL,
    [password] NVARCHAR(1024) NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [account_createdAt_df] DEFAULT SYSUTCDATETIME(),
    [updatedAt] DATETIME2 NOT NULL,
    CONSTRAINT [account_pkey] PRIMARY KEY CLUSTERED ([id]),
    CONSTRAINT [account_userId_fkey] FOREIGN KEY ([userId]) REFERENCES [user]([id]) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX [account_userId_idx] ON [account]([userId]);
CREATE UNIQUE INDEX [account_providerId_accountId_key] ON [account]([providerId], [accountId]);

CREATE TABLE [verification] (
    [id] NVARCHAR(255) NOT NULL,
    [identifier] NVARCHAR(512) NOT NULL,
    [value] NVARCHAR(MAX) NOT NULL,
    [expiresAt] DATETIME2 NOT NULL,
    [createdAt] DATETIME2 NOT NULL CONSTRAINT [verification_createdAt_df] DEFAULT SYSUTCDATETIME(),
    [updatedAt] DATETIME2 NOT NULL,
    CONSTRAINT [verification_pkey] PRIMARY KEY CLUSTERED ([id])
);

CREATE INDEX [verification_identifier_idx] ON [verification]([identifier]);
