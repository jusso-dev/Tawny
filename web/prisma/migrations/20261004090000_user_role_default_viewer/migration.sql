-- New users default to least privilege; admins are created explicitly.
ALTER TABLE [dbo].[user] DROP CONSTRAINT [user_role_df];
ALTER TABLE [dbo].[user] ADD CONSTRAINT [user_role_df] DEFAULT N'Viewer' FOR [role];
