SELECT [Id],[UserName] FROM [dbo].[AspNetUsers]

SELECT [Id],[Name] FROM [dbo].[AspNetRoles]

SELECT [UserId],[RoleId] FROM [dbo].[AspNetUserRoles]

INSERT INTO [dbo].[AspNetUserRoles]
(UserId, RoleId)
Values 
('d5b54c1f-7c6d-4fcb-99a8-eb6d74c4d07b','41c51214-83fa-4c31-9f2f-7e5c7789c787'),
('5ea836b1-a415-4918-880a-203966f40b98','9914a9f3-3bb8-43d8-a71b-c7d64fd06682'),
('c34e4a53-383b-475e-bbb4-1488227a23bb','f94524b0-7242-4a78-a8b4-dbd767e9ea6c')