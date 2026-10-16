DELETE FROM role_permissions
 WHERE permission_id IN (SELECT id FROM permissions WHERE resource = 'events' AND action = 'read');

DELETE FROM permissions WHERE resource = 'events' AND action = 'read';
