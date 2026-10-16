CREATE INDEX message_attachments_pending ON message_attachments(path) WHERE url IS NULL;
