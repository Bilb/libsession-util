ALTER TABLE message_attachments ADD COLUMN sending_thumbnail_width INTEGER;
ALTER TABLE message_attachments ADD COLUMN sending_thumbnail_height INTEGER;

CREATE INDEX message_attachments_sending_thumbnail ON message_attachments(message)
    WHERE sending_thumbnail_width IS NOT NULL;
