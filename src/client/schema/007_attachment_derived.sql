ALTER TABLE attachment_cache ADD COLUMN width INTEGER;
ALTER TABLE attachment_cache ADD COLUMN height INTEGER;
ALTER TABLE attachment_cache ADD COLUMN frames INTEGER;

CREATE TABLE attachment_derived (
    entry INTEGER NOT NULL REFERENCES attachment_cache(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL,
    size INTEGER,
    failed INTEGER,
    PRIMARY KEY (entry, kind)
) STRICT;

CREATE INDEX message_attachments_pending ON message_attachments(path) WHERE url IS NULL;

ALTER TABLE message_attachments ADD COLUMN auto_pending INTEGER;
CREATE INDEX message_attachments_auto_pending ON message_attachments(message)
    WHERE auto_pending IS NOT NULL;
