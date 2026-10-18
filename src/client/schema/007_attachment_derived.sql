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
