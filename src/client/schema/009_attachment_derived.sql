CREATE TABLE attachment_derived (
    entry INTEGER NOT NULL REFERENCES attachment_cache(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL,
    size INTEGER,
    failed INTEGER,
    PRIMARY KEY (entry, kind)
) STRICT;

INSERT INTO attachment_derived (entry, kind, size, failed)
    SELECT id, 1, thumbnail, thumbnail_failed FROM attachment_cache
    WHERE thumbnail IS NOT NULL OR thumbnail_failed IS NOT NULL;
UPDATE attachment_cache SET size = size - thumbnail WHERE thumbnail IS NOT NULL;
ALTER TABLE attachment_cache DROP COLUMN thumbnail;
ALTER TABLE attachment_cache DROP COLUMN thumbnail_failed;
