ALTER TABLE attachment_derived ADD COLUMN width INTEGER;
ALTER TABLE attachment_derived ADD COLUMN height INTEGER;

-- Thumbnails made before this were square crops of unknown size.  Without a row, the cache sweep
-- removes each file as an orphan and the thumbnail pass makes it again in the picture's own shape.
DELETE FROM attachment_derived WHERE kind = 1;
