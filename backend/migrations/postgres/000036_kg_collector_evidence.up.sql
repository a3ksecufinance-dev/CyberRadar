-- ═══════════════════════════════════════════════════════════════════════════
-- 000036 — The collector may assert a relationship
--
-- kg_observations accepts 'collector' as a source. kg_relationships does not,
-- although the API's own validator lists it and the service declares the
-- constant. So a relationship asserted by the collector — which is the service
-- that discovers most of them, BELONGS_TO between an asset and its owner above
-- all — passed validation and was refused by the database.
--
-- The two tables disagreeing is the defect; the constraint is the side that is
-- wrong, because every other layer already treats the collector as a source.
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE kg_relationships
    DROP CONSTRAINT IF EXISTS kg_relationships_evidence_source_check;

ALTER TABLE kg_relationships
    ADD CONSTRAINT kg_relationships_evidence_source_check
    CHECK (evidence_source = ANY (ARRAY[
        'siem', 'ueba', 'ti', 'vuln', 'attackpath', 'collector', 'manual', 'computed'
    ]));

COMMENT ON COLUMN kg_relationships.evidence_source IS
    'Which service asserted this relationship. Kept in step with the same list on kg_observations.source_service and with model.Source* in the knowledgegraph service.';
