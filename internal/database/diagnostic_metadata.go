package database

const diagnosticMetadataSchema = `
CREATE TABLE diagnostic_result_metadata(task_id TEXT PRIMARY KEY REFERENCES results(task_id) ON DELETE CASCADE,payload_json TEXT NOT NULL CHECK(json_valid(payload_json)));
`
