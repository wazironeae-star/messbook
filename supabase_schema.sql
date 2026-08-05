-- ====================================================================
-- SUPABASE POSTGRESQL SCHEMA FOR MESSBOOK AUTOMATED CLOUD STORAGE
-- ====================================================================
-- INSTRUCTIONS:
-- 1. Copy the entire contents of this file.
-- 2. Log in to your Supabase Dashboard: https://supabase.com
-- 3. Open your project ("mess_book")
-- 4. Navigate to "SQL Editor" in the left sidebar.
-- 5. Create a new query, paste this SQL, and click "Run".
-- ====================================================================

-- Create a table to store the master state of the MessBook application
CREATE TABLE IF NOT EXISTS messbook_state (
    id VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Insert initial empty JSON state if it does not already exist
INSERT INTO messbook_state (id, data, updated_at)
VALUES ('active_state', '{}'::jsonb, now())
ON CONFLICT (id) DO NOTHING;

-- Grant public read/write permission to allow your client code to read & write 
-- (Ensure security rules are set up as needed for your production environment)
ALTER TABLE messbook_state ENABLE ROW LEVEL SECURITY;

-- Grant SQL-level privileges to the PostgREST API roles (anon, authenticated, and service_role)
-- This fixes the "permission denied for table messbook_state" database-level error.
GRANT ALL ON TABLE messbook_state TO anon, authenticated, service_role;

-- Create policies to allow public reads and writes for simplicity (development)
CREATE POLICY "Allow public read on messbook_state" ON messbook_state 
    FOR SELECT USING (true);

CREATE POLICY "Allow public insert/update on messbook_state" ON messbook_state 
    FOR ALL USING (true) WITH CHECK (true);
