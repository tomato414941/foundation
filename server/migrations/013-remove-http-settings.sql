-- Connection methods no longer say how to send a connection's values over HTTP, so neither the methods kept as items
-- nor the connections made with them keep that among their data.
UPDATE resources SET data = data - 'http' WHERE kind IN ('method', 'connection') AND data ? 'http';
