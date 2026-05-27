-- CyberRadar Platform — PostgreSQL initialization
-- Creates all required databases for the platform

-- Keycloak identity database
CREATE DATABASE crp_keycloak
  WITH OWNER crp_user
  ENCODING 'UTF8'
  LC_COLLATE 'en_US.utf8'
  LC_CTYPE 'en_US.utf8'
  TEMPLATE template0;

-- Main platform database (already created as POSTGRES_DB)
-- crp_foundation is the default DB, no need to CREATE it here

GRANT ALL PRIVILEGES ON DATABASE crp_keycloak TO crp_user;
GRANT ALL PRIVILEGES ON DATABASE crp_foundation TO crp_user;
