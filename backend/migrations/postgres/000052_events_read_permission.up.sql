-- La recherche d'événements avait besoin d'un droit qui n'existait pas.
--
-- La ressource `events` ne portait qu'une action : `ingest`, créée en 000031
-- pour les comptes de service. Il n'y avait aucun droit de *lecture* des
-- événements, pour une raison simple — rien ne les lisait. La table
-- crp_audit.cyber_events recevait chaque événement normalisé depuis le
-- premier jour, et aucune API ne permettait de l'interroger.
--
-- `events:read` est séparé de `alerts:read` délibérément. Une alerte est une
-- conclusion que la plateforme a tirée ; le flux d'événements est tout ce
-- qu'elle a vu, y compris les authentifications, les transactions et les
-- charges utiles brutes de tout le parc. Qui est habilité à trier des
-- conclusions ne l'est pas automatiquement à lire la matière première.
--
-- L'attribution suit cette logique : les rôles qui enquêtent l'obtiennent,
-- les rôles qui supervisent ne l'obtiennent pas. tenant_admin ne l'a pas non
-- plus — administrer un locataire n'est pas enquêter dedans, et le rôle a
-- déjà audit:read pour ce qui relève de la traçabilité.

INSERT INTO permissions (resource, action, description) VALUES
    ('events', 'read', 'Rechercher et lire les événements normalisés')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON (p.resource, p.action) IN (('events', 'read'))
WHERE r.name IN (
    'soc_analyst_l1',     -- le tri commence par regarder autour de l'alerte
    'soc_analyst_l2',
    'threat_hunter',      -- la chasse n'est que cela
    'incident_responder', -- reconstituer une chronologie
    'fraud_analyst'       -- les transactions signalées arrivent dans ce flux
)
ON CONFLICT DO NOTHING;

-- super_admin détient toute permission, y compris celle-ci.
--
-- Depuis 000035, l'autorité d'un opérateur de plateforme est énumérable dans
-- la matrice plutôt que dérivée d'un contournement : une permission ajoutée
-- sans cette ligne lui *retire* un droit qu'il est censé avoir tous.
-- TestSuperAdminHoldsEveryPermission casse la construction quand on l'oublie,
-- et c'est exactement ce qui est arrivé ici.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON (p.resource, p.action) IN (('events', 'read'))
WHERE r.name = 'super_admin'
ON CONFLICT DO NOTHING;
