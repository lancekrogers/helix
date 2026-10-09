-- ADR-0002 amendment: the platform-wide LLM spend aggregate behind the daily ceiling.
--
-- The edge reads spend through withPartition, and the gateway_calls RLS policy scopes every
-- read to one app, so a cross-app sum cannot be a plain query. This function returns two
-- aggregates (today, last hour) for one env and nothing else. It adds no reach: helix_edge
-- can already read every app's rows one at a time by setting app.app_id itself. The real
-- boundary (no grant on app_secrets or registry writes) is unchanged.
--
-- gateway_calls is FORCE ROW LEVEL SECURITY, so the table owner is subject to RLS too. Every
-- existing policy is role-scoped, so an owner-run definer function would match none and see
-- zero rows (silently disabling the ceiling). The policy below admits the migration owner.

DO $$
BEGIN
  -- Bound at migration time to whichever role runs the migration: helixadmin in production
  -- (postgresAdminLogin), helix in the dev container.
  EXECUTE format(
    'CREATE POLICY gateway_calls_owner_read ON gateway_calls FOR SELECT TO %I USING (true)',
    current_user
  );
END $$;

CREATE FUNCTION platform_llm_spend_micro_usd(p_env text)
  RETURNS TABLE (today bigint, hour bigint)
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, public
AS $$
  SELECT
    COALESCE(SUM("costMicroUsd") FILTER (WHERE "createdAt" >= date_trunc('day', now())), 0)::bigint,
    COALESCE(SUM("costMicroUsd") FILTER (WHERE "createdAt" >= now() - interval '1 hour'), 0)::bigint
  FROM public.gateway_calls
  WHERE env = p_env AND capability = 'llm'
    AND "createdAt" >= date_trunc('day', now()) - interval '1 hour'
$$;

REVOKE EXECUTE ON FUNCTION platform_llm_spend_micro_usd(text) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'helix_edge') THEN
    GRANT EXECUTE ON FUNCTION platform_llm_spend_micro_usd(text) TO helix_edge;
  END IF;
END $$;
