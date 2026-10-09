/**
 * Catalog queries for the platform LLM spend definer (ADR-0002 amendment). The
 * startup self-test in the platform-ceiling wiring reuses the same SQL.
 */
export const PLATFORM_LLM_SPEND_DEFINER_CATALOG_SQL = `
SELECT
  p.proname = 'platform_llm_spend_micro_usd' AS fn_name_ok,
  p.prosecdef AS security_definer,
  EXISTS (
    SELECT 1 FROM unnest(COALESCE(p.proconfig, ARRAY[]::text[])) AS cfg
    WHERE cfg LIKE 'search_path=%'
  ) AS search_path_pinned,
  pg_get_userbyid(p.proowner) AS function_owner,
  pol.policyname = 'gateway_calls_owner_read' AS policy_name_ok,
  pol.cmd = 'SELECT' AS policy_cmd_ok,
  pol.roles @> ARRAY[pg_get_userbyid(p.proowner)]::name[] AS policy_admits_owner
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public'
LEFT JOIN pg_policies pol
  ON pol.tablename = 'gateway_calls'
 AND pol.policyname = 'gateway_calls_owner_read'
WHERE p.proname = 'platform_llm_spend_micro_usd'
  AND pg_get_function_identity_arguments(p.oid) = 'p_env text'
`;
