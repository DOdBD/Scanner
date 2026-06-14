-- ─── leads ────────────────────────────────────────────────────────────────────
create table if not exists leads (
  id                  uuid primary key default gen_random_uuid(),
  email               text not null,
  domain              text,
  first_scan_id       uuid,
  hubspot_contact_id  text,
  captured_at         timestamptz default now(),
  gdpr_consent        boolean default false,
  gdpr_consent_at     timestamptz
);

-- ─── scans ────────────────────────────────────────────────────────────────────
create table if not exists scans (
  -- identity
  id                  uuid primary key default gen_random_uuid(),
  domain              text not null,
  scanned_at          timestamptz default now(),
  scanner_ip_hash     text,
  scan_source         text default 'lead_magnet',
  lead_id             uuid references leads(id),

  -- time series
  is_latest           boolean default true,
  previous_scan_id    uuid references scans(id),
  days_since_last_scan integer,

  -- geography & enrichment
  domain_tld          text,
  inferred_country    text,
  inferred_sector     text,

  -- email & DNS
  email_provider      text,
  dns_host            text,
  ipv4_addresses      text[],
  ipv6_addresses      text[],
  subdomain_count     integer,
  ssl_issuer          text,

  -- hosting & tools
  cdn                 text[],
  hosting             text[],
  web_server          text[],
  cms                 text[],
  crm                 text[],
  marketing_tools     text[],
  internal_tools      text[],

  -- verified vendors
  verified_vendors    text[],
  has_openai          boolean default false,
  has_anthropic       boolean default false,
  has_apple_business  boolean default false,

  -- email security
  spf_configured      boolean,
  spf_senders         text[],
  dmarc_configured    boolean,
  dmarc_policy        text,
  security_headers_count integer,
  security_headers    text[],

  -- GEO: crawlability
  robots_txt_found            boolean,
  robots_txt_allows_gptbot    boolean,
  robots_txt_allows_claudebot boolean,
  robots_txt_allows_perplexity boolean,
  robots_txt_allows_google_extended boolean,
  robots_txt_raw              text,

  -- GEO: AI guidance files
  llms_txt_found      boolean,
  llms_full_txt_found boolean,
  llms_txt_content    text,

  -- GEO: content signals
  sitemap_found           boolean,
  sitemap_page_count      integer,
  homepage_title          text,
  homepage_description    text,
  homepage_og_title       text,
  homepage_og_description text,
  schema_org_type         text,
  schema_org_raw          jsonb,
  homepage_word_count     integer,

  -- Claude synthesis
  geo_positioning         text,
  geo_target_market       text,
  geo_tone_of_voice       text,
  geo_ai_readiness_score  integer,
  geo_gaps                text[],
  geo_synthesis_raw       text,
  geo_model_used          text
);

-- ─── FK back-reference ────────────────────────────────────────────────────────
alter table leads
  add constraint leads_first_scan_id_fkey
  foreign key (first_scan_id) references scans(id);

-- ─── indexes ──────────────────────────────────────────────────────────────────
create index if not exists idx_scans_domain_scanned_at on scans (domain, scanned_at desc);
create index if not exists idx_scans_is_latest         on scans (is_latest) where is_latest = true;
create index if not exists idx_scans_domain_tld        on scans (domain_tld);
create index if not exists idx_scans_inferred_country  on scans (inferred_country);
