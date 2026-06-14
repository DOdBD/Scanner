import asyncio
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urljoin

import anthropic
import dns.resolver
import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client
import os

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
claude_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ─── Fingerprint tables (ported from domain-scanner.html) ─────────────────────

EMAIL_MX = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "aspmx.l.google.com": "Google Workspace", "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365", "mail.protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail", "zoho.eu": "Zoho Mail", "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid", "amazonses.com": "Amazon SES",
    "mimecast.com": "Mimecast (security gateway)", "pphosted.com": "Proofpoint (security gateway)",
    "proofpoint.com": "Proofpoint (security gateway)", "barracuda": "Barracuda (security gateway)",
    "messagelabs.com": "Symantec MessageLabs", "yandex": "Yandex Mail",
    "fastmail": "Fastmail", "ovh.net": "OVH Mail",
}

TXT_FP = {
    "google-site-verification": ("Google Search Console", "tools"),
    "facebook-domain-verification": ("Meta / Facebook Ads", "marketing"),
    "ms=": ("Microsoft 365", "tools"),
    "atlassian-domain-verification": ("Atlassian (Jira/Confluence)", "tools"),
    "atlassian-sending-domain": ("Atlassian", "tools"),
    "docusign": ("DocuSign", "tools"),
    "adobe-idp-site-verification": ("Adobe", "tools"),
    "adobe-sign-verification": ("Adobe Sign", "tools"),
    "stripe-verification": ("Stripe", "tools"),
    "dropbox-domain-verification": ("Dropbox", "tools"),
    "notion": ("Notion", "tools"),
    "slack-domain-verification": ("Slack", "tools"),
    "miro-verification": ("Miro", "tools"),
    "zoom": ("Zoom", "tools"),
    "calendly": ("Calendly", "tools"),
    "github": ("GitHub", "tools"),
    "gitlab": ("GitLab", "tools"),
    "1password": ("1Password", "tools"),
    "okta-verification": ("Okta", "tools"),
    "okta": ("Okta", "tools"),
    "auth0": ("Auth0", "tools"),
    "onelogin": ("OneLogin", "tools"),
    "duosecurity": ("Duo Security", "tools"),
    "segment": ("Segment", "tools"),
    "datadog": ("Datadog", "tools"),
    "pagerduty": ("PagerDuty", "tools"),
    "twilio": ("Twilio", "tools"),
    "sendgrid": ("SendGrid", "tools"),
    "mailchimp": ("Mailchimp", "marketing"),
    "mandrill": ("Mailchimp Transactional", "marketing"),
    "klaviyo": ("Klaviyo", "marketing"),
    "hubspot": ("HubSpot", "crm"),
    "_hubspot": ("HubSpot", "crm"),
    "pardot": ("Salesforce Pardot", "crm"),
    "salesforce": ("Salesforce", "crm"),
    "marketo": ("Marketo", "crm"),
    "intercom": ("Intercom", "crm"),
    "zendesk": ("Zendesk", "crm"),
    "freshdesk": ("Freshdesk", "crm"),
    "freshworks": ("Freshworks", "crm"),
    "pipedrive": ("Pipedrive", "crm"),
    "drift": ("Drift", "crm"),
    "amazonses": ("Amazon SES", "tools"),
    "cloudflare": ("Cloudflare", "tools"),
    "shopify": ("Shopify", "cms"),
    "webflow": ("Webflow", "cms"),
    "wix": ("Wix", "cms"),
    "squarespace": ("Squarespace", "cms"),
    "knowbe4": ("KnowBe4 (security training)", "tools"),
    "logmein": ("LogMeIn / GoTo", "tools"),
    "citrix": ("Citrix", "tools"),
    "workday": ("Workday", "tools"),
    "servicenow": ("ServiceNow", "tools"),
    "qualtrics": ("Qualtrics", "marketing"),
    "surveymonkey": ("SurveyMonkey", "marketing"),
}

NS_HOSTS = {
    "awsdns": "AWS Route 53", "cloudflare": "Cloudflare",
    "googledomains": "Google Domains", "google.com": "Google Cloud DNS",
    "azure-dns": "Azure DNS", "digitalocean": "DigitalOcean DNS",
    "netlify": "Netlify DNS", "vercel-dns": "Vercel DNS",
    "nsone.net": "NS1", "dnsimple": "DNSimple", "gandi.net": "Gandi",
    "ovh.net": "OVH", "domaincontrol.com": "GoDaddy",
    "registrar-servers.com": "Namecheap", "name-services.com": "Enom",
    "ultradns": "UltraDNS (Vercara)", "akam.net": "Akamai (Edge DNS)",
    "dynect.net": "Oracle Dyn", "combell": "Combell",
    "hostbasket": "Hostbasket", "one.com": "One.com", "transip": "TransIP",
    "openprovider": "Openprovider", "kinamo": "Kinamo", "nucleus": "Nucleus",
    "versio": "Versio", "antagonist": "Antagonist", "cloudns": "ClouDNS",
    "hostnet": "Hostnet", "mijndomein": "Mijndomein",
    "infomaniak": "Infomaniak", "scaleway": "Scaleway", "hetzner": "Hetzner",
}

VERIFY_FP = {
    "openai-domain-verification": "OpenAI (ChatGPT)",
    "anthropic-domain-verification": "Anthropic (Claude)",
    "apple-domain-verification": "Apple Business",
    "google-site-verification": "Google Search Console",
    "facebook-domain-verification": "Meta Business",
    "atlassian-domain-verification": "Atlassian",
    "dropbox-domain-verification": "Dropbox",
    "stripe-verification": "Stripe",
    "zoom-domain-verification": "Zoom",
    "slack-domain-verification": "Slack",
    "miro-verification": "Miro",
    "canva-domain-verification": "Canva",
    "figma": "Figma",
    "calendly": "Calendly",
}

HEADER_FP = [
    {"h": "server", "m": "cloudflare", "l": "Cloudflare", "c": "cdn"},
    {"h": "server", "m": "nginx", "l": "Nginx", "c": "server"},
    {"h": "server", "m": "apache", "l": "Apache", "c": "server"},
    {"h": "server", "m": "microsoft-iis", "l": "Microsoft IIS", "c": "server"},
    {"h": "server", "m": "openresty", "l": "OpenResty", "c": "server"},
    {"h": "server", "m": "vercel", "l": "Vercel", "c": "hosting"},
    {"h": "server", "m": "awselb", "l": "AWS ELB", "c": "hosting"},
    {"h": "server", "m": "gunicorn", "l": "Gunicorn (Python)", "c": "server"},
    {"h": "x-powered-by", "m": "express", "l": "Express (Node.js)", "c": "server"},
    {"h": "x-powered-by", "m": "php", "l": "PHP", "c": "server"},
    {"h": "x-powered-by", "m": "asp.net", "l": "ASP.NET", "c": "server"},
    {"h": "x-powered-by", "m": "next.js", "l": "Next.js", "c": "cms"},
    {"h": "x-powered-by", "m": "shopify", "l": "Shopify", "c": "cms"},
    {"h": "x-powered-by", "m": "wp engine", "l": "WP Engine", "c": "hosting"},
    {"h": "via", "m": "cloudfront", "l": "AWS CloudFront", "c": "cdn"},
    {"h": "via", "m": "varnish", "l": "Varnish / Fastly", "c": "cdn"},
    {"h": "x-served-by", "m": "cache", "l": "Fastly", "c": "cdn"},
    {"h": "x-cache", "m": "cloudfront", "l": "AWS CloudFront", "c": "cdn"},
    {"h": "x-vercel-id", "m": "", "l": "Vercel", "c": "hosting"},
    {"h": "x-nf-request-id", "m": "", "l": "Netlify", "c": "hosting"},
    {"h": "x-github-request-id", "m": "", "l": "GitHub Pages", "c": "hosting"},
    {"h": "x-amz-cf-id", "m": "", "l": "AWS CloudFront", "c": "cdn"},
    {"h": "x-shopify-stage", "m": "", "l": "Shopify", "c": "cms"},
    {"h": "x-drupal-cache", "m": "", "l": "Drupal", "c": "cms"},
    {"h": "x-generator", "m": "drupal", "l": "Drupal", "c": "cms"},
    {"h": "x-generator", "m": "wordpress", "l": "WordPress", "c": "cms"},
    {"h": "x-wix-request-id", "m": "", "l": "Wix", "c": "cms"},
    {"h": "x-hubspot", "m": "", "l": "HubSpot CMS", "c": "cms"},
    {"h": "cf-ray", "m": "", "l": "Cloudflare", "c": "cdn"},
    {"h": "fly-request-id", "m": "", "l": "Fly.io", "c": "hosting"},
]

SEC_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

SPF_MAP = {
    "_spf.google.com": "Google Workspace", "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun", "amazonses.com": "Amazon SES",
    "_spf.salesforce.com": "Salesforce", "spf.mandrillapp.com": "Mailchimp",
    "servers.mcsv.net": "Mailchimp", "mail.zendesk.com": "Zendesk",
    "_spf.intercom.io": "Intercom", "spf.hubspotemail.net": "HubSpot",
    "_spf.qualtrics.com": "Qualtrics", "spf.mtasv.net": "Postmark",
    "_spf.pardot.com": "Salesforce Pardot", "stspg-customer.com": "Statuspage",
    "_spf.createsend.com": "Campaign Monitor", "sparkpostmail.com": "SparkPost",
    "billit": "Billit (invoicing)", "teamleader": "Teamleader",
    "exact.com": "Exact", "yuki": "Yuki", "mailjet.com": "Mailjet",
    "sendinblue": "Brevo (Sendinblue)", "brevo.com": "Brevo",
    "spf.flockmail": "Flock", "mailprotect.be": "Combell Mailprotect",
    "antispamcloud": "SpamExperts", "mailcontrol.com": "Forcepoint",
    "ppe-hosted.com": "Proofpoint", "_spf.freshemail.io": "Freshworks",
    "mailgun": "Mailgun", "klaviyomail.com": "Klaviyo",
    "cmail": "Campaign Monitor", "amazonses": "Amazon SES",
}

IP_HOSTS = [
    ("199.60.103.", "Squarespace"), ("185.230.6", "Wix"),
    ("104.16.", "Cloudflare"), ("104.17.", "Cloudflare"),
    ("104.18.", "Cloudflare"), ("104.19.", "Cloudflare"),
    ("172.67.", "Cloudflare"), ("13.", "AWS"), ("52.", "AWS"),
    ("54.", "AWS"), ("3.", "AWS"), ("34.", "Google Cloud"),
    ("35.", "Google Cloud"), ("20.", "Azure"), ("40.", "Azure"),
    ("76.76.21.", "Vercel"), ("75.2.", "Netlify"),
    ("99.83.", "AWS Global Accelerator"), ("151.101.", "Fastly"),
    ("146.75.", "Fastly"),
]

# ─── helpers ──────────────────────────────────────────────────────────────────

def uniq(lst: list) -> list:
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]

def push(lst: list, val):
    if val and val not in lst:
        lst.append(val)

def host_from_ip(ips: list[str]) -> list[str]:
    out = []
    for ip in ips:
        for prefix, label in IP_HOSTS:
            if ip.startswith(prefix):
                push(out, label)
                break
    return out

def dns_lookup(name: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=5)
        return [r.to_text() for r in answers]
    except Exception:
        return []

def parse_txt_records(records: list[str]) -> dict:
    out = {"crm": [], "marketing": [], "tools": [], "cms": []}
    spf = None
    has_dmarc = False
    dmarc_policy = None

    for raw in records:
        rec = raw.replace('"', "")
        low = rec.lower()
        if low.startswith("v=dmarc1"):
            has_dmarc = True
            m = re.search(r"p=(\w+)", rec, re.I)
            dmarc_policy = m.group(1) if m else "none"
            continue
        if low.startswith("v=spf1"):
            spf = rec
            for k, (label, cat) in TXT_FP.items():
                if k in low:
                    bucket = out.get(cat, out["tools"])
                    push(bucket, label)
            continue
        for k, (label, cat) in TXT_FP.items():
            if k in low:
                bucket = out.get(cat, out["tools"])
                push(bucket, label)

    return {**out, "spf": spf, "has_dmarc": has_dmarc, "dmarc_policy": dmarc_policy}

def parse_spf(spf: Optional[str]) -> dict:
    if not spf:
        return {"senders": [], "includes": []}
    includes = re.findall(r"include:(\S+)", spf, re.I)
    senders = []
    for inc in includes:
        inc_low = inc.lower()
        for k, label in SPF_MAP.items():
            if k in inc_low:
                push(senders, label)
    return {"senders": senders, "includes": includes}

def parse_verifications(records: list[str]) -> list[str]:
    out = []
    for raw in records:
        low = raw.replace('"', "").lower()
        if low.startswith("v=spf1") or low.startswith("v=dmarc1"):
            continue
        for k, label in VERIFY_FP.items():
            if k in low:
                push(out, label)
    return out

def parse_headers(headers: dict) -> dict:
    det = {"cdn": [], "server": [], "hosting": [], "cms": [], "security": []}
    for fp in HEADER_FP:
        val = headers.get(fp["h"])
        if val is None:
            continue
        if fp["m"] == "" or fp["m"] in val.lower():
            cat = fp["c"]
            if cat not in det:
                det[cat] = []
            push(det[cat], fp["l"])
    found_sec = [h for h in SEC_HEADERS if h in headers]
    det["security"] = found_sec
    return det

def parse_robots(content: str) -> dict:
    result = {
        "allows_gptbot": None,
        "allows_claudebot": None,
        "allows_perplexity": None,
        "allows_google_extended": None,
    }
    bot_map = {
        "gptbot": "allows_gptbot",
        "claudebot": "allows_claudebot",
        "perplexitybot": "allows_perplexity",
        "google-extended": "allows_google_extended",
    }
    current_agents = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            current_agents = []
            continue
        low = line.lower()
        if low.startswith("user-agent:"):
            agent_val = low.split(":", 1)[1].strip()
            current_agents = [agent_val]
        elif low.startswith("disallow:") or low.startswith("allow:"):
            directive, path = low.split(":", 1)
            path = path.strip()
            is_allow = directive == "allow"
            for agent in current_agents:
                for bot_key, field in bot_map.items():
                    if bot_key in agent or agent == "*":
                        if path in ("", "/"):
                            if agent == "*" and result[field] is None:
                                result[field] = is_allow if directive == "allow" else not (path == "/")
                            elif bot_key in agent:
                                result[field] = is_allow if directive == "allow" else not (path == "/")
    # anything still None means not mentioned = implicitly allowed
    for k in result:
        if result[k] is None:
            result[k] = True
    return result

def count_sitemap_urls(content: str) -> int:
    try:
        root = ET.fromstring(content)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = root.findall(".//sm:url", ns) or root.findall(".//url")
        return len(urls)
    except Exception:
        return 0

def parse_homepage(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("title")
    desc = soup.find("meta", attrs={"name": "description"})
    og_title = soup.find("meta", attrs={"property": "og:title"})
    og_desc = soup.find("meta", attrs={"property": "og:description"})

    schema_type = None
    schema_raw = None
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "")
            if isinstance(data, dict):
                schema_type = data.get("@type")
                schema_raw = data
                break
            elif isinstance(data, list) and data:
                schema_type = data[0].get("@type")
                schema_raw = data[0]
                break
        except Exception:
            pass

    body_text = soup.get_text(separator=" ", strip=True)
    word_count = len(body_text.split())

    return {
        "title": title.get_text(strip=True) if title else None,
        "description": desc.get("content") if desc else None,
        "og_title": og_title.get("content") if og_title else None,
        "og_description": og_desc.get("content") if og_desc else None,
        "schema_org_type": schema_type,
        "schema_org_raw": schema_raw,
        "word_count": word_count,
    }

def tld_from_domain(domain: str) -> str:
    parts = domain.rsplit(".", 2)
    return "." + parts[-1] if len(parts) >= 2 else domain

def infer_country(tld: str) -> Optional[str]:
    mapping = {
        ".be": "Belgium", ".nl": "Netherlands", ".lu": "Luxembourg",
        ".de": "Germany", ".fr": "France", ".uk": "United Kingdom",
        ".gb": "United Kingdom", ".us": "United States", ".ca": "Canada",
        ".au": "Australia", ".ie": "Ireland", ".ch": "Switzerland",
        ".at": "Austria", ".dk": "Denmark", ".se": "Sweden",
        ".no": "Norway", ".fi": "Finland", ".es": "Spain",
        ".it": "Italy", ".pl": "Poland", ".pt": "Portugal",
    }
    return mapping.get(tld)

# ─── HTTP fetches ──────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DomainScanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        r = await client.get(url, timeout=10, follow_redirects=True, headers=HEADERS)
        return r
    except Exception:
        return None

# ─── Claude GEO synthesis ─────────────────────────────────────────────────────

def geo_synthesis(domain: str, homepage: dict, llms_txt: Optional[str], stack: dict) -> dict:
    stack_summary = (
        f"Email: {stack.get('email_provider') or 'unknown'}, "
        f"DNS: {stack.get('dns_host') or 'unknown'}, "
        f"CMS: {', '.join(stack.get('cms', [])) or 'unknown'}, "
        f"CRM: {', '.join(stack.get('crm', [])) or 'unknown'}, "
        f"Marketing: {', '.join(stack.get('marketing_tools', [])) or 'unknown'}"
    )
    prompt = f"""You are analyzing {domain} for Generative Engine Optimization (GEO).

Homepage title: {homepage.get('title') or 'N/A'}
Homepage description: {homepage.get('description') or 'N/A'}
OG title: {homepage.get('og_title') or 'N/A'}
Schema.org type: {homepage.get('schema_org_type') or 'N/A'}
Word count: {homepage.get('word_count', 0)}
Tech stack: {stack_summary}
llms.txt present: {'yes' if llms_txt else 'no'}
llms.txt content: {llms_txt[:800] if llms_txt else 'N/A'}

Return a JSON object with exactly these keys:
- positioning: one sentence describing how this company positions itself (max 120 chars)
- target_market: who they serve (max 80 chars)
- tone_of_voice: e.g. "technical", "enterprise", "friendly B2B" (max 40 chars)
- ai_readiness_score: integer 0-100 (100 = fully AI-crawler-ready: has llms.txt, allows all bots, rich schema.org, clear positioning)
- geo_gaps: array of short strings, each a specific actionable gap (e.g. "No llms.txt", "Blocks GPTBot in robots.txt", "No schema.org markup")

Return only valid JSON, no markdown fences."""

    response = claude_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {
            "positioning": None, "target_market": None,
            "tone_of_voice": None, "ai_readiness_score": None, "geo_gaps": [],
        }
    parsed["raw"] = raw
    return parsed


# ─── Request model ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str
    email: Optional[str] = None

# ─── Main scan endpoint ───────────────────────────────────────────────────────

@app.post("/scan")
async def scan(request: Request, body: ScanRequest):
    raw_domain = body.domain.strip().lower()
    raw_domain = re.sub(r"^https?://", "", raw_domain)
    raw_domain = re.sub(r"^www\.", "", raw_domain)
    raw_domain = raw_domain.split("/")[0]

    # Hash requester IP for privacy
    client_ip = request.client.host if request.client else "unknown"
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]

    # ── 1. DNS lookups ────────────────────────────────────────────────────────
    mx_raw, txt_raw, ns_raw, a_raw, aaaa_raw, caa_raw = await asyncio.gather(
        asyncio.to_thread(dns_lookup, raw_domain, "MX"),
        asyncio.to_thread(dns_lookup, raw_domain, "TXT"),
        asyncio.to_thread(dns_lookup, raw_domain, "NS"),
        asyncio.to_thread(dns_lookup, raw_domain, "A"),
        asyncio.to_thread(dns_lookup, raw_domain, "AAAA"),
        asyncio.to_thread(dns_lookup, raw_domain, "CAA"),
    )

    # ── 2. HTTP fetches ───────────────────────────────────────────────────────
    async with httpx.AsyncClient(verify=False) as client:
        homepage_resp, robots_resp, llms_resp, llms_full_resp, sitemap_resp = await asyncio.gather(
            fetch_url(client, f"https://{raw_domain}"),
            fetch_url(client, f"https://{raw_domain}/robots.txt"),
            fetch_url(client, f"https://{raw_domain}/llms.txt"),
            fetch_url(client, f"https://{raw_domain}/llms-full.txt"),
            fetch_url(client, f"https://{raw_domain}/sitemap.xml"),
        )

    # ── 3. Parse homepage ─────────────────────────────────────────────────────
    homepage_html = homepage_resp.text if homepage_resp and homepage_resp.status_code < 400 else ""
    homepage = parse_homepage(homepage_html) if homepage_html else {}

    # ── 4. Parse robots.txt ───────────────────────────────────────────────────
    robots_content = ""
    robots_found = False
    if robots_resp and robots_resp.status_code == 200:
        robots_found = True
        robots_content = robots_resp.text
    robots = parse_robots(robots_content) if robots_found else {
        "allows_gptbot": None, "allows_claudebot": None,
        "allows_perplexity": None, "allows_google_extended": None,
    }

    # ── 5. Fingerprint ────────────────────────────────────────────────────────
    email_provider = None
    for rec in mx_raw:
        low = rec.lower()
        for k, label in EMAIL_MX.items():
            if k in low:
                email_provider = label
                break
        if email_provider:
            break

    dns_host = None
    for rec in ns_raw:
        low = rec.lower()
        for k, label in NS_HOSTS.items():
            if k in low:
                dns_host = label
                break
        if dns_host:
            break

    txt_parsed = parse_txt_records(txt_raw)
    spf_parsed = parse_spf(txt_parsed["spf"])
    verifications = parse_verifications(txt_raw)

    caa_issuers = []
    for r in caa_raw:
        m = re.search(r'issue\s+"?([^"\s]+)"?', r, re.I)
        if m:
            push(caa_issuers, m.group(1))

    # HTTP headers
    http_headers = {}
    if homepage_resp:
        http_headers = {k.lower(): v for k, v in homepage_resp.headers.items()}
    header_det = parse_headers(http_headers)

    ip_hosts = host_from_ip(a_raw)
    hosting = uniq(header_det.get("hosting", []) + ip_hosts)
    cdn = header_det.get("cdn", [])
    web_server = header_det.get("server", [])
    cms = uniq(header_det.get("cms", []) + txt_parsed.get("cms", []))
    crm = txt_parsed.get("crm", [])
    marketing_tools = uniq(txt_parsed.get("marketing", []) + spf_parsed["senders"])
    internal_tools = txt_parsed.get("tools", [])
    security_headers = header_det.get("security", [])

    # llms.txt
    llms_txt_found = bool(llms_resp and llms_resp.status_code == 200)
    llms_full_txt_found = bool(llms_full_resp and llms_full_resp.status_code == 200)
    llms_txt_content = llms_resp.text if llms_txt_found else None

    # sitemap
    sitemap_found = bool(sitemap_resp and sitemap_resp.status_code == 200)
    sitemap_count = count_sitemap_urls(sitemap_resp.text) if sitemap_found else 0

    tld = tld_from_domain(raw_domain)
    country = infer_country(tld)

    stack = {
        "email_provider": email_provider,
        "dns_host": dns_host,
        "cms": cms,
        "crm": crm,
        "marketing_tools": marketing_tools,
    }

    # ── 6. Claude GEO synthesis ───────────────────────────────────────────────
    geo = geo_synthesis(raw_domain, homepage, llms_txt_content, stack)

    # ── 7. Write scan to Supabase ─────────────────────────────────────────────
    scan_row = {
        "domain": raw_domain,
        "scanner_ip_hash": ip_hash,
        "scan_source": "lead_magnet",
        "is_latest": True,
        "domain_tld": tld,
        "inferred_country": country,
        "email_provider": email_provider,
        "dns_host": dns_host,
        "ipv4_addresses": a_raw,
        "ipv6_addresses": aaaa_raw,
        "subdomain_count": None,
        "ssl_issuer": caa_issuers[0] if caa_issuers else None,
        "cdn": cdn,
        "hosting": hosting,
        "web_server": web_server,
        "cms": cms,
        "crm": crm,
        "marketing_tools": marketing_tools,
        "internal_tools": internal_tools,
        "verified_vendors": verifications,
        "has_openai": "OpenAI (ChatGPT)" in verifications,
        "has_anthropic": "Anthropic (Claude)" in verifications,
        "has_apple_business": "Apple Business" in verifications,
        "spf_configured": bool(txt_parsed.get("spf")),
        "spf_senders": spf_parsed["senders"],
        "dmarc_configured": txt_parsed.get("has_dmarc", False),
        "dmarc_policy": txt_parsed.get("dmarc_policy"),
        "security_headers_count": len(security_headers),
        "security_headers": security_headers,
        "robots_txt_found": robots_found,
        "robots_txt_allows_gptbot": robots.get("allows_gptbot"),
        "robots_txt_allows_claudebot": robots.get("allows_claudebot"),
        "robots_txt_allows_perplexity": robots.get("allows_perplexity"),
        "robots_txt_allows_google_extended": robots.get("allows_google_extended"),
        "robots_txt_raw": robots_content or None,
        "llms_txt_found": llms_txt_found,
        "llms_full_txt_found": llms_full_txt_found,
        "llms_txt_content": llms_txt_content,
        "sitemap_found": sitemap_found,
        "sitemap_page_count": sitemap_count,
        "homepage_title": homepage.get("title"),
        "homepage_description": homepage.get("description"),
        "homepage_og_title": homepage.get("og_title"),
        "homepage_og_description": homepage.get("og_description"),
        "schema_org_type": homepage.get("schema_org_type"),
        "schema_org_raw": homepage.get("schema_org_raw"),
        "homepage_word_count": homepage.get("word_count"),
        "geo_positioning": geo.get("positioning"),
        "geo_target_market": geo.get("target_market"),
        "geo_tone_of_voice": geo.get("tone_of_voice"),
        "geo_ai_readiness_score": geo.get("ai_readiness_score"),
        "geo_gaps": geo.get("geo_gaps", []),
        "geo_synthesis_raw": geo.get("raw"),
        "geo_model_used": "claude-sonnet-4-6",
    }

    # Mark previous scans for this domain as not latest
    supabase.table("scans").update({"is_latest": False}).eq("domain", raw_domain).eq("is_latest", True).execute()

    result = supabase.table("scans").insert(scan_row).execute()
    scan_id = result.data[0]["id"] if result.data else None

    # ── 9. Write lead if email provided ───────────────────────────────────────
    if body.email and scan_id:
        lead_row = {
            "email": body.email,
            "domain": raw_domain,
            "first_scan_id": scan_id,
            "gdpr_consent": True,
            "gdpr_consent_at": "now()",
        }
        supabase.table("leads").upsert(lead_row, on_conflict="email").execute()

    # ── 10. Return result ─────────────────────────────────────────────────────
    return {
        "scan_id": scan_id,
        "domain": raw_domain,
        "email_provider": email_provider,
        "dns_host": dns_host,
        "ipv4_addresses": a_raw,
        "ipv6_addresses": aaaa_raw,
        "cdn": cdn,
        "hosting": hosting,
        "web_server": web_server,
        "cms": cms,
        "crm": crm,
        "marketing_tools": marketing_tools,
        "internal_tools": internal_tools,
        "verified_vendors": verifications,
        "has_openai": "OpenAI (ChatGPT)" in verifications,
        "has_anthropic": "Anthropic (Claude)" in verifications,
        "spf_configured": bool(txt_parsed.get("spf")),
        "spf_senders": spf_parsed["senders"],
        "dmarc_configured": txt_parsed.get("has_dmarc", False),
        "dmarc_policy": txt_parsed.get("dmarc_policy"),
        "security_headers": security_headers,
        "robots_txt_found": robots_found,
        "robots_txt_allows_gptbot": robots.get("allows_gptbot"),
        "robots_txt_allows_claudebot": robots.get("allows_claudebot"),
        "robots_txt_allows_perplexity": robots.get("allows_perplexity"),
        "robots_txt_allows_google_extended": robots.get("allows_google_extended"),
        "llms_txt_found": llms_txt_found,
        "llms_full_txt_found": llms_full_txt_found,
        "llms_txt_content": llms_txt_content,
        "sitemap_found": sitemap_found,
        "sitemap_page_count": sitemap_count,
        "homepage_title": homepage.get("title"),
        "homepage_description": homepage.get("description"),
        "homepage_og_title": homepage.get("og_title"),
        "homepage_og_description": homepage.get("og_description"),
        "schema_org_type": homepage.get("schema_org_type"),
        "homepage_word_count": homepage.get("word_count"),
        "geo_positioning": geo.get("positioning"),
        "geo_target_market": geo.get("target_market"),
        "geo_tone_of_voice": geo.get("tone_of_voice"),
        "geo_ai_readiness_score": geo.get("ai_readiness_score"),
        "geo_gaps": geo.get("geo_gaps", []),
        "tld": tld,
        "inferred_country": country,
    }
