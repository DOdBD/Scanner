import asyncio
import hashlib
import ipaddress
import json
import re
import uuid as uuid_lib
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urljoin

from mistralai import Mistral
import dns.resolver
import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from supabase import create_client
import os

load_dotenv()

# ─── Rate limiter ─────────────────────────────────────────────────────────────
def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=_get_client_ip, default_limits=[])

def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"error": "Too many requests. Please try again later."}, status_code=429)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dodbd.github.io"],
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

# ─── SSRF protection ──────────────────────────────────────────────────────────
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",   # loopback + AWS/GCP metadata
        "0.0.0.0/8", "100.64.0.0/10",       # any + carrier-grade NAT
        "::1/128", "fc00::/7", "fe80::/10",  # IPv6 private
    ]
]

def _is_safe_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False

def _assert_safe_domain(domain: str) -> None:
    """Raises HTTPException(400) if domain is a raw private IP."""
    try:
        addr = ipaddress.ip_address(domain)
        if any(addr in net for net in _BLOCKED_NETWORKS):
            raise HTTPException(status_code=400, detail="Invalid domain.")
        raise HTTPException(status_code=400, detail="Raw IP addresses are not allowed.")
    except (ValueError, HTTPException) as e:
        if isinstance(e, HTTPException):
            raise

_supabase_url  = os.getenv("SUPABASE_URL") or ""
_supabase_key  = os.getenv("SUPABASE_KEY") or ""
_mistral_key   = os.getenv("MISTRAL_API_KEY") or ""
_brevo_key     = os.getenv("BREVO_API_KEY") or ""
_brevo_from    = os.getenv("BREVO_FROM_EMAIL") or ""

supabase = create_client(_supabase_url, _supabase_key) if _supabase_url and _supabase_key else None
mistral_client = Mistral(api_key=_mistral_key) if _mistral_key else None

@app.get("/health")
def health():
    return {
        "status": "ok",
        "SUPABASE_URL":    "set" if _supabase_url else "MISSING",
        "SUPABASE_KEY":    "set" if _supabase_key else "MISSING",
        "MISTRAL_API_KEY": "set" if _mistral_key  else "MISSING",
        "BREVO_API_KEY":   "set" if _brevo_key    else "MISSING",
    }

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
    "ahrefs-site-verification": ("Ahrefs", "tools"),
    "semrush": ("SEMrush", "tools"),
    "outreach-domain-verification": ("Outreach", "tools"),
    "salesloft-site-verification": ("Salesloft", "tools"),
    "spf.activecampaign.com": ("ActiveCampaign", "marketing"),
    "lemlist": ("Lemlist", "tools"),
    "apollo": ("Apollo", "tools"),
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
    "ahrefs-site-verification": "Ahrefs",
    "outreach-domain-verification": "Outreach",
    "salesloft-site-verification": "Salesloft",
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

# ─── HTML body fingerprints ────────────────────────────────────────────────────
# Each entry: pattern to search (case-insensitive) in raw HTML, label, category
# Categories: analytics | chat | intent | reviews | sales | ab_testing | cms | marketing | tools
HTML_FP = [
    # Analytics & tracking
    {"p": "hotjar.com",           "l": "Hotjar",              "c": "analytics"},
    {"p": "static.hotjar.com",    "l": "Hotjar",              "c": "analytics"},
    {"p": "mixpanel.com",         "l": "Mixpanel",            "c": "analytics"},
    {"p": "cdn.amplitude.com",    "l": "Amplitude",           "c": "analytics"},
    {"p": "clarity.ms",           "l": "Microsoft Clarity",   "c": "analytics"},
    {"p": "fullstory.com",        "l": "FullStory",           "c": "analytics"},
    {"p": "heap.io",              "l": "Heap",                "c": "analytics"},
    {"p": "heapanalytics.com",    "l": "Heap",                "c": "analytics"},
    {"p": "plausible.io",         "l": "Plausible",           "c": "analytics"},
    {"p": "posthog.com",          "l": "PostHog",             "c": "analytics"},
    {"p": "matomo",               "l": "Matomo",              "c": "analytics"},
    {"p": "googletagmanager.com", "l": "Google Tag Manager",  "c": "analytics"},
    {"p": "google-analytics.com", "l": "Google Analytics",    "c": "analytics"},
    {"p": "gtag/js",              "l": "Google Analytics",    "c": "analytics"},
    # Chat & support
    {"p": "js.drift.com",         "l": "Drift",               "c": "chat"},
    {"p": "drift.com/include",    "l": "Drift",               "c": "chat"},
    {"p": "client.crisp.chat",    "l": "Crisp",               "c": "chat"},
    {"p": "tidiochat.com",        "l": "Tidio",               "c": "chat"},
    {"p": "widget.intercom.io",   "l": "Intercom",            "c": "chat"},
    {"p": "js.intercomcdn.com",   "l": "Intercom",            "c": "chat"},
    {"p": "static.zdassets.com",  "l": "Zendesk Chat",        "c": "chat"},
    {"p": "freshchat.com",        "l": "Freshchat",           "c": "chat"},
    {"p": "embed.tawk.to",        "l": "Tawk.to",             "c": "chat"},
    {"p": "userlike.com",         "l": "Userlike",            "c": "chat"},
    {"p": "chatra.io",            "l": "Chatra",              "c": "chat"},
    # Intent / visitor identification (high GTM value for Benelux B2B)
    {"p": "serve.albacross.com",  "l": "Albacross",           "c": "intent"},
    {"p": "albacross.com",        "l": "Albacross",           "c": "intent"},
    {"p": "script.leadinfo.com",  "l": "Leadinfo",            "c": "intent"},
    {"p": "leadinfo.com",         "l": "Leadinfo",            "c": "intent"},
    {"p": "lf-cdn.com",           "l": "Leadfeeder/Dealfront","c": "intent"},
    {"p": "leadfeeder.com",       "l": "Leadfeeder/Dealfront","c": "intent"},
    {"p": "ws.zoominfo.com",      "l": "ZoomInfo WebSights",  "c": "intent"},
    {"p": "6sc.co",               "l": "6sense",              "c": "intent"},
    {"p": "clearbit.com/e",       "l": "Clearbit Reveal",     "c": "intent"},
    # Review platforms
    {"p": "widget.trustpilot.com","l": "Trustpilot",          "c": "reviews"},
    {"p": "trustpilot.com",       "l": "Trustpilot",          "c": "reviews"},
    {"p": "app.g2.com",           "l": "G2",                  "c": "reviews"},
    {"p": "g2.com/products",      "l": "G2",                  "c": "reviews"},
    {"p": "widget.reviews.io",    "l": "Reviews.io",          "c": "reviews"},
    {"p": "capterra.com",         "l": "Capterra",            "c": "reviews"},
    # Sales engagement & outreach
    {"p": "lemlist.com",          "l": "Lemlist",             "c": "sales"},
    {"p": "outreach.io",          "l": "Outreach",            "c": "sales"},
    {"p": "salesloft.com",        "l": "Salesloft",           "c": "sales"},
    {"p": "apollo.io",            "l": "Apollo",              "c": "sales"},
    {"p": "reply.io",             "l": "Reply.io",            "c": "sales"},
    {"p": "lusha.com",            "l": "Lusha",               "c": "sales"},
    # A/B testing & optimisation
    {"p": "vwo.com",              "l": "VWO",                 "c": "ab_testing"},
    {"p": "optimizely.com",       "l": "Optimizely",          "c": "ab_testing"},
    {"p": "abtasty.com",          "l": "AB Tasty",            "c": "ab_testing"},
    {"p": "convert.com/services", "l": "Convert",             "c": "ab_testing"},
    # CMS detection via scripts
    {"p": "wp-content",           "l": "WordPress",           "c": "cms"},
    {"p": "wp-includes",          "l": "WordPress",           "c": "cms"},
    {"p": "hs-scripts.com",       "l": "HubSpot CMS",         "c": "cms"},
    {"p": "hsforms.com",          "l": "HubSpot CMS",         "c": "cms"},
    {"p": "wixstatic.com",        "l": "Wix",                 "c": "cms"},
    {"p": "ghost.io",             "l": "Ghost",               "c": "cms"},
    {"p": "webflow.io",           "l": "Webflow",             "c": "cms"},
    # Paid ads & retargeting
    {"p": "connect.facebook.net", "l": "Meta Pixel",          "c": "marketing"},
    {"p": "snap.licdn.com",       "l": "LinkedIn Insight Tag","c": "marketing"},
    {"p": "bat.bing.com",         "l": "Microsoft Ads",       "c": "marketing"},
    {"p": "googleadservices.com", "l": "Google Ads",          "c": "marketing"},
    # Other tools
    {"p": "vidyard.com",          "l": "Vidyard",             "c": "tools"},
    {"p": "wistia.com",           "l": "Wistia",              "c": "tools"},
    {"p": "pendo.io",             "l": "Pendo",               "c": "tools"},
    {"p": "appcues.com",          "l": "Appcues",             "c": "tools"},
    {"p": "walkme.com",           "l": "WalkMe",              "c": "tools"},
    {"p": "cdn.segment.com",      "l": "Segment",             "c": "tools"},
    {"p": "chilipiper.com",       "l": "Chili Piper",         "c": "tools"},
    {"p": "gainsight.com",        "l": "Gainsight",           "c": "tools"},
    {"p": "ahrefs-site-verification","l": "Ahrefs",           "c": "tools"},
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
    ("185.230.6", "Wix"),
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

# ─── Company name extraction ──────────────────────────────────────────────────

def extract_company_name(title: Optional[str], domain: str) -> str:
    if title:
        for sep in [" | ", " - ", " — ", " · ", " :: "]:
            if sep in title:
                return title.split(sep)[0].strip()
        if len(title) < 40:
            return title.strip()
    name = domain.split(".")[0]
    return name.replace("-", " ").replace("_", " ").title()

# ─── Wikipedia check ──────────────────────────────────────────────────────────

async def check_wikipedia(company_name: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                "https://en.wikipedia.org/w/api.php",
                params={
                    "action": "query", "list": "search",
                    "srsearch": company_name, "format": "json",
                    "srlimit": "3", "origin": "*",
                },
                timeout=8, headers=HEADERS,
            )
            results = r.json().get("query", {}).get("search", [])
            name_low = company_name.lower()
            for result in results:
                title_low = result["title"].lower()
                if name_low in title_low or title_low.startswith(name_low):
                    url = f"https://en.wikipedia.org/wiki/{result['title'].replace(' ', '_')}"
                    return {"found": True, "url": url, "title": result["title"]}
    except Exception:
        pass
    return {"found": False, "url": None, "title": None}

# ─── Schema.org completeness ───────────────────────────────────────────────────

SCHEMA_ORG_SCORED_FIELDS = {
    "name": 10, "description": 10, "url": 10,
    "logo": 5, "image": 5,
    "sameAs": 15,           # links to LinkedIn, Crunchbase, Wikipedia — critical for AI entity linking
    "foundingDate": 5, "numberOfEmployees": 5,
    "address": 5, "areaServed": 5,
    "telephone": 5, "email": 5,
    "contactPoint": 5, "potentialAction": 5,
}

def parse_html_body(html: str) -> dict:
    out = {"analytics": [], "chat": [], "intent": [], "reviews": [], "sales": [], "ab_testing": [], "cms": [], "marketing": [], "tools": []}
    html_low = html.lower()
    for fp in HTML_FP:
        if fp["p"].lower() in html_low:
            bucket = out.get(fp["c"], out["tools"])
            push(bucket, fp["l"])
    return out

def score_schema_org(schema_raw: Optional[dict]) -> tuple:
    if not schema_raw:
        return 0, []
    present = [f for f, pts in SCHEMA_ORG_SCORED_FIELDS.items() if schema_raw.get(f)]
    score = sum(SCHEMA_ORG_SCORED_FIELDS[f] for f in present)
    return min(score, 100), present

# ─── Stack delta ───────────────────────────────────────────────────────────────

def compute_stack_delta(current: dict, previous: dict) -> dict:
    fields = ["cms", "crm", "marketing_tools", "internal_tools", "verified_vendors", "cdn", "hosting"]
    delta = {}
    for field in fields:
        curr = set(current.get(field) or [])
        prev = set(previous.get(field) or [])
        added = sorted(curr - prev)
        removed = sorted(prev - curr)
        if added or removed:
            delta[field] = {}
            if added: delta[field]["added"] = added
            if removed: delta[field]["removed"] = removed
    return delta

# ─── HTTP fetches ──────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DomainScanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

async def _ssrf_redirect_guard(response: httpx.Response) -> None:
    """Block redirects to raw private IPs (e.g. 169.254.169.254)."""
    if response.is_redirect:
        location = response.headers.get("location", "")
        if location:
            host = httpx.URL(location).host
            if host:
                try:
                    # Only act if the redirect target is a raw IP address
                    if not _is_safe_ip(host):
                        raise httpx.InvalidURL(f"Redirect to private IP blocked: {host}")
                except ValueError:
                    pass  # Not an IP address — hostname redirects are allowed

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        r = await client.get(url, timeout=10, follow_redirects=True, headers=HEADERS)
        return r
    except Exception:
        return None

# ─── Mistral GEO synthesis ────────────────────────────────────────────────────

def geo_synthesis(
    domain: str,
    homepage: dict,
    llms_txt: Optional[str],
    stack: dict,
    wikipedia: dict,
    schema_completeness: int,
    stack_delta: dict,
) -> dict:
    stack_summary = (
        f"Email: {stack.get('email_provider') or 'unknown'}, "
        f"DNS: {stack.get('dns_host') or 'unknown'}, "
        f"CMS: {', '.join(stack.get('cms', [])) or 'unknown'}, "
        f"CRM: {', '.join(stack.get('crm', [])) or 'unknown'}, "
        f"Marketing: {', '.join(stack.get('marketing_tools', [])) or 'unknown'}"
    )
    delta_summary = ""
    if stack_delta:
        parts = []
        for field, changes in stack_delta.items():
            if changes.get("added"):
                parts.append(f"+{', '.join(changes['added'])} ({field})")
            if changes.get("removed"):
                parts.append(f"-{', '.join(changes['removed'])} ({field})")
        delta_summary = "Stack changes since last scan: " + "; ".join(parts)

    prompt = f"""You are analyzing {domain} for Generative Engine Optimization (GEO).

Homepage title: {homepage.get('title') or 'N/A'}
Homepage description: {homepage.get('description') or 'N/A'}
Schema.org type: {homepage.get('schema_org_type') or 'N/A'}
Schema.org completeness: {schema_completeness}/100
Word count: {homepage.get('word_count', 0)}
Tech stack: {stack_summary}
Wikipedia presence: {'yes — ' + wikipedia.get('url', '') if wikipedia.get('found') else 'no'}
llms.txt present: {'yes' if llms_txt else 'no'}
llms.txt content: {llms_txt[:800] if llms_txt else 'N/A'}
{delta_summary}

Return a JSON object with exactly these keys:
- positioning: one sentence describing how this company positions itself (max 120 chars)
- target_market: who they serve (max 80 chars)
- tone_of_voice: e.g. "technical", "enterprise", "friendly B2B" (max 40 chars)
- ai_readiness_score: integer 0-100 (100 = fully AI-crawler-ready: has llms.txt, allows all bots, rich schema.org, Wikipedia presence, clear positioning)
- geo_gaps: array of short strings, each a specific actionable gap (e.g. "No llms.txt", "No Wikipedia page", "Schema.org completeness only 15/100", "No schema.org markup")"""

    if not mistral_client:
        return {"positioning": None, "target_market": None, "tone_of_voice": None,
                "ai_readiness_score": None, "geo_gaps": [], "raw": None}
    try:
        response = mistral_client.chat.complete(
            model="mistral-small-latest",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {
                "positioning": None, "target_market": None,
                "tone_of_voice": None, "ai_readiness_score": None, "geo_gaps": [],
            }
        parsed["raw"] = raw
        return parsed
    except Exception as e:
        print(f"[geo_synthesis] ERROR: {e}")
        return {
            "positioning": None, "target_market": None,
            "tone_of_voice": None, "ai_readiness_score": None,
            "geo_gaps": [], "raw": None,
        }


# ─── Request model ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str

# ─── Main scan endpoint ───────────────────────────────────────────────────────

@app.post("/scan")
@limiter.limit("30/hour")
async def scan(request: Request, body: ScanRequest):
    raw_domain = body.domain.strip().lower()
    raw_domain = re.sub(r"^https?://", "", raw_domain)
    raw_domain = re.sub(r"^www\.", "", raw_domain)
    raw_domain = raw_domain.split("/")[0].split(":")[0]  # strip path and port

    if not raw_domain or "." not in raw_domain:
        raise HTTPException(status_code=400, detail="Invalid domain.")

    # SSRF: block raw IP addresses immediately
    _assert_safe_domain(raw_domain)

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

    # SSRF: block if any resolved IP is in a private range
    for ip in a_raw + aaaa_raw:
        if not _is_safe_ip(ip):
            raise HTTPException(status_code=400, detail="Domain resolves to a non-routable address.")

    # ── 2. HTTP fetches ───────────────────────────────────────────────────────
    async with httpx.AsyncClient(
        verify=True,
        follow_redirects=True,
        max_redirects=3,
        event_hooks={"response": [_ssrf_redirect_guard]},
    ) as client:
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

    # HTML body fingerprinting
    html_det = parse_html_body(homepage_html) if homepage_html else {}

    cms = uniq(header_det.get("cms", []) + txt_parsed.get("cms", []) + html_det.get("cms", []))
    crm = txt_parsed.get("crm", [])
    marketing_tools = uniq(txt_parsed.get("marketing", []) + spf_parsed["senders"] + html_det.get("marketing", []))
    internal_tools = uniq(txt_parsed.get("tools", []) + html_det.get("tools", []) + html_det.get("sales", []) + html_det.get("ab_testing", []))
    analytics_tools = html_det.get("analytics", [])
    chat_tools = html_det.get("chat", [])
    intent_tools = html_det.get("intent", [])
    review_platforms = html_det.get("reviews", [])
    security_headers = header_det.get("security", [])

    # llms.txt — strip HTML if the URL returns an HTML page instead of plain text
    llms_txt_found = bool(llms_resp and llms_resp.status_code == 200)
    llms_full_txt_found = bool(llms_full_resp and llms_full_resp.status_code == 200)
    if llms_txt_found:
        raw_llms = llms_resp.text.strip()
        if raw_llms.lower().startswith("<!doctype") or raw_llms.lower().startswith("<html"):
            soup = BeautifulSoup(raw_llms, "html.parser")
            llms_txt_content = soup.get_text(separator="\n", strip=True)[:5000]
        else:
            llms_txt_content = raw_llms[:5000]
    else:
        llms_txt_content = None

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
        "internal_tools": internal_tools,
        "analytics_tools": analytics_tools,
        "chat_tools": chat_tools,
        "intent_tools": intent_tools,
        "review_platforms": review_platforms,
        "verified_vendors": verifications,
        "cdn": cdn,
        "hosting": hosting,
    }

    # ── 6. Wikipedia + schema.org scoring + previous scan delta ──────────────
    company_name = extract_company_name(homepage.get("title"), raw_domain)
    wikipedia, (schema_completeness, schema_fields) = await asyncio.gather(
        check_wikipedia(company_name),
        asyncio.to_thread(score_schema_org, homepage.get("schema_org_raw")),
    )

    stack_delta = {}
    if supabase:
        try:
            prev = supabase.table("scans").select(
                "cms,crm,marketing_tools,internal_tools,verified_vendors,cdn,hosting"
            ).eq("domain", raw_domain).eq("is_latest", True).limit(1).execute()
            if prev.data:
                stack_delta = compute_stack_delta(stack, prev.data[0])
        except Exception:
            pass

    # ── 7. GEO synthesis ──────────────────────────────────────────────────────
    geo = geo_synthesis(raw_domain, homepage, llms_txt_content, stack, wikipedia, schema_completeness, stack_delta)

    # ── 8. Write scan to Supabase ─────────────────────────────────────────────
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
        "analytics_tools": analytics_tools,
        "chat_tools": chat_tools,
        "intent_tools": intent_tools,
        "review_platforms": review_platforms,
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
        "robots_txt_raw": robots_content[:5000] if robots_content else None,
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
        "geo_model_used": "mistral-small-latest",
        "wikipedia_found": wikipedia.get("found", False),
        "wikipedia_url": wikipedia.get("url"),
        "schema_org_completeness": schema_completeness,
        "schema_org_fields": schema_fields,
        "stack_delta": stack_delta or None,
    }

    scan_id = None
    if supabase:
        try:
            supabase.table("scans").update({"is_latest": False}).eq("domain", raw_domain).eq("is_latest", True).execute()
            result = supabase.table("scans").insert(scan_row).execute()
            scan_id = result.data[0]["id"] if result.data else None
        except Exception as e:
            print(f"[supabase] scan write failed: {e}")

    # ── 9. Return result ──────────────────────────────────────────────────────
    # Lead capture happens in /send-report only, after explicit GDPR consent.
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
        "analytics_tools": analytics_tools,
        "chat_tools": chat_tools,
        "intent_tools": intent_tools,
        "review_platforms": review_platforms,
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
        "wikipedia_found": wikipedia.get("found", False),
        "wikipedia_url": wikipedia.get("url"),
        "schema_org_completeness": schema_completeness,
        "schema_org_fields": schema_fields,
        "stack_delta": stack_delta or None,
        "tld": tld,
        "inferred_country": country,
    }


# ─── Email report ─────────────────────────────────────────────────────────────

def _score_color(score):
    if score is None: return "#9CA3AF"
    if score >= 70: return "#16A34A"
    if score >= 40: return "#D97706"
    return "#DC2626"

def build_email_html(s: dict) -> str:
    domain = s.get("domain", "")
    score = s.get("geo_ai_readiness_score")
    sc = _score_color(score)
    gaps = s.get("geo_gaps") or []

    def row(label, value, value_color="#1A2B4A"):
        if not value: return ""
        return (f"<tr>"
                f"<td style='padding:10px 12px;border-bottom:1px solid #F3F4F6;color:#6B7280;font-size:15px;width:160px;vertical-align:top'>{label}</td>"
                f"<td style='padding:10px 12px;border-bottom:1px solid #F3F4F6;font-size:15px;color:{value_color};font-weight:600'>{value}</td>"
                f"</tr>")

    def badge(label, ok):
        color = "#16A34A" if ok else "#DC2626"
        mark = "&#10003;" if ok else "&#10007;"
        return (f"<tr>"
                f"<td style='padding:10px 12px;border-bottom:1px solid #F3F4F6;color:#6B7280;font-size:15px;width:200px'>{label}</td>"
                f"<td style='padding:10px 12px;border-bottom:1px solid #F3F4F6;font-size:15px;font-weight:700;color:{color}'>{mark} {'Allowed' if ok else 'Blocked'}</td>"
                f"</tr>")

    score_block = ""
    if score is not None:
        score_block = (
            f"<table width='100%' cellpadding='0' cellspacing='0' style='margin-bottom:28px'><tr>"
            f"<td style='background:{sc}10;border:2px solid {sc}30;border-radius:10px;padding:20px 24px;text-align:center'>"
            f"<div style='font-size:52px;font-weight:800;color:{sc};line-height:1'>{score}</div>"
            f"<div style='font-size:14px;color:#6B7280;margin-top:4px'>AI readiness score / 100</div>"
            f"</td></tr></table>"
        )

    positioning_block = ""
    if s.get("geo_positioning"):
        positioning_block = (
            f"<div style='background:#F0FDFA;border-left:4px solid #00B4A0;padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:28px'>"
            f"<div style='font-size:12px;font-weight:700;color:#00B4A0;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px'>Positioning</div>"
            f"<div style='font-size:16px;color:#1A2B4A;line-height:1.5'>{s['geo_positioning']}</div>"
            f"{'<div style=\"font-size:14px;color:#6B7280;margin-top:6px\">Target: ' + s['geo_target_market'] + '</div>' if s.get('geo_target_market') else ''}"
            f"</div>"
        )

    gaps_block = ""
    if gaps:
        gap_items = "".join(
            f"<tr><td style='padding:10px 12px;border-bottom:1px solid #FEE2E2;font-size:15px;color:#DC2626'>&#9656; {g}</td></tr>"
            for g in gaps
        )
        gaps_block = (
            f"<div style='margin-bottom:28px'>"
            f"<div style='font-size:13px;font-weight:700;color:#1A2B4A;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px'>GEO Gaps to fix</div>"
            f"<table width='100%' cellpadding='0' cellspacing='0' style='background:#FFF5F5;border-radius:8px;overflow:hidden'>{gap_items}</table>"
            f"</div>"
        )

    stack_rows = "".join(filter(None, [
        row("Email", s.get("email_provider")),
        row("DNS host", s.get("dns_host")),
        row("CDN", ", ".join(s.get("cdn") or [])),
        row("Hosting", ", ".join(s.get("hosting") or [])),
        row("CMS", ", ".join(s.get("cms") or [])),
        row("CRM", ", ".join(s.get("crm") or [])),
        row("Marketing", ", ".join(s.get("marketing_tools") or [])),
    ]))

    wiki = s.get("wikipedia_url")
    wiki_val = f'<a href="{wiki}" style="color:#0891B2;text-decoration:none">&#10003; Wikipedia page found</a>' if wiki else "&#10007; No Wikipedia page"
    wiki_color = "#16A34A" if wiki else "#DC2626"

    bot_badges = "".join(filter(None, [
        badge("GPTBot (ChatGPT)", s.get("robots_txt_allows_gptbot")) if s.get("robots_txt_allows_gptbot") is not None else "",
        badge("ClaudeBot (Anthropic)", s.get("robots_txt_allows_claudebot")) if s.get("robots_txt_allows_claudebot") is not None else "",
        badge("PerplexityBot", s.get("robots_txt_allows_perplexity")) if s.get("robots_txt_allows_perplexity") is not None else "",
        badge("Google-Extended", s.get("robots_txt_allows_google_extended")) if s.get("robots_txt_allows_google_extended") is not None else "",
    ]))
    llms_color = "#16A34A" if s.get("llms_txt_found") else "#DC2626"
    llms_mark = "&#10003;" if s.get("llms_txt_found") else "&#10007;"

    def section(title):
        return f"<div style='font-size:13px;font-weight:700;color:#1A2B4A;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px;margin-top:28px'>{title}</div>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Domain scan: {domain}</title></head>
<body style="margin:0;padding:16px;background:#F1F5F9;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;max-width:600px">
  <tr><td style="background:#1A2B4A;padding:28px 32px;border-bottom:4px solid #00B4A0">
    <div style="font-size:12px;font-weight:700;color:#00B4A0;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px">Domain Scan Report</div>
    <div style="font-size:28px;font-weight:800;color:#ffffff">{domain}</div>
  </td></tr>
  <tr><td style="padding:32px">
    {score_block}{positioning_block}{gaps_block}
    {section("Tech Stack")}
    <table width="100%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #E5E7EB">{stack_rows}</table>
    {section("Knowledge Graph")}
    <div style="font-size:15px;font-weight:600;color:{wiki_color};margin-bottom:20px">{wiki_val}</div>
    {section("AI Crawler Access")}
    <table width="100%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #E5E7EB">
      {bot_badges}
      <tr><td style="padding:10px 12px;border-bottom:1px solid #F3F4F6;color:#6B7280;font-size:15px;width:200px">llms.txt</td>
          <td style="padding:10px 12px;border-bottom:1px solid #F3F4F6;font-size:15px;font-weight:700;color:{llms_color}">{llms_mark} {"Found" if s.get("llms_txt_found") else "Not found"}</td></tr>
    </table>
  </td></tr>
  <tr><td style="background:#F8FAFC;padding:20px 32px;border-top:1px solid #E5E7EB">
    <p style="margin:0;font-size:12px;color:#9CA3AF;line-height:1.8">
      You requested this report via Domain Stack Scanner. Your email was used solely to deliver this report.<br>
      To request deletion of your data, reply to this email with "delete my data".<br>
      <strong style="color:#6B7280">Data controller:</strong> Domain Stack Scanner &nbsp;&middot;&nbsp;
      <strong style="color:#6B7280">Legal basis:</strong> Art. 6(1)(a) GDPR &nbsp;&middot;&nbsp;
      <a href="https://www.dataprotectionauthority.be" style="color:#9CA3AF">Belgian DPA</a>
    </p>
  </td></tr>
</table>
</td></tr></table>
</body></html>"""


class SendReportRequest(BaseModel):
    scan_id: str
    email: EmailStr
    consent: bool


@app.post("/send-report")
@limiter.limit("30/hour")
async def send_report_endpoint(request: Request, body: SendReportRequest):
    if not body.consent:
        return {"ok": False, "error": "Consent is required."}
    if not _brevo_key or not _brevo_from:
        return {"ok": False, "error": "Email sending is not configured on this server."}
    if not supabase:
        return {"ok": False, "error": "Database not configured."}

    # Validate scan_id is a proper UUID before hitting the DB
    try:
        uuid_lib.UUID(body.scan_id)
    except ValueError:
        return {"ok": False, "error": "Invalid scan ID."}

    result = supabase.table("scans").select("*").eq("id", body.scan_id).limit(1).execute()
    if not result.data:
        return {"ok": False, "error": "Scan not found."}

    scan = result.data[0]
    html = build_email_html(scan)

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": _brevo_key, "Content-Type": "application/json"},
            json={
                "sender": {"name": "Domain Stack Scanner", "email": _brevo_from},
                "to": [{"email": body.email}],
                "subject": f"Your domain scan report: {scan.get('domain', '')}",
                "htmlContent": html,
            },
            timeout=15,
        )

    if r.status_code not in (200, 201):
        return {"ok": False, "error": f"Email delivery failed ({r.status_code})."}

    try:
        if supabase:
            supabase.table("leads").upsert({
                "email": body.email,
                "domain": scan.get("domain"),
                "first_scan_id": body.scan_id,
                "gdpr_consent": True,
                "gdpr_consent_at": "now()",
            }, on_conflict="email").execute()
    except Exception:
        pass

    return {"ok": True}
