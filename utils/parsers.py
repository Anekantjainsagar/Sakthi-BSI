"""
SpiderFoot CSV Parser - Standalone (No Database)
Parses SpiderFoot CSV report directly using pandas.
Extracts manager's 16 data types + subdomains.
"""

import re
import pandas as pd
from io import StringIO
from datetime import datetime


# Manager's 16 data types → section mapping
TYPE_MAPPING = {
    "BLACKLISTED_COHOST":    "section_2_blacklisted_cohost",
    "CO_HOSTED_SITE":        "section_3_co_hosted_site",
    "CO_HOSTED_SITE_DOMAIN": "section_4_co_hosted_site_domain",
    "EMAILADDR":             "section_5_emailaddr",
    "EMAILADDR_GENERIC":     "section_6_emailaddr_generic",
    "HASH":                  "section_7_hash",
    "HTTP_CODE":             "section_8_http_code",
    "INTERESTING_FILE":      "section_9_interesting_file",
    "MALICIOUS_COHOST":      "section_10_malicious_cohost",
    "PUBLIC_CODE_REPO":      "section_11_public_code_repo",
    "SIMILARDOMAIN":         "section_12_similardomain",
    "SOFTWARE_USED":         "section_13_software_used",
    "SSL_CERTIFICATE_RAW":   "section_14_ssl_certificate_raw",
    "WEBSERVER_HTTPHEADERS": "section_15_webserver_httpheaders",
    "WEBSERVER_TECHNOLOGY":  "section_16_webserver_technology",
}

# Types used to extract subdomains
SUBDOMAIN_SOURCE_TYPES = [
    "AFFILIATE_DOMAIN_NAME",
    "AFFILIATE_INTERNET_NAME",
    "INTERNET_NAME",
    "DOMAIN_NAME_PARENT",
    "SSL_CERTIFICATE_RAW",
]


def _detect_columns(df):
    """
    Detect which DataFrame columns map to 'type' and 'data'.
    SpiderFoot CSV can use slightly different headers across versions.
    Returns (type_col, data_col, source_col).
    """
    lower_cols = {c.lower().strip(): c for c in df.columns}

    # --- type column ---
    for candidate in ["type", "event type", "module type", "source data type"]:
        if candidate in lower_cols:
            type_col = lower_cols[candidate]
            break
    else:
        # Fallback: first column that has known SF types
        sf_types = set(TYPE_MAPPING.keys()) | set(SUBDOMAIN_SOURCE_TYPES)
        type_col = None
        for col in df.columns:
            if df[col].astype(str).str.upper().isin(sf_types).any():
                type_col = col
                break
        if type_col is None:
            raise ValueError(
                f"Cannot identify 'type' column. Available columns: {list(df.columns)}"
            )

    # --- data column ---
    for candidate in ["data", "event data", "value"]:
        if candidate in lower_cols:
            data_col = lower_cols[candidate]
            break
    else:
        # Pick the column with the most unique values (usually the data column)
        remaining = [c for c in df.columns if c != type_col]
        data_col = max(remaining, key=lambda c: df[c].nunique(), default=remaining[0])

    # --- source column (optional) ---
    source_col = None
    for candidate in ["source", "source data", "module"]:
        if candidate in lower_cols:
            source_col = lower_cols[candidate]
            break

    return type_col, data_col, source_col


def parse_spiderfoot_csv(csv_content: str, target_domain: str = None):
    """
    Parse SpiderFoot CSV content (string).

    Parameters
    ----------
    csv_content : str
        Raw CSV text from SpiderFoot export.
    target_domain : str, optional
        Target domain (e.g. 'firstquality.com').  If None, tries to infer.

    Returns
    -------
    dict
        Same structure as BSI 2.0 agent_1_parser output:
        {section_1: {...}, section_2_blacklisted_cohost: [...], ..., section_17_subdomains: [...]}
    """

    # --- read CSV ---
    try:
        df = pd.read_csv(StringIO(csv_content), dtype=str, on_bad_lines="skip")
    except Exception:
        df = pd.read_csv(StringIO(csv_content), dtype=str, error_bad_lines=False)

    df = df.fillna("")
    total_records = len(df)

    # --- detect columns ---
    try:
        type_col, data_col, source_col = _detect_columns(df)
    except ValueError as e:
        return {"error": str(e)}

    # Normalise type column to upper-case for matching
    df["_type"] = df[type_col].str.strip().str.upper()
    df["_data"] = df[data_col].str.strip()
    df["_source"] = df[source_col].str.strip() if source_col else ""

    # --- infer target domain if not supplied ---
    if not target_domain:
        # Try to find a DOMAIN_NAME row first
        dn_rows = df[df["_type"] == "DOMAIN_NAME"]["_data"]
        if not dn_rows.empty:
            target_domain = dn_rows.iloc[0]
        else:
            # Fall back to most common root in EMAILADDR data
            email_rows = df[df["_type"] == "EMAILADDR"]["_data"]
            if not email_rows.empty:
                domains = email_rows.str.extract(r"@(.+)")[0].dropna()
                if not domains.empty:
                    target_domain = domains.mode()[0]
            else:
                target_domain = "unknown.domain"

    base_domain = target_domain.replace("www.", "")
    base_name = base_domain.split(".")[0]

    # All unique data types in the file
    all_data_types = sorted(df["_type"].unique().tolist())

    # --- initialise output structure ---
    output = {
        "section_1": {
            "target_domain": target_domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_records": total_records,
            "data_types_found": all_data_types,
            "total_count_of_data_types": len(all_data_types),
            "manager_filtered_types": 16,
        },
        "section_2_blacklisted_cohost": [],
        "section_3_co_hosted_site": [],
        "section_4_co_hosted_site_domain": [],
        "section_5_emailaddr": [],
        "section_6_emailaddr_generic": [],
        "section_7_hash": [],
        "section_8_http_code": [],
        "section_9_interesting_file": [],
        "section_10_malicious_cohost": [],
        "section_11_public_code_repo": [],
        "section_12_similardomain": [],
        "section_13_software_used": [],
        "section_14_ssl_certificate_raw": [],
        "section_15_webserver_httpheaders": [],
        "section_16_webserver_technology": [],
        "section_17_subdomains": [],
    }

    # Subdomain regex
    subdomain_pattern = re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)\."
        + re.escape(base_domain)
        + r"\b",
        re.IGNORECASE,
    )

    all_subdomain_rows = []
    seen: dict = {key: set() for key in output if isinstance(output[key], list)}

    for _, row in df.iterrows():
        dtype = row["_type"]
        data_val = row["_data"]
        source_val = row["_source"]

        if not data_val:
            continue

        # --- 15 manager types ---
        if dtype in TYPE_MAPPING:
            section = TYPE_MAPPING[dtype]

            if dtype == "SIMILARDOMAIN":
                # Only keep domains starting with the base name
                if not (
                    data_val.lower().startswith(base_name.lower() + ".")
                    or data_val.lower() == base_name.lower()
                ):
                    continue

            if data_val not in seen[section]:
                seen[section].add(data_val)
                output[section].append(
                    {"data": data_val, "source": source_val, "type": dtype}
                )

        # --- collect subdomain sources ---
        if dtype in SUBDOMAIN_SOURCE_TYPES:
            all_subdomain_rows.append(
                {"data": data_val, "source": source_val, "type": dtype}
            )

    # --- extract subdomains ---
    extracted_subdomains: set = set()
    for item in all_subdomain_rows:
        data_str = str(item["data"])

        # Direct FQDN match
        if data_str.lower().endswith("." + base_domain.lower()):
            candidate = data_str.lower().strip(".,;:()[]{}\"' ")
            if (
                candidate
                and "." in candidate
                and candidate not in (base_domain.lower(), "www." + base_domain.lower())
            ):
                extracted_subdomains.add(candidate)

        # Regex scan (useful for SSL cert raw text)
        for match in subdomain_pattern.finditer(data_str):
            full = match.group(0).lower()
            prefix = match.group(1).lower()
            if full not in (base_domain.lower(), "www." + base_domain.lower()):
                if prefix and prefix != "www":
                    clean = full.strip(".,;:()[]{}\"' ")
                    if clean and "." in clean:
                        extracted_subdomains.add(clean)

    for subdomain in sorted(extracted_subdomains):
        output["section_17_subdomains"].append(
            {
                "data": subdomain,
                "source": "Extracted from multiple SpiderFoot data types",
                "type": "SUBDOMAIN",
            }
        )

    return output


def get_section_counts(parsed_data: dict) -> dict:
    """Return counts per section (excluding section_1 metadata)."""
    counts = {}
    for key, value in parsed_data.items():
        if key != "section_1" and isinstance(value, list):
            counts[key] = len(value)
    return counts
