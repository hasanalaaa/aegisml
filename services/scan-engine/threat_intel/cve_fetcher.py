import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
import httpx
from sqlalchemy import select
from database import AsyncSessionLocal, CVERecord

logger = logging.getLogger("aegisml.threat_intel.cve_fetcher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# AI-related keywords to search for in NVD
KEYWORDS = ["pickle", "pytorch", "tensorflow", "keras", "huggingface", "safetensors", "gguf", "onnx", "machine learning model"]

async def fetch_cves_for_keyword(keyword: str, api_key: str | None = None) -> list[dict]:
    """Fetch CVEs from NVD for a specific keyword with exponential backoff."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20, # Limit to recent 20 for each keyword to avoid massive payloads
    }

    max_retries = 5
    base_delay = 2.0
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for attempt in range(max_retries):
            try:
                response = await client.get(NVD_API_URL, params=params, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("vulnerabilities", [])
                elif response.status_code == 403 or response.status_code == 429:
                    # Rate limit or forbidden
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"NVD API rate limit hit (Status {response.status_code}). Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"NVD API returned status {response.status_code}")
                    break
            except (httpx.RequestError, httpx.TimeoutException) as e:
                delay = base_delay * (2 ** attempt)
                logger.warning(f"NVD API request failed: {e}. Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
                
    return []

def parse_cve_item(item: dict) -> dict:
    """Extract relevant fields from the NVD JSON item."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")
    
    # Extract description
    descriptions = cve_data.get("descriptions", [])
    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
    
    # Extract CVSS Score
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
        
    # Extract Published Date
    published_date_str = cve_data.get("published")
    published_date = None
    if published_date_str:
        try:
            # NVD format: 2024-01-01T00:00:00.000
            published_date = datetime.fromisoformat(published_date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
            
    return {
        "cve_id": cve_id,
        "description": desc_en,
        "cvss_score": cvss_score,
        "published_date": published_date,
    }

async def fetch_and_store_ai_cves():
    """Main task to fetch AI CVEs and store them in the database."""
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        logger.info("No NVD_API_KEY provided. Using public tier with strict rate limits.")
        
    total_new = 0
    
    async with AsyncSessionLocal() as session:
        for keyword in KEYWORDS:
            logger.info(f"Fetching CVEs for keyword: {keyword}")
            vulnerabilities = await fetch_cves_for_keyword(keyword, api_key)
            
            for item in vulnerabilities:
                parsed = parse_cve_item(item)
                
                # Check if it already exists
                stmt = select(CVERecord).where(CVERecord.cve_id == parsed["cve_id"])
                existing = await session.scalar(stmt)
                
                if not existing:
                    new_cve = CVERecord(
                        cve_id=parsed["cve_id"],
                        description=parsed["description"],
                        cvss_score=parsed["cvss_score"],
                        published_date=parsed["published_date"],
                        affected_tech=keyword
                    )
                    session.add(new_cve)
                    total_new += 1
            
            # Commit after each keyword to save progress
            await session.commit()
            
            # Enforce a mandatory delay between keyword requests to respect public tier
            if not api_key:
                await asyncio.sleep(6.0) 
                
    logger.info(f"CVE fetch complete. Added {total_new} new CVEs to the database.")
