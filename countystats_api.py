from concurrent.futures import ThreadPoolExecutor
import requests



url = "https://api.census.gov/data/2022/acs/acs5"
params = {
    "get": "NAME,B01003_001E",
    "for": "county:*",
    "in": "state:12"
}
#12 = florida




od_url = (
    "https://public.opendatasoft.com/api/records/1.0/search/"
    "?dataset=georef-united-states-of-america-county"
    "&refine.ste_name=Florida"
    "&rows=1"
)

def _census(cty: str):
    if not cty or not isinstance(cty, str):
        return {"pop": None, "err": "Invalid county name"}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        try:
            data = r.json()
        except ValueError:
            return {"pop": None, "err": "invalid json"}
        hdr, rows = data[0], data[1:]
        search_str = cty.lower().strip() + " county,"
        match = next((row for row in rows if row[0].lower().startswith(search_str)), None)
        
        if not match:
            possible_matches = [row for row in rows if cty.lower().strip() in row[0].lower()]
            
            if not possible_matches:
                return {"pop": None, "note": "county not found"}
            match = possible_matches[0]
        idx = hdr.index("B01003_001E")
        return {"pop": int(match[idx])}
    except requests.exceptions.Timeout:
        return {"pop": None, "err": "timed out requst"}
    except Exception as e:
        return {"pop": None, "err": str(e)}






def _od(cty: str):
    if not cty or not isinstance(cty, str):
        return {"cfips": None, "err": "invalid name"}
    try:
        r = requests.get(od_url + f"&refine.coty_name={cty}", timeout=10)
        r.raise_for_status()
        try:
            js = r.json()
        
        except ValueError:
            return {"cfips": None, "err": "OD API - invalid json"}
        records = js.get("records", [])
        
        
        if not records:
            return {"cfips": None, "err": "no data - OD"}
        rec = records[0].get("fields", {})
        return {
            "cfips": rec.get("coty_code"),
            "sfips": rec.get("ste_code"),
            "bbox": rec.get("geo_shape", {}).get("bbox"),
        }
    except requests.exceptions.Timeout:
        return {"cfips": None, "err": "OD - timed out"}
    except Exception as e:
        return {"cfips": None, "err": str(e)}




def get_stats(cty: str):
    if not cty or not isinstance(cty, str):
        return {"error": "invalid county name"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_census, cty)
        f2 = pool.submit(_od, cty)
        c = f1.result()
        o = f2.result()
    return {
        "county": cty,
        "census": c,
        "ods": o
    }
