"""
upload_csv_to_supabase.py
=========================
Automated CSV dataset importer for Supabase.

Uploads CSV datasets:
  1. facebook_fake_account_dataset_1M.csv  ->  facebook_dataset table
  2. instagram_fake_account_dataset_1M-1.csv -> instagram_dataset table
  3. data/synthetic_accounts.csv             ->  synthetic_accounts table

Usage:
  python upload_csv_to_supabase.py
"""
import os
import sys
import math
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv(".env.local")
load_dotenv(".env")

SUPABASE_URL = os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
SUPABASE_KEY = (
    os.environ.get("SUPABASE_SECRET_KEY")
    or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    or os.environ.get("SUPABASE_PUBLISHABLE_KEY")
    or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
)

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[ERROR] Supabase URL or Key not found in .env / .env.local")
    sys.exit(1)

client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
CHUNK_SIZE = 1000  # Insert 1000 rows per batch HTTP call


def sanitize_val(v):
    if pd.isna(v):
        return None
    if isinstance(v, (float, int)) and math.isnan(v):
        return None
    return v


def upload_dataset(csv_path: str, table_name: str, max_rows: int = None):
    if not os.path.exists(csv_path):
        print(f"[SKIP] File {csv_path} does not exist.")
        return

    print(f"\n==========================================")
    print(f"Uploading {csv_path} -> Supabase table: '{table_name}'")
    print(f"==========================================")

    df = pd.read_csv(csv_path)
    if max_rows:
        df = df.iloc[:max_rows]

    total_rows = len(df)
    print(f"Total rows to insert: {total_rows:,}")

    inserted = 0
    for i in range(0, total_rows, CHUNK_SIZE):
        chunk = df.iloc[i : i + CHUNK_SIZE]
        records = []
        for _, row in chunk.iterrows():
            rec = {col: sanitize_val(row[col]) for col in chunk.columns}
            records.append(rec)

        try:
            res = client.table(table_name).insert(records).execute()
            inserted += len(records)
            pct = (inserted / total_rows) * 100
            print(f"  Inserted {inserted:,} / {total_rows:,} rows ({pct:.1f}%) ...")
        except Exception as exc:
            print(f"  [ERROR] Batch insert failed at index {i}: {exc}")
            print("  Make sure you ran create_dataset_tables.sql in Supabase SQL Editor first!")
            break

    print(f"[SUCCESS] Upload finished for table '{table_name}' ({inserted:,} rows inserted).\n")


if __name__ == "__main__":
    print("🚀 Starting Supabase Dataset Upload ...")
    
    # 1. Upload Synthetic Accounts
    upload_dataset("data/synthetic_accounts.csv", "synthetic_accounts")
    
    # 2. Upload Facebook Dataset (first 10,000 rows for fast demonstration)
    upload_dataset("facebook_fake_account_dataset_1M.csv", "facebook_dataset", max_rows=10000)
    
    # 3. Upload Instagram Dataset (first 10,000 rows for fast demonstration)
    upload_dataset("instagram_fake_account_dataset_1M-1.csv", "instagram_dataset", max_rows=10000)
    
    print("🎉 Dataset upload routine completed!")
