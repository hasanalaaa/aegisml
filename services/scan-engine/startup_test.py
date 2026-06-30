import sys
sys.path.insert(0, '.')
try:
    from database import init_db, AsyncSessionLocal, ScanRecord
    from cache import get_cached_stats
    print("✅ All imports OK")
except Exception as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
