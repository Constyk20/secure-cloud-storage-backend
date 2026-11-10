from supabase import create_client, Client
from config import get_settings

settings = get_settings()

supabase: Client = create_client(
    settings.SUPABASE_URL,
    settings.SUPABASE_SERVICE_ROLE_KEY,
)


def get_storage():
    """
    Returns the Supabase Storage client for the private bucket.
    The service-role key bypasses Storage RLS, so this must stay on the server only.
    """
    return supabase.storage.from_(settings.SUPABASE_BUCKET_NAME)