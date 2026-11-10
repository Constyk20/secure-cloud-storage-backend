from storage import get_storage

PATH = "tests/connection-check.txt"
CONTENT = b"supabase connection ok"


def main():
    storage = get_storage()

    # Remove an old test object if it exists, then upload.
    try:
        storage.remove([PATH])
    except Exception:
        pass

    storage.upload(
        PATH,
        CONTENT,
        {"content-type": "text/plain", "upsert": "true"},
    )
    print("Upload succeeded.")

    downloaded = storage.download(PATH)
    print("Downloaded bytes:", downloaded)

    if downloaded != CONTENT:
        raise SystemExit("Download did not match what we uploaded.")

    storage.remove([PATH])
    print("Delete succeeded.")
    print("Supabase Storage connection is working.")


if __name__ == "__main__":
    main()