import os
import tempfile
import contextlib
import logging

logger = logging.getLogger(__name__)

_s3_client = None


# lazy-initialise the s3 client so boto3 is only imported when s3 is actually used
def _get_s3():
    global _s3_client
    if _s3_client is None:
        import boto3
        _s3_client = boto3.client(
            's3',
            region_name=os.environ.get('S3_REGION', 'us-east-1'),
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        )
    return _s3_client


def _use_s3() -> bool:
    return bool(
        os.environ.get('S3_BUCKET') and
        os.environ.get('AWS_ACCESS_KEY_ID') and
        os.environ.get('AWS_SECRET_ACCESS_KEY')
    )


def save(file_bytes: bytes, unique_filename: str) -> str:
    """
    Persist file_bytes under unique_filename.
    Returns a storage key: S3 object key or local absolute path.
    """
    if _use_s3():
        bucket = os.environ['S3_BUCKET']
        key    = f'uploads/{unique_filename}'
        _get_s3().put_object(Bucket=bucket, Key=key, Body=file_bytes)
        logger.info('Uploaded %s to s3://%s/%s', unique_filename, bucket, key)
        return key
    else:
        from flask import current_app
        folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, unique_filename)
        with open(path, 'wb') as fh:
            fh.write(file_bytes)
        return path


def delete(key: str) -> None:
    """Delete by storage key (S3 object key or local path). Silent on missing."""
    if not key:
        return
    if _use_s3():
        bucket = os.environ.get('S3_BUCKET', '')
        if bucket:
            try:
                _get_s3().delete_object(Bucket=bucket, Key=key)
            except Exception as exc:
                logger.warning('S3 delete failed for %s: %s', key, exc)
    else:
        if os.path.exists(key):
            try:
                os.remove(key)
            except OSError as exc:
                logger.warning('Local delete failed for %s: %s', key, exc)


@contextlib.contextmanager
def local_path(key: str):
    """
    Context manager that yields a local filesystem path for the stored file.
    For local storage, yields the path directly (no copy needed).
    For S3, downloads to a temp file and cleans up on exit.
    """
    if not _use_s3():
        yield key
        return

    bucket = os.environ['S3_BUCKET']
    suffix = os.path.splitext(key)[-1] or '.bin'
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = tmp.name

    try:
        _get_s3().download_file(bucket, key, tmp_path)
        yield tmp_path
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
