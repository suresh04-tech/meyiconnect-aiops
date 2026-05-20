import boto3
from botocore.config import Config
from app.utils.db import get_db

class AWSClientFactory:
    """
    Factory to dynamically create boto3 clients using credentials stored
    in the database (meyiconnect.insight_connectors).
    """

    def __init__(self, connector_id: str = None):
        self.connector_id = connector_id
        self.config = self._fetch_config()
        self.region = self.config.get("region", "us-east-1")
        self.access_key = self.config.get("accessKeyId")
        self.secret_key = self.config.get("secretAccessKey")

        if not self.access_key or not self.secret_key:
            identifier = self.connector_id if self.connector_id else "type=aws"
            raise ValueError(f"Missing AWS credentials in connector {identifier}")

    def _fetch_config(self) -> dict:
        with get_db() as conn:
            with conn.cursor() as cur:
                if self.connector_id:
                    cur.execute(
                        "SELECT config FROM meyiconnect.insight_connectors WHERE id = %s",
                        (self.connector_id,)
                    )
                else:
                    cur.execute(
                        "SELECT config FROM meyiconnect.insight_connectors WHERE type = 'aws' LIMIT 1"
                    )
                row = cur.fetchone()
                if not row:
                    if self.connector_id:
                        raise ValueError(f"Connector not found: {self.connector_id}")
                    else:
                        raise ValueError("No AWS connector found in the database")
                
                config_data = row["config"]
                if isinstance(config_data, str):
                    import json
                    config_data = json.loads(config_data)
                
                return config_data

    def get_client(self, service_name: str, region_name: str = None, config: Config = None):
        """
        Create a boto3 client dynamically.
        """
        return boto3.client(
            service_name,
            region_name=region_name or self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=config
        )
