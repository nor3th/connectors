import uuid

from stix2 import Bundle
from src.mitre import MitreConnector
from pycti.connector.new.tests.test_class import ConnectorTest


class MitreTest(ConnectorTest):
    connector = MitreConnector

    def _setup(self, monkeypatch):
        monkeypatch.setenv("opencti_broker", "pika")
        monkeypatch.setenv("opencti_ssl_verify", "False")
        monkeypatch.setenv("connector_id", str(uuid.uuid4()))
        monkeypatch.setenv("connector_name", "MITRE Connector")
        monkeypatch.setenv("connector_run_and_terminate", "true")
        monkeypatch.setenv("connector_scope", 'IPv4Addr')
        monkeypatch.setenv("connector_interval", "2")
        monkeypatch.setenv("connector_testing", "True")
        monkeypatch.setenv("app_enterprise_file_url", "https://raw.githubusercontent.com/oasis-open/cti-stix-common-objects/main/objects/location/location--011a9d8e-75eb-475a-a861-6998e9968287.json")
        monkeypatch.setenv("app_mobile_attack_file_url", "")
        monkeypatch.setenv("app_ics_attack_file_url", "")
        monkeypatch.setenv("app_capec_file_url", "")


    def verify(self, bundle: Bundle):
        bundle_objects = bundle["objects"]
        ids = ["bundle--8376c00f-48c6-4fc0-949f-06e8edd7c0a6", "bundle--1bbffad5-534d-4349-8ab9-6cef05a8676d", "bundle--17f97d69-4677-4371-9fd4-a18ae702576f", "bundle--adac1215-a6be-4f71-84ad-8d467e1dc412", "bundle--2c804425-6cae-4444-a630-89f96da3d899"]
        assert bundle['id'] in ids, f"Invalid bundle id {bundle['id']}"
        print(f"Len bundles {len(bundle_objects)}")


CONNECTORS = [MitreTest]
