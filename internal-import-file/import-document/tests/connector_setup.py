import uuid
from typing import Optional

from pycti import StixMetaTypes, StixCyberObservableTypes
from stix2 import Bundle
from dateutil.parser import parse
from src.reportimporter.core import ImportDocument
from pycti.connector.new.tests.test_class import ConnectorTest


class ImportDocumentTest(ConnectorTest):
    connector = ImportDocument

    def _setup(self, monkeypatch):
        monkeypatch.setenv("opencti_broker", "pika")
        monkeypatch.setenv("opencti_ssl_verify", "False")
        monkeypatch.setenv("connector_name", "Test-Import-Document")
        monkeypatch.setenv("connector_id", str(uuid.uuid4()))
        monkeypatch.setenv("connector_scope", 'application/pdf,text/csv')
        monkeypatch.setenv("connector_testing", "True")
        monkeypatch.setenv("connector_log_level", "DEBUG")

        date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")
        self.organization = self.api_client.identity.create(
            type="Organization",
            name="My organization",
            alias=["my-organization"],
            description="A new organization.",
        )

        # Create the report
        self.report = self.api_client.report.create(
            name="My new report of my organization",
            description="A report wrote by my organization",
            published=date,
            report_types=["internal-report"],
            createdBy=self.organization["id"],
        )

        self.file = self.api_client.stix_domain_object.add_file(
            id=self.report["id"],
            file_name="./tests/test.pdf",
        )

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.report["id"])
        self.api_client.stix_domain_object.delete(id=self.organization["id"])

    def initiate(self) -> Optional[str]:
        file_url = self.api_client.stix_domain_object.file_ask_for_enrichment(
            file_id=self.file["data"]["stixDomainObjectEdit"][
                "importPush"
            ]["id"],
            connector_id=self.connector_instance.base_config.id,
        )
        return file_url

    def verify(self, bundle: Bundle):
        bundle_objects = bundle["objects"]
        assert len(bundle_objects) == 22, f"Error bundle has size {len(bundle_objects)}"

        infos = [
            {'type': StixCyberObservableTypes.MAC_ADDR.value, 'value': "c8:5b:76:8b:c2:40"},
            {'type': StixCyberObservableTypes.MAC_ADDR.value, 'value': "f0:d5:bf:2b:bf:ba"},
            {'type': StixCyberObservableTypes.DOMAIN_NAME.value, 'value': "intranet.accenture"},
            {'type': StixCyberObservableTypes.DOMAIN_NAME.value, 'value': "googa.net"},
            {'type': StixCyberObservableTypes.DOMAIN_NAME.value, 'value': "google.live"},
            {'type': StixCyberObservableTypes.DOMAIN_NAME.value, 'value': "foo.net"},
            {'type': StixCyberObservableTypes.URL.value, 'value': "https://googa.net"},
            {'type': StixCyberObservableTypes.URL.value, 'value': "https://foo.net"},
        ]

        for item in infos:
            found = False
            for _object in bundle_objects:
                type = _object.get('type', None)
                val = _object.get('value', None)
                if type.lower() == item['type'].lower() and val.lower() == item['value'].lower():
                    found = True
                    break

            assert found is True, f"Item {item} not found!"


CONNECTORS = [ImportDocumentTest]
