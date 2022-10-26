"""Mitre connector module."""
import json
import sys
import time
from typing import List

from pycti.connector.connector_types.connector_base_types import \
    ExternalInputConnector
from pycti.connector.connector_types.connector_settings import ConnectorConfig
from pycti.connector.libs.mixins.http import HttpMixin
from stix2 import Bundle, parse


class MitreConfig(ConnectorConfig):
    enterprise_file_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    mobile_attack_file_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
    ics_attack_file_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    capec_file_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
    )


class MitreConnector(ExternalInputConnector, HttpMixin):
    """Mitre connector."""
    config = MitreConfig

    # Add confidence to every object in a bundle
    def add_confidence_to_bundle_objects(self, serialized_bundle: str) -> str:
        # the list of object types for which the confidence has to be added
        # (skip marking-definition, identity, external-reference-as-report)
        object_types_with_confidence = [
            "attack-pattern",
            "course-of-action",
            "threat-actor",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "vulnerability",
            "report",
            "relationship",
        ]
        stix_bundle = json.loads(serialized_bundle)
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type in object_types_with_confidence:
                # self.helper.log_info(f"Adding confidence to {object_type} object")
                obj["confidence"] = int(self.base_config.confidence_level)
        return json.dumps(stix_bundle)

    def run(self, config: MitreConfig) -> (str, List[Bundle]):
        bundles = []
        entities = [
            config.enterprise_file_url,
            config.mobile_attack_file_url,
            config.ics_attack_file_url,
            config.capec_file_url,
        ]

        for entity in entities:
            self.logger.info(f"Retrieving {entity}")
            if entity == "":
                continue
            data = self.get(entity)
            data_with_confidence = self.add_confidence_to_bundle_objects(data)
            obj = parse(data_with_confidence, allow_custom=True)
            bundles.append(obj)

        return "Finished", bundles


if __name__ == "__main__":
    try:
        mitreConnector = MitreConnector()
        mitreConnector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
