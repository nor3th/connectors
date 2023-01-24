import base64
import os
import time
from datetime import datetime
from typing import Callable, Dict, List

import stix2
from pycti import Report, StixCoreRelationship
from pycti.connector.connector_types.connector_base_types import \
    InternalFileInputConnector
from pycti.connector.connector_types.connector_settings import ConnectorConfig
from pydantic import BaseModel, Field
from stix2 import Bundle

from src.constants import (ENTITY_CLASS, OBSERVABLE_CLASS,
                           RESULT_FORMAT_CATEGORY, RESULT_FORMAT_MATCH,
                           RESULT_FORMAT_TYPE)
from src.models import Entity, EntityConfig, Observable
from src.report_parser import ReportParser
from src.util import MyConfigParser


class ImportDocumentConfig(ConnectorConfig):
    create_indicator: bool = Field(env="app_create_indicator", alias="app_create_indicator", default=True)


class ImportDocument(InternalFileInputConnector):
    config = ImportDocumentConfig

    def init(self) -> None:
        # Instantiate the connector helper from config
        base_path = os.path.dirname(os.path.abspath(__file__))

        # Load Entity and Observable configs
        observable_config_file = base_path + "/config/observable_config.ini"
        entity_config_file = base_path + "/config/entity_config.ini"

        if os.path.isfile(observable_config_file) and os.path.isfile(
            entity_config_file
        ):
            self.observable_config = self._parse_config(
                observable_config_file, Observable
            )
        else:
            raise FileNotFoundError(f"{observable_config_file} was not found")

        if os.path.isfile(entity_config_file):
            self.entity_config = self._parse_config(entity_config_file, EntityConfig)
        else:
            raise FileNotFoundError(f"{entity_config_file} was not found")

    def run(self, file_path: str, file_mime: str, entity_id: str, app_config: ImportDocumentConfig) -> (str, List[Bundle]):
        self.logger.info("Processing new message")

        entity = (
            self.api.stix_domain_object.read(id=entity_id)
            if entity_id is not None
            else None
        )
        if self.base_config.contextual_only and entity is None:
            return "Connector is only contextual and entity is not defined. Nothing was imported"

        # Retrieve entity set from OpenCTI
        entity_indicators = self._collect_stix_objects(self.entity_config)

        # Parse report
        parser = ReportParser(self.base_config.log_level, entity_indicators, self.observable_config)

        file_data = open(file_path, "rb").read()
        file_data_encoded = base64.b64encode(file_data)
        self.file = {
            "name": file_path,
            "data": file_data_encoded,
            "mime_type": file_mime,
        }
        parsed = parser.run_parser(file_path, file_mime)

        if not parsed:
            return "No information extracted from report", []

        # Process parsing results
        self.logger.debug("Results: {}".format(parsed))
        observables, entities = self._process_parsing_results(parsed, entity, app_config)
        # Send results to OpenCTI
        bundles = self._process_parsed_objects(
            entity, observables, entities, file_path
        )

        self.logger.info("Finished")
        return (
                   f"Sent {len(observables)} observables, 1 report update and {len(entities)} entity connections as stix "
                   f"bundle for worker import "
               ), bundles

    def _collect_stix_objects(
        self, entity_config_list: List[EntityConfig]
    ) -> List[Entity]:
        base_func = self.api
        entity_list = []
        for entity_config in entity_config_list:
            func_format = entity_config.stix_class
            try:
                custom_function = getattr(base_func, func_format)
                entries = custom_function.list(
                    getAll=True,
                    filters=entity_config.filter,
                    customAttributes=entity_config.custom_attributes,
                )
                entity_list += entity_config.convert_to_entity(entries, self.base_config.log_level)
            except AttributeError:
                e = "Selected parser format is not supported: {}".format(func_format)
                raise NotImplementedError(e)

        return entity_list

    @staticmethod
    def _parse_config(config_file: str, file_class: Callable) -> List[BaseModel]:
        config = MyConfigParser()
        config.read(config_file)

        config_list = []
        for section, content in config.as_dict().items():
            content["name"] = section
            config_object = file_class(**content)
            config_list.append(config_object)

        return config_list

    def _process_parsing_results(
        self, parsed: List[Dict], context_entity: Dict, app_config: ImportDocumentConfig
    ) -> (List[Dict], List[str]):
        observables = []
        entities = []
        if context_entity is not None:
            object_markings = [
                x["standard_id"] for x in context_entity.get("objectMarking", [])
            ]
            # external_references = [x['standard_id'] for x in report.get('externalReferences', [])]
            # labels = [x['standard_id'] for x in report.get('objectLabel', [])]
            author = context_entity.get("createdBy")
        else:
            object_markings = []
            author = None
        if author is not None:
            author = author.get("standard_id", None)
        for match in parsed:
            if match[RESULT_FORMAT_TYPE] == OBSERVABLE_CLASS:
                if match[RESULT_FORMAT_CATEGORY] == "Vulnerability.name":
                    entity = self.api.vulnerability.read(
                        filters={"key": "name", "values": [match[RESULT_FORMAT_MATCH]]}
                    )
                    if entity is None:
                        self.logger.info(
                            f"Vulnerability with name '{match[RESULT_FORMAT_MATCH]}' could not be "
                            f"found. Is the CVE Connector activated?"
                        )
                        continue

                    entities.append(entity["standard_id"])
                elif match[RESULT_FORMAT_CATEGORY] == "Attack-Pattern.x_mitre_id":
                    entity = self.api.attack_pattern.read(
                        filters={
                            "key": "x_mitre_id",
                            "values": [match[RESULT_FORMAT_MATCH]],
                        }
                    )
                    if entity is None:
                        self.logger.info(
                            f"AttackPattern with MITRE ID '{match[RESULT_FORMAT_MATCH]}' could not be "
                            f"found. Is the MITRE Connector activated?"
                        )
                        continue

                    entities.append(entity["standard_id"])
                else:
                    observable = None
                    if match[RESULT_FORMAT_CATEGORY] == "Autonomous-System.number":
                        observable = stix2.AutonomousSystem(
                            number=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Domain-Name.value":
                        observable = stix2.DomainName(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Email-Addr.value":
                        observable = stix2.EmailAddress(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.name":
                        observable = stix2.File(
                            name=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "IPv4-Addr.value":
                        observable = stix2.IPv4Address(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "IPv6-Addr.value":
                        observable = stix2.IPv6Address(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Mac-Addr.value":
                        observable = stix2.MACAddress(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.MD5":
                        observable = stix2.File(
                            hashes={"MD5": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.SHA-1":
                        observable = stix2.File(
                            hashes={"SHA-1": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "File.hashes.SHA-256":
                        observable = stix2.File(
                            hashes={"SHA-256": match[RESULT_FORMAT_MATCH]},
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Windows-Registry-Key.key":
                        observable = stix2.WindowsRegistryKey(
                            key=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    elif match[RESULT_FORMAT_CATEGORY] == "Url.value":
                        observable = stix2.URL(
                            value=match[RESULT_FORMAT_MATCH],
                            object_marking_refs=object_markings,
                            custom_properties={
                                "x_opencti_create_indicator": app_config.create_indicator,
                                "created_by_ref": author,
                            },
                        )
                    if observable is not None:
                        observables.append(observable)

            elif match[RESULT_FORMAT_TYPE] == ENTITY_CLASS:
                entities.append(match[RESULT_FORMAT_MATCH])
            else:
                self.logger.info("Odd data received: {}".format(match))

        return observables, entities

    def _process_parsed_objects(
        self,
        entity: Dict,
        observables: List,
        entities_ids: List,
        file_name: str,
    ) -> List[Bundle]:
        if len(observables) == 0 and len(entities_ids) == 0:
            return []
        observables_ids = [o["id"] for o in observables]
        if entity is not None:
            entity_stix_bundle = self.api.stix2.export_entity(
                entity["entity_type"], entity["id"]
            )
            if len(entity_stix_bundle["objects"]) == 0:
                raise ValueError("Entity cannot be found or exported")
            entity_stix = [
                object
                for object in entity_stix_bundle["objects"]
                if object["id"] == entity["standard_id"]
            ][0]
            relationships = []
            # For containers, just insert everything in it
            if (
                entity_stix["type"] == "report"
                or entity_stix["type"] == "note"
                or entity_stix["type"] == "opinion"
            ):
                entity_stix["object_refs"] = (
                    entity_stix["object_refs"] + observables_ids + entities_ids
                    if "object_refs" in entity_stix
                    else observables_ids + entities_ids
                )
                entity_stix["x_opencti_files"] = (
                    [self.file] if self.file is not None else []
                )
            # For observed data, just insert all observables in it
            elif entity_stix["type"] == "observed-data":
                entity_stix["object_refs"] = (
                    entity_stix["object_refs"] + observables_ids
                    if "object_refs" in entity_stix
                    else observables_ids
                )
            else:
                # For all other entities, relate all observables
                for observable in observables:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable["id"], entity_stix_bundle["id"]
                            ),
                            relationship_type="related-to",
                            source_ref=observable["id"],
                            target_ref=entity_stix["id"],
                            allow_custom=True,
                        )
                    )
                if entity_stix["type"] == "incident":
                    for entity_id in entities_ids:
                        # Incident attributed-to Threats
                        if (
                            entity_id.startswith("threat-actor")
                            or entity_id.startswith("intrusion-set")
                            or entity_id.startswith("campaign")
                        ):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "attributed-to",
                                        entity_stix["id"],
                                        entity["id"],
                                    ),
                                    relationship_type="attributed-to",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
                                    allow_custom=True,
                                )
                            )
                        # Incident targets Vulnerabilities
                        elif entity_id.startswith("vulnerability"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "targets",
                                        entity_stix["id"],
                                        entity["id"],
                                    ),
                                    relationship_type="targets",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
                                    allow_custom=True,
                                )
                            )
                        # Incident uses Attack Patterns
                        elif entity_id.startswith("attack-pattern"):
                            relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", entity_stix["id"], entity["id"]
                                    ),
                                    relationship_type="uses",
                                    source_ref=entity_stix["id"],
                                    target_ref=entity,
                                    allow_custom=True,
                                )
                            )
            observables = observables + relationships
            observables.append(entity_stix)
        else:
            timestamp = int(time.time())
            now = datetime.utcfromtimestamp(timestamp)
            report = stix2.Report(
                id=Report.generate_id(file_name, now),
                name=file_name,
                description="Automatic import",
                published=now,
                report_types=["threat-report"],
                object_refs=observables_ids + entities_ids,
                allow_custom=True,
                custom_properties={
                    "x_opencti_files": [self.file] if self.file is not None else []
                },
            )
            observables.append(report)
        bundles_sent = []
        if len(observables) > 0:
            bundle = stix2.Bundle(objects=observables, allow_custom=True)
            bundles_sent.append(bundle)

        # len() - 1 because the report update increases the count by one
        return bundles_sent
