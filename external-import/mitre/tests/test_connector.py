import base64
import json

from pycti.connector.libs.opencti_schema import WorkerMessage
from pycti.connector.tests.test_library import wait_for_test_to_finish
from pytest import fixture
from stix2 import Bundle

from .connector_setup import CONNECTORS


@fixture(params=CONNECTORS)
def connector_test_instance(request, api_client, monkeypatch):
    connector = request.param(api_client)
    connector.setup(monkeypatch)
    yield connector
    connector.shutdown()
    connector.teardown()


def test_connector_run(connector_test_instance, rabbit_server):
    connector_test_instance.run()
    rabbit_server.run(
        connector_test_instance.connector_instance.base_config.name.lower()
    )

    error_msg = wait_for_test_to_finish(connector_test_instance, {"last_run": None})

    expected_error = connector_test_instance.get_expected_exception()
    if expected_error == "":
        assert error_msg == expected_error, f"Error during execution: {error_msg}"

        messages = rabbit_server.get_messages()
        for msg in messages:
            worker_message = WorkerMessage(**json.loads(msg))
            bundle = Bundle(
                **json.loads(base64.b64decode(worker_message.content)),
                allow_custom=True,
            )
            connector_test_instance.verify(bundle)

    else:
        assert (
                expected_error in error_msg
        ), f"Expected exception did not match occurred exception ({expected_error}) vs ({error_msg})"

