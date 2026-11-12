"""The seed the Gravitino backend sends through Gravitino's REST API at each stand-up, and the
fileset directory whose file it writes (evals/cve/backends/gravitino.py)."""

from dataclasses import dataclass
from typing import Any

METALAKE = "metalake_demo"


@dataclass(frozen=True)
class SeedRequest:
    method: str
    path: str  # under the metalakes endpoint
    body: dict[str, Any]


def _under(path: str, body: dict[str, Any], method: str = "POST") -> SeedRequest:
    return SeedRequest(method, f"/{METALAKE}{path}", body)


# The Playground's catalog over its PostgreSQL (init/common/init_metalake_catalog.sh at
# 11b37bc618763c2f172f6ae997871a067666389f), its jdbc-url at the postgresql alias. Its HR schema and
# tables are the ones init/postgres/init.sql creates in gravitino-db, which Gravitino reads through
# the catalog, so the seed creates neither.
_CATALOG_POSTGRES = {
    "name": "catalog_postgres",
    "type": "RELATIONAL",
    "provider": "jdbc-postgresql",
    "comment": "comment",
    "properties": {
        "jdbc-url": "jdbc:postgresql://postgresql/db",
        "jdbc-user": "postgres",
        "jdbc-password": "postgres",
        "jdbc-database": "db",
        "jdbc-driver": "org.postgresql.Driver",
    },
}
FILESET_DIRECTORY = "/tmp/root/schema/example_fileset"
_CUSTOM_POLICY_CONTENT = {"supportedObjectTypes": ["CATALOG", "TABLE"]}

# The fileset, model, messaging, statistic, tag and policy requests are the examples of Gravitino's
# documentation at v1.2.1 (docs/manage-fileset-metadata-using-gravitino.md,
# manage-model-metadata-using-gravitino.md, manage-messaging-metadata-using-gravitino.md,
# manage-statistics-in-gravitino.md, manage-tags-in-gravitino.md, manage-policies-in-gravitino.md),
# sent to metalake_demo, with the tags and policies on catalog_postgres and its hr schema. The
# messaging example's catalog is named `catalog` like the fileset example's, so it takes the name
# catalog_kafka, after the Playground's catalog names.
GRAVITINO_SEED: tuple[SeedRequest, ...] = (
    SeedRequest("POST", "", {"name": METALAKE, "comment": "comment", "properties": {}}),
    _under("/catalogs", _CATALOG_POSTGRES),
    _under(
        "/catalogs",
        {
            "name": "catalog",
            "type": "FILESET",
            "comment": "comment",
            "properties": {"location": "file:///tmp/root"},
        },
    ),
    _under(
        "/catalogs/catalog/schemas",
        {
            "name": "schema",
            "comment": "comment",
            "properties": {"location": "file:///tmp/root/schema"},
        },
    ),
    _under(
        "/catalogs/catalog/schemas/schema/filesets",
        {
            "name": "example_fileset",
            "comment": "This is an example fileset",
            "type": "MANAGED",
            "storageLocation": f"file://{FILESET_DIRECTORY}",
            "properties": {"k1": "v1"},
        },
    ),
    _under(
        "/catalogs",
        {
            "name": "model_catalog",
            "type": "MODEL",
            "comment": "This is a model catalog",
            "properties": {"k1": "v1"},
        },
    ),
    _under(
        "/catalogs/model_catalog/schemas",
        {"name": "model_schema", "comment": "This is a model schema", "properties": {"k1": "v1"}},
    ),
    _under(
        "/catalogs/model_catalog/schemas/model_schema/models",
        {
            "name": "example_model",
            "comment": "This is an example model",
            "properties": {"k1": "v1"},
        },
    ),
    _under(
        "/catalogs/model_catalog/schemas/model_schema/models/example_model/versions",
        {
            "uri": "path/to/model",
            "aliases": ["alias1", "alias2"],
            "comment": "This is version 0",
            "properties": {"k1": "v1"},
        },
    ),
    _under(
        "/catalogs",
        {
            "name": "catalog_kafka",
            "type": "MESSAGING",
            "comment": "comment",
            "provider": "kafka",
            "properties": {"bootstrap.servers": "kafka:9092"},
        },
    ),
    _under(
        "/catalogs/catalog_kafka/schemas/default/topics",
        {
            "name": "example_topic",
            "comment": "This is an example topic",
            "properties": {"partition-count": "3", "replication-factor": 1},
        },
    ),
    _under(
        "/objects/table/catalog_postgres.hr.employees/statistics",
        {"updates": {"custom-tableLastModifiedTime": "20250128"}},
        method="PUT",
    ),
    _under(
        "/tags",
        {
            "name": "tag1",
            "comment": "This is a tag",
            "properties": {"key1": "value1", "key2": "value2"},
        },
    ),
    # The association example names tag2 without creating it, so it is created in tag1's shape.
    _under("/tags", {"name": "tag2", "comment": "This is a tag", "properties": {}}),
    *(
        _under(
            "/policies", {"name": name, "policyType": "custom", "content": _CUSTOM_POLICY_CONTENT}
        )
        for name in ("policy1", "policy2", "policy3")
    ),
    _under(
        "/objects/catalog/catalog_postgres/tags",
        {"tagsToAdd": ["tag1", "tag2"], "tagsToRemove": ["tag3"]},
    ),
    _under("/objects/schema/catalog_postgres.hr/tags", {"tagsToAdd": ["tag1"]}),
    _under(
        "/objects/catalog/catalog_postgres/policies",
        {"policiesToAdd": ["policy1", "policy2"], "policiesToRemove": ["policy3"]},
    ),
    _under("/objects/schema/catalog_postgres.hr/policies", {"policiesToAdd": ["policy1"]}),
)
