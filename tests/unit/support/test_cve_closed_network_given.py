from tests.fakes.network_docker import FakeNetwork, FakeNetworkDocker

NAME = "mcp-auditor-cve-fictional-bridge"
OLD_DAEMON_MESSAGE = (
    "Error response from daemon: failed to parse com.docker.network.bridge.gateway_mode_ipv4 "
    "value: isolated (unknown gateway mode isolated)"
)

# Recorded on Docker 29.9.2 with `docker network inspect -f '{{json .}}'`: a network created
# with `--internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated`, and a plain one
# with a container attached.
CLOSED_INSPECT = (
    '{"Name":"mcp-auditor-cve-rec-closed","Id":"c600d5a6b0c74399af38516db396fd7c1ade150727b2c2e6'
    'fbfda7b55c35901c","Created":"2026-11-02T18:30:01.764543657+01:00","Scope":"local",'
    '"Driver":"bridge","EnableIPv4":true,"EnableIPv6":false,"IPAM":{"Driver":"default",'
    '"Options":{},"Config":[{"Subnet":"172.21.0.0/16"}]},"Internal":true,"Attachable":false,'
    '"Ingress":false,"ConfigFrom":{"Network":""},"ConfigOnly":false,"Options":'
    '{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"},"Labels":{"mcp-auditor-cve":""},'
    '"Containers":{},"Status":{"IPAM":{"Subnets":{"172.21.0.0/16":{"IPsInUse":2,'
    '"DynamicIPsAvailable":65534}}}}}'
)
OPEN_INSPECT = (
    '{"Name":"mcp-auditor-cve-rec-open","Id":"ed20b4682ea69cb4c65ce66e46a9579be2840046598cceb8b6'
    '9cafd135e67325","Created":"2026-11-02T18:30:08.39517825+01:00","Scope":"local",'
    '"Driver":"bridge","EnableIPv4":true,"EnableIPv6":false,"IPAM":{"Driver":"default",'
    '"Options":{},"Config":[{"Subnet":"172.21.0.0/16","Gateway":"172.21.0.1"}]},'
    '"Internal":false,"Attachable":false,"Ingress":false,"ConfigFrom":{"Network":""},'
    '"ConfigOnly":false,"Options":{},"Labels":{"mcp-auditor-cve":""},"Containers":'
    '{"a271d1f6b78b0f09f480c21b4b5d0765f7cd5044fe59b317bc199670e0c487c0":{"Name":'
    '"mcp-auditor-cve-rec-box","EndpointID":"66d1d86ec811afe084954294c585f903b4db9a53108e9ae70'
    '20fe6a48fec1bbc","MacAddress":"06:9a:65:76:1c:3d","IPv4Address":"172.21.0.2/16",'
    '"IPv6Address":""}},"Status":{"IPAM":{"Subnets":{"172.21.0.0/16":{"IPsInUse":4,'
    '"DynamicIPsAvailable":65532}}}}}'
)


def a_closed_network_with(*containers: str) -> FakeNetworkDocker:
    network = FakeNetwork(True, True, "isolated", containers=list(containers))
    return FakeNetworkDocker(networks={NAME: network})


def an_open_labelled_network_with(*containers: str) -> FakeNetworkDocker:
    network = FakeNetwork(True, False, None, containers=list(containers))
    return FakeNetworkDocker(networks={NAME: network})


def an_unlabelled_network_with(*containers: str) -> FakeNetworkDocker:
    network = FakeNetwork(False, False, None, containers=list(containers))
    return FakeNetworkDocker(networks={NAME: network})
