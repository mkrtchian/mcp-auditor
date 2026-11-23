from evals.cve.kit import launch as kit_launch


def test_the_kit_tags_its_images_outside_the_acceptance_namespace():
    assert kit_launch.image_tag("x") == "mcp-auditor-kit-x:local"
