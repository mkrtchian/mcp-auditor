"""The GitLab CE backend's seed: the scripts `evals.cve.backends.gitlab` runs inside the GitLab
container, each awaited, so the ids come out the same on every stand-up: project 1 `root/rails`
from GitLab's built-in Rails template (the first of `lib/gitlab/project_template.rb`, shipped in
the image), project 2 `root/examples` whose `.gitlab-ci.yml` starts pipeline 1, job 1 `test` (a
trace and the artifact `file.txt`) and job 2 `deploy_prod` (manual, playable), and runner 1, an
instance runner with the shell executor that runs job 1.

The CI file joins two examples of GitLab's CI documentation: `test` is "Example of
`artifacts:expose_as`" (doc/ci/yaml/_index.md) and `deploy_prod` the manual job of "Protect manual
jobs" (doc/ci/jobs/job_control.md).

The token is created with GitLab's documented "Create a personal access token programmatically"
command (`gitlab-rails runner` with `set_token`), scope `api`, which play, retry and cancel need,
where the documented example asks for `read_user` and `read_repository`. Its value is that
command's own example value: the command requires 20 characters, and the server README's
`your_gitlab_token`, which the run image bakes, has 17. The scripts read it from `SEED_TOKEN`.
"""

GITLAB_TOKEN = "token-string-here123"

SEED_PROJECTS = r"""set -euo pipefail
api=http://127.0.0.1/api/v4
until curl -sf -o /dev/null http://127.0.0.1/-/readiness; do sleep 3; done
gitlab-rails runner "token = User.find_by_username('root').personal_access_tokens.create(\
scopes: ['api'], name: 'mcp-gitlab', expires_at: 365.days.from_now); \
token.set_token('${SEED_TOKEN}'); token.save!"
auth="PRIVATE-TOKEN: ${SEED_TOKEN}"
until curl -sf -o /dev/null -H "$auth" "$api/user"; do sleep 2; done
curl -sf -o /dev/null -H "$auth" -X POST "$api/projects" -d name=rails -d template_name=rails
until curl -sf -H "$auth" "$api/projects/1/import" | grep -q '"import_status":"finished"'; do
  sleep 3
done
curl -sf -o /dev/null -H "$auth" -X POST "$api/projects" -d name=examples
cat > /tmp/ci.yml <<'EOF'
test:
  script: ["echo 'test' > file.txt"]
  artifacts:
    expose_as: 'artifact 1'
    paths: ['file.txt']

deploy_prod:
  stage: deploy
  script:
    - echo "Deploy to production server"
  environment:
    name: production
    url: https://example.com
  when: manual
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
EOF
curl -sf -o /dev/null -H "$auth" -X POST "$api/projects/2/repository/files/.gitlab-ci.yml" \
  --data-urlencode branch=main --data-urlencode commit_message="Add .gitlab-ci.yml" \
  --data-urlencode content@/tmp/ci.yml
runner_token=$(curl -sf -H "$auth" -X POST "$api/user/runners" \
  -d runner_type=instance_type -d run_untagged=true \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
gitlab-runner register --non-interactive --url http://gitlab.example.com \
  --token "$runner_token" --executor shell
mkdir -p /var/opt/gitlab-runner
"""

START_RUNNER = (
    "cd /var/opt/gitlab-runner"
    " && exec gitlab-runner run --working-directory /var/opt/gitlab-runner"
    " >/var/log/gitlab-runner.log 2>&1"
)

# Every non-manual job has finished once none is pending, running or created and one has ended.
WAIT_FOR_JOBS = r"""set -uo pipefail
api=http://127.0.0.1/api/v4
auth="PRIVATE-TOKEN: ${SEED_TOKEN}"
for attempt in $(seq 1 200); do
  waiting=$(curl -gsf -H "$auth" \
    "$api/projects/2/jobs?scope[]=pending&scope[]=running&scope[]=created" || echo error)
  ended=$(curl -gsf -H "$auth" "$api/projects/2/jobs?scope[]=success&scope[]=failed" \
    | grep -o '"id":' | wc -l)
  if [ "$waiting" = "[]" ] && [ "$ended" -ge 1 ]; then exit 0; fi
  sleep 3
done
echo "the seeded pipeline's jobs did not finish" >&2
exit 1
"""
