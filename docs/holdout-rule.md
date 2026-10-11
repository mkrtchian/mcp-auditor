# CVE holdout selection rule

This is the selection rule of the holdout layer of the CVE benchmark. The decisions behind it are in [ADR 015](adr/015-eval-instruments-and-claims.md), [ADR 028](adr/028-cve-holdout-selection.md), [ADR 029](adr/029-nonce-only-proof.md) and [ADR 030](adr/030-credit-replayed-on-patched.md). Its changes, the excluded servers, the dropped targets, the cutoffs, the classes of the grammar and every other act this rule says is logged are in [`holdout-log.md`](holdout-log.md).

## Census

The census and the calibrations are done by LLM agents. Every agent of one step of a census or a calibration runs on the same model, so that no flaw is read by a stronger or weaker model than the other flaws of that step. The steps of a census are its collection, with every run after a widening, its recall, with the `vulnerablemcp.info` check, its classification and its grouping by proof. The steps of a draw's calibration are the calibration of its candidates, second calibrations included, and the check of their cards. When a step is done by two readers that each read every flaw of the step independently of each other, each reader may instead run on its own model, with every agent of one reader on that model, since every flaw is then read by both models. The classification and the grouping by proof are such steps. The maintainer chooses the model of each step, or of each reader, before the step starts and does not change it while the step runs, and the census records the model ID of each agent.

**What counts as an MCP server.** An MCP server is a program that serves the Model Context Protocol to a client and exposes tools, distributed as a package or a public repository. Clients, hosts, inspectors, registries and SDKs are not servers, and a flaw of an SDK is not a candidate. A server is one package, or one repository when it is published only as a repository. When one package of a repository is an excluded server, the other packages of that repository stay candidates.

**The unit of the census is one flaw.** It is identified by its CVE ID in upper case, or by its GHSA ID as GitHub writes it when it has none. When several IDs describe one flaw as it enters the census, the lowest CVE ID that is not rejected (by year, then by number) is kept. The identifier, once recorded, never changes, even when a CVE ID is assigned or found later, so its draw hash never changes. A flaw found again under another ID, in this census or in the census of a later version, is matched to its recorded entry and not added twice.

**Sources.**

1. The GitHub Advisory Database, reviewed advisories only, through its public repository `github/advisory-database`.
2. The NVD, through its JSON data feeds.
3. OSV, through its data export, for the advisories the first two do not carry.

**Collection.** One agent per source runs a broad pre-filter on it, then reads every flaw the pre-filter returns and keeps every flaw of software that implements MCP: servers, clients, hosts and SDKs. The pre-filter, as first written, matches without regard to case the strings `mcp` and `model context protocol` anywhere in the advisory text or in the names of affected packages (on the NVD, in CPE product names). Each agent also looks beyond the pre-filter in its source, for instance at other advisories of the organizations that publish MCP servers, and records each flaw it finds there as a gap of the pre-filter.

**Recall.** Three more agents search, one per angle set in their instructions: the MCP vulnerability aggregators and security blogs, the security advisories of MCP server repositories, and servers whose names do not contain `mcp`. A flaw they find enters the census only through an advisory in one of the three sources. Every MCP CVE that `vulnerablemcp.info` lists with a disclosure date within the census must be found, or recorded as absent from the three sources. For each flaw found outside the pre-filter, by any agent, the pre-filter gains a string or a package name that matches it, and the collection runs again. These widenings are recorded in the census and open no version of this rule. The census is complete when the pre-filter, as last widened, finds every flaw the agents found.

**Classification.** Two classifiers classify every flaw of the census, independently of each other. A classifier may run as several agents, each in its own context on its own share of the flaws. Each flaw is classified from its advisory and the pages it links to, without access to this repository or its prompts. Each classifier records, per flaw: the server package and its versions, whether a vulnerable version and its first patched version can both be pinned, the disclosure date, the transport, the MCP primitive, whether the effect shows in a tool response, whether the server appears able to run in a container (no third-party service, credential or proprietary binary needed), the effect class (one of the grammar's, or another class it names), and for an ineligible flaw the first of the criteria checkable from an advisory (see Eligibility) that it fails, in their listed order. Every field is filled for every flaw, even after a first failed criterion. The classifiers' agreement is recorded as the share of flaws on which they agree, field by field. Until a disagreement is settled, a flaw counts as meeting a criterion when either classifier finds that it does. A flaw counts outside the grammar only when both classifiers place it outside the grammar. For the candidates the draw reaches, the maintainer settles each disagreement criterion by criterion, never on a guess about what the auditor would detect, and records each settlement with its reason. The maintainer applies the exclusions to the classified flaws.

**Grouping by proof.** Two readers group by proof the flaws that have a census identifier (a CVE or GHSA ID), meet the criteria of the draw order, have a server that either classifier finds able to run in a container, and are placed outside the classes of the grammar by both classifiers. Each reader works in its own context, told to read only what it is given: the advisory records of each flaw and the pages they link to, the flaw's server package, the effect names the two classifiers gave it, offered as hints, and a description, as of the day of the grouping, of how the benchmark proves a detection. For each flaw, the reader states how the effect could be proven in a tool response and gives its reason. It groups the flaws by that proof, with one group for the flaws whose effect cannot be proven in a tool response. The flaws a reader places in that group are the known gap of the holdout as that reader finds it (ADR 029). The judgments of the two readers are never settled into one. Neither the grouping nor the judgment that a server appears able to run in a container takes a flaw out of the draw order: a flaw of the known gap, or of a server judged unable to run in a container, is drawn and calibrated like any other. The grouping is done once for each census, and a later version groups only the flaws its census adds. The census records, for every flaw the readers group, each reader's group, proof and reason.

**The disclosure date** of a flaw is its earliest publication date across the three sources, compared as a UTC calendar day. The census covers every flaw disclosed on or before the committer date of the commit that introduces version 1 of this file. The census of a later version that adds targets extends to the committer date of that version's commit.

**Output.** The census is committed as `evals/holdout_census.json`, before and after each draw and each replacement. It refers to the large artifacts it read instead of holding them: the commit of `github/advisory-database`, the date and SHA-256 of each NVD and OSV export, and for each pinned version, the integrity hash npm or PyPI publishes, or its commit SHA when it is pinned as a commit. It records the grammar fingerprint at the draw, the grouping by proof, the calibration records and cards, and two coverage figures: the share of MCP server flaws the auditor can reach (stdio transport, Tools primitive, effect in a tool response), and, once for each reader, the share of the known gap among the flaws that have a census identifier, meet the criteria of the draw order and have a server that either classifier finds able to run in a container. A flaw that either classifier places in a class of the grammar counts outside the gap without being read, so that share is a lower bound. It also reports, over every MCP server flaw of the census, the shares by transport, by MCP primitive, by effect class, and of effects that do not show in a tool response, and the number of flaws disclosed each month.

## Proof

A detection is proven only by a nonce that surfaces in a tool response: a random value the auditor cannot write, planted where only the flaw reaches it. At each launch of a target, every place calibration keeps for it holds a nonce of its own, drawn for that launch, so the report tells which place each detection came from. The effect class of a target is a label, reported with the target. The calibration agent files each target under the class of the grammar its published mechanism produces, or under no class when none fits, and records that choice in the card. The class sets which judge categories count in `fail_without_proof` (see the per-target report). Under no class, every category counts.

The places come from the list below. Calibration keeps, for each target, every listed place that only its flaw reaches. On a target whose flaw runs code the caller chooses, the account of the process is one of the listed places: the server runs under an account named after the nonce of that place, so `id`, `whoami` and the passwd file print it. A value the kernel or the runtime computes from nothing the fixture sets, such as the version a database reports, holds no nonce.

The list was written before any draw, from the pinned sources below. Its filter keeps the ATT&CK techniques that have a tactic among Credential Access, Discovery or Collection, and a platform among Linux, Containers or IaaS. The other pinned sources cover what ATT&CK does not name: ATLAS covers the process environment and the configuration of an agent or its tools, the Falco rules cover the container and cloud locations, and the MCP security best practices cover the internal network services. The technique ID of a place comes from the ATT&CK or ATLAS object, even when a Falco rule tags the place with an ID. Each place cites its technique ID at the pinned version and a text that names the place. That text is quoted from an ATT&CK or ATLAS object, a Falco rule or the MCP security best practices. When none of them names the place itself, it is quoted from the documentation or the source of the software that defines that place as its default. A place that cannot be cited this way does not enter.

### Frozen-source manifest

Each source file is pinned by its version and its SHA-256. Each quotation in the list is an excerpt of at most 160 characters, with its cuts marked `...`, found in the text of the source it cites, up to case and spacing.

- **MITRE ATT&CK Enterprise 19.2**: tag `v19.2` of `mitre-attack/attack-stix-data`, file `enterprise-attack/enterprise-attack-19.2.json`, SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. The filter keeps 109 of its 697 active techniques. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
- **MITRE ATLAS**, data version 5.6.0: tag `v2026.09` of `mitre-atlas/atlas-data`, file `dist/ATLAS.yaml`, SHA-256 `c9c23971d0db07e2782423d795a20e78d5c2c9bcdc78fc67e24530657daaec41`, techniques AML.T0055, AML.T0083 and AML.T0098, the ones that name credentials held in the process environment or in the configuration of an agent or its tools. Apache License 2.0.
- **Falco rules**: `rules/falco_rules.yaml` at tag `falco-rules-5.2.0` (SHA-256 `30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b`), `rules/falco-incubating_rules.yaml` at tag `falco-incubating-rules-6.0.1` (`47bf87041e2f39ca336e7acf1ae4e6183771a92e81031f367d01f2b49cabe1ac`) and `rules/falco-sandbox_rules.yaml` at tag `falco-sandbox-rules-6.2.0` (`f05ad34f07c43930932ea6dd84c08a37bc8e5ba9f88901ca091ff1b52b3f33d3`), all of `falcosecurity/rules`. Copyright The Falco Authors, Apache License 2.0.
- **MCP Security Best Practices**, protocol version 2026-07-28: commit `1f520964b295d58494d944f2aea8a5ab51c79f77` of `modelcontextprotocol/modelcontextprotocol`, file `docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx`, SHA-256 `0d859ba68bbab6148907ef2bf7b2e169a1b9a2cbe1e8731d7c0d47e15ed37f23`. Model Context Protocol contributors, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **Documentation or source of the software that defines a place**, retrieved on 2026-10-11. A rendered page has no stable hash, so it is cited by its URL and that date, after which it can change.
  - dotenv, `.env` in the working directory: `https://github.com/motdotla/dotenv`.
  - Docker CLI, `~/.docker/config.json`: `https://docs.docker.com/reference/cli/docker/`.
  - Docker secrets, `/run/secrets/<name>`: `https://docs.docker.com/engine/swarm/secrets/`.
  - kubectl, `~/.kube/config`: `https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/`.
  - Amazon ECS container credentials, `169.254.170.2`: `https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html`.
  - Amazon EKS Pod Identity, `169.254.170.23`: `https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html`.
  - Google Cloud metadata server, `metadata.google.internal`: `https://docs.cloud.google.com/compute/docs/metadata/overview`.
  - GitHub CLI, the directory `~/.config/gh`: `https://cli.github.com/manual/gh_help_environment`. Its file `hosts.yml`: `pkg/config/config.go` at tag `v2.16.1` of `cli/go-gh`, the library the GitHub CLI 2.102.0 builds on, SHA-256 `a5f63c41231f77e06959b979494e754d43817d382a820c95e0f5221401c90e81`.
  - npm, the per-user `~/.npmrc`: `https://docs.npmjs.com/cli/v11/configuring-npm/npmrc`.
  - git credential store, `~/.git-credentials`: `https://git-scm.com/docs/git-credential-store`.

<!-- FROZEN place-list fragment for holdout-rule.md v4. Generated from places_final.json. Do not hand-edit; regenerate from the pinned sources. -->

### The nonce places

The places a nonce may sit, with the technique that names each and the text that names it. The list is written from the pinned sources only (see the frozen-source manifest), never from the auditor's prompts. ATT&CK IDs are at Enterprise 19.2. Where a technique names only a class, the concrete default path is the owning software's documentation, named here and pinned in the manifest. Calibration keeps, per target, only the places that target's flaw alone reaches.

Reach: `read` = arbitrary file read, `exec` = command execution, `fetch` = server-side request.

**Family 1 host identity / accounts**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| Running process account identity (username + its /etc/passwd GECOS field), surfaced by whoami / id / getent passwd $USER | exec | T1003.008, T1033 | ATT&CK object - "Adversaries may attempt to identify the primary user, currently logged in user ... user and username details are prevalent throughout a system and include ru..." |
| /etc/shadow | read/exec | T1003.008 | ATT&CK object - "Adversaries attempt to read sensitive files such as /etc/passwd and /etc/shadow for credential dumping." |
| The container hostname (set at launch with --hostname), surfaced by hostname / uname -n / /etc/hostname / /proc/sys/kernel/hostname | read/exec | T1082 | ATT&CK object - "[TeamTNT] has searched for system version, architecture, and hostname information." |

**Family 2 generic user credential files**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| ~/.aws/credentials | read/exec | T1552.001 | ATT&CK object - "harvested credentials stored in config files and credential files ... to include `~/.aws/credentials`, `application_default_credentials.json`, and `azureProf..." |
| ~/.config/gcloud/application_default_credentials.json | read/exec | T1552.001 | ATT&CK object - "`~/.aws/credentials`, `application_default_credentials.json`, and `azureProfile.json`" |
| ~/.azure/azureProfile.json | read/exec | T1552.001 | ATT&CK object - "`~/.aws/credentials`, `application_default_credentials.json`, and `azureProfile.json`" |
| ~/.ssh/id_rsa (or id_ed25519) | read/exec | T1552.004 | ATT&CK object - "Script or user agent seen accessing keys (e.g., cat ~/.ssh/id_rsa, tar ~/.gnupg) ... Common key and certificate file extensions include: .key, .pgp, .gpg, .p..." |
| ~/.bash_history (or ~/.zsh_history) | read/exec | T1552.003 | ATT&CK object - "For each user, this file resides at the same location: for example, `~/.bash_history` or `~/.zsh_history`." |
| ~/.git-credentials | read/exec | T1552.001 | ATT&CK object - "gathered credentials from files stored in common credential file paths to include targeting git-credentials" |
| ~/.npmrc | read/exec | T1552.001 | ATT&CK object - "targeted credentials and tokens stored in NPM files `.npmrc` and GitHub config files" |
| ~/.config/gh/hosts.yml | read/exec | T1552.001 | owner-doc: GitHub CLI (~/.config/gh/hosts.yml) - "func hostsConfigFile() string { return filepath.Join(ConfigDir(), "hosts.yml") }" |
| ~/.docker/config.json | read/exec | T1552.001 | owner-doc: Docker (~/.docker/config.json); owner-doc: Docker CLI (~/.docker/config.json) - "By default, configuration file is stored in ~/.docker/config.json." |
| the server's .env file (dotenv process-secrets file, in its working directory) | read/exec | T1552.001 | ATT&CK object (class) + owner-doc: dotenv (.env in the working directory) - "configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords." |

**Family 3 database credential/config files**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| ~/.pgpass | read/exec | T1213.006 | ATT&CK object - "can extract credentials from multiple database configuration files including ~/.pgpass, ~/.my.cnf, ~/.mongorc.js, and /etc/mysql/my.cnf." |
| ~/.my.cnf | read/exec | T1213.006 | ATT&CK object - "~/.pgpass, ~/.my.cnf, ~/.mongorc.js, and /etc/mysql/my.cnf" |
| ~/.mongorc.js | read/exec | T1213.006 | ATT&CK object - "~/.pgpass, ~/.my.cnf, ~/.mongorc.js, and /etc/mysql/my.cnf" |
| /etc/mysql/my.cnf | read/exec | T1213.006 | ATT&CK object - "~/.pgpass, ~/.my.cnf, ~/.mongorc.js, and /etc/mysql/my.cnf" |

**Family 4 process environment and command line**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| /proc/self/environ (and /proc/<pid>/environ of the server process) | read/exec | T1083 | ATT&CK object - "[TeamTNT] has used a script that checks `/proc/*/environ` for environment variables related to AWS." |
| /proc/self/cmdline (and /proc/<pid>/cmdline; also surfaced by ps -ef) | read/exec | T1057 | ATT&CK object - "[UPSTYLE] has the ability to read `/proc/self/cmdline` to see if it is running as a monitored process." |

**Family 5 the server's own artifacts**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| The server's own source or installed file with an embedded (hardcoded) secret, inside the install dir above the served root | read/exec | T1552.001 | ATT&CK object - "source code/binary files containing embedded passwords." |
| The server's own configuration/state file holding its upstream credential or connection string (at the path the server software documents) | read/exec | T1552.001 | ATT&CK object - "configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords." |

**Family 6 container-native secret locations**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| ~/.kube/config (kubeconfig with cluster credentials) | read/exec | T1552.001 | owner-doc: kubectl (~/.kube/config) - "If the KUBECONFIG environment variable doesn't exist, kubectl uses the default kubeconfig file, $HOME/.kube/config." |
| /run/secrets/<secret_name> (Docker Compose / Swarm orchestrator-mounted secret) | read/exec | T1552.001 | owner-doc: Docker Compose (/run/secrets/<name>); owner-doc: Docker Compose (/run/secrets/<secret_name>) - "The location of the mount point within the container defaults to /run/secrets/<secret_name> in Linux containers" |
| /var/run/secrets/kubernetes.io/serviceaccount/token (and the directory it sits in) | read/exec | T1613 | ATT&CK object - "searched for Kubernetes pods using the command ` os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount") or "KUBERNETES_SERVICE_HOST" in os.environ `." |

**Family 7 internal / SSRF endpoints**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| http://169.254.169.254/ cloud instance metadata API (IMDS), alias metadata.google.internal | fetch/exec | T1552.005 | ATT&CK object - "Detects access attempts to cloud instance metadata endpoints (e.g., 169.254.169.254)" |
| http://169.254.170.2/v2/credentials/ (ECS/Fargate task container credentials endpoint) | fetch/exec | T1552.005 | owner-doc: AWS ECS (http://169.254.170.2/, $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) - "The value is appended to the default Amazon ECS hostname of 169.254.170.2." |
| http://169.254.170.23/v1/credentials (EKS Pod Identity Agent credentials endpoint) | fetch/exec | T1552.005 | owner-doc: AWS EKS Pod Identity (http://169.254.170.23/v1/credentials) - "EKS Pod Identity Agent ... occupying ports 80 and 2703 on the link-local address (169.254.170.23 for IPv4, [fd00:ec2::23] for IPv6)" |
| Docker daemon API (unix:///var/run/docker.sock, or TCP on the default bridge gateway 172.17.0.1:2375) | fetch/exec | T1552.007 | ATT&CK object - "APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components." |
| Kubernetes API server (https://kubernetes.default.svc / 10.96.0.1) | fetch | T1552.007 | ATT&CK object - "An adversary with sufficient permissions, such as via a pod's service account, may also use the Kubernetes API to retrieve credentials from the Kubernetes AP..." |
| loopback internal service (127.0.0.1:<port>, e.g. Redis on 6379) | fetch | T1046 | MCP spec - "Localhost services: URLs like http://localhost:6379/ can interact with local services (Redis, databases, admin panels)" |
| internal network service on a private range (10.0.0.0/8, 172.16.0.0/12 incl. the Docker bridge, 192.168.0.0/16; e.g. http://192.168.1.1/admin, http://10.0.0.1/api) | fetch/exec | T1046 | MCP spec - "Direct internal IP access: URLs like `http://192.168.1.1/admin` or `http://10.0.0.1/api` target internal network services" |

**Family 8 discovery / log places**

| Place | Reach | Technique | Names it |
|---|---|---|---|
| /etc/hosts | read/exec | T1018 | ATT&CK object - "Execution of built-in or AppleScript-based system enumeration via `arp`, `netstat`, `ping`, and discovery of `/etc/hosts` contents." |
| /var/log/auth.log (or /var/log/secure) authentication log | read/exec | T1654 | Falco rule access_log_files / log_files list (concrete only); owner-doc: rsyslog/Debian (/var/log/auth.log), RHEL (/var/log/secure) - "log_directories items: [/var/log, /dev/log] ... log_files items: [syslog, auth.log, secure, kern.log, cron, user.log, dpkg.log, last.log, yum.log, access_log..." |

## Eligibility

A flaw is eligible when all of these hold:

- it is a flaw of an MCP server, as defined above.
- the server runs over stdio, and the flaw is reached through `tools/call`.
- its effect shows in a tool response.
- a vulnerable version and the first patched version can both be pinned, as a release or a commit of a public source.
- both versions run in Docker.
- the calibration passes as it does on the acceptance layer: it keeps at least 1 place, and on the vulnerable version the nonce of every place it keeps surfaces in the response to at least one of the exploits written from the published mechanism, each exploit reading as aimed under the target's aim predicate, while the benign call surfaces no nonce and does not read as aimed. On the patched version, the benign call returns no error and no exploit surfaces a nonce.

The first four criteria are checkable from an advisory. With the first two exclusions below, they are the criteria of the draw order.

A flaw is excluded when any of these holds:

- it is a target of the CVE benchmark, now or before (the current targets are in `evals/cve_targets.py`, the dropped ones in the log).
- its server is an excluded server, listed in the log, or a package built from a repository GitHub marks as a fork of an excluded server's repository.
- for a drawn candidate, the maintainer finds that its vulnerable code is taken from an excluded server, and records the evidence in the census.

**Calibration.** Candidates are calibrated in draw order by an LLM agent. From the advisory and the published mechanism, it writes the fixture of the candidate and of its patched version, the listed places it keeps, its aim predicate, the exploits and the benign call. It sets no tools filter and no chain setting, which are conditions of the run. The launch it writes is the one the server documents, and no path or name it seeds refers to the flaw. It works from the fixture format, the grammar of the benchmark and the list of places, without access to the auditor's code, its prompts, its results or its traces. Its instructions are to make each candidate reproduce. It makes as many attempts as it needs, and gives up on a candidate only when it concludes that the calibration cannot pass in a container, with that reason in its own words. The census records the number of attempts and, for a give-up, its reason in one sentence. The maintainer does not exclude a candidate at calibration. When the agent gives up on a candidate, a second calibration follows at once, in a fresh context that receives the record of the first. A second give-up excludes the candidate, and both reasons are recorded.

**Calibration card.** For each candidate that passes, the agent writes a card into the census: the mechanism as the advisory states it, the class it files the target under, each place kept, with the reason only the flaw reaches it, each listed place whose reach the flaw has (read, exec or fetch, from its published mechanism) but that is not kept, with its reason, the exploit calls, the benign call, and the result on the patched version. A place is left out only because the flaw does not reach it, something other than the flaw reaches it, or it cannot be planted in a container, or for another reason the card states in full. A second LLM agent, without access to the auditor either, checks each card against the advisory, the fixture and the list of places, and reports to the maintainer any gap and every place left out for another reason. The maintainer reads, on every card, the mechanism, the exploit calls, the result on the patched version and every gap the second agent reports, before the candidate enters the holdout. A gap the maintainer confirms, criterion by criterion and recorded with its reason, sends the candidate back to calibration. Reading a card spends nothing.

## Sides

The cutoff of a draw is the latest knowledge cutoff the vendors declare for the models of the default configuration (generator and judge) at that draw, with its type (as the vendor words it, for instance training data or reliable knowledge), and with a note when the vendor only gives the cutoff of a base model. It is recorded in the log, as is the cutoff of every model a holdout run uses, with the same type and note. A flaw whose disclosure date is on or before it sits on the pre-cutoff side of that draw, a later one on the post-cutoff side. The sides of a draw only set the composition of the holdout: a run reports its split on the cutoff of its own models (see the split by side).

## Draw

The flaws are sorted in ascending order of the lowercase hexadecimal SHA-256 digest of the UTF-8 string `"mcp-auditor-holdout:" + id`, where `id` is the census identifier and the prefix is the salt. The order covers the flaws that meet the criteria of the draw order. Both sides are walked in that one order, each flaw filling its own side until the side holds 10 targets. Each flaw reached goes through these steps, in this order:

1. its disagreements are settled.
2. it is skipped, and the skip recorded, if its server already gives a target to the holdout, on either side.
3. the maintainer checks its vulnerable code against the excluded servers.
4. it is calibrated.

It enters only if it is still eligible, its calibration passes and the maintainer has read its calibration card as set out above. A flaw the walk passes over because its side is full is not reached. If the post-cutoff side ends with fewer than 10 targets, the walk takes up again the pre-cutoff flaws it passed over, in draw order, until the holdout holds 20 targets. Classes have no quota. If fewer than 20 flaws pass in all, the holdout takes every one that passes.

## Run conditions and statistic

Before each holdout run, every vulnerable and patched image is built again from its committed Dockerfile, with the build cache. Each target is then checked without an LLM, as at calibration, on both versions and for every place it keeps. A target that no longer passes, on either version, is reported as not run and left out of N, the number of targets the statistic counts, until its fixture is repaired. Repairing a fixture is calibration, done by the calibration agent, and spends nothing. The patched versions serve the check and the replay, and are not audited.

A holdout run audits every target at one commit, under these conditions:

- 3 runs, budget 10, no tools filter, and the list of targets.
- the chain settings (chains per tool, steps per chain, and any chain setting the auditor gains later) and the tool call timeout, the same for every target, set in the log before the first run that uses them.
- the provider, models and reasoning levels of the run, default or not, and their cutoff. A run refuses to start when the cutoff of one of its models is not in the log.
- the replay of every detecting run on the patched version of its target (ADR 030). The replay keeps or refuses each credit, the detection that the nonce of a unit gives the run, a unit being the case or chain the grammar grades as one.
- the grammar fingerprint, and the fixture fingerprint of each target, which covers its patched version.

The commit of this file, the commit of the census and the image ID of each target are recorded as provenance, not as conditions, as ADR 024 decides for image IDs.

If the cost of a holdout run has to come down, the runs go from 3 down to 1 before any target is cut, since only targets narrow the interval (ADR 015). The change is logged, and the new number of runs is a condition of the runs that follow. Lowering the chain settings is logged the same way.

**The primary number is the mean over the runs of k/N**, the share of targets detected in one run, averaged. A target counts as detected in a run when its status, after the replay, is in `DETECTION_RUNGS`. Its detection share is the fraction of the runs that detect it. The cited interval is the 95 % two-sided Wilson score interval, without continuity correction, over the N targets with the sum of the detection shares as the count, never over the N × runs verdicts. The number speaks about the eligible flaws under this rule, in the composition the draw gave each side, and not about MCP flaws at large.

Beside it, each holdout run reports the composition of each side and the full ladder of statuses. Per target, after the replay, it reports the target's class, the detection share, the runs where a nonce surfaced and from which places, the credits the replay refused, the credits it could not check, the runs where a unit aimed at the flaw, the runs where an aimed unit judged FAIL in a category its class admits surfaced no nonce (`fail_without_proof`), and the number of tools. It also reports the cost of the run in dollars, at the vendors' list prices on the day of the run.

**The split by side.** Each holdout run reports the primary number of each side of the cutoff of the models it runs, default or not. A side left short of targets by a later cutoff triggers no new target.

**The contrast between two sides** is a difference of proportions, with each side's sum of detection shares as its count, and its 95 % two-sided Newcombe hybrid score interval, without continuity correction, computed only when each side holds at least 5 targets. Below that, both sides are reported next to each other, without a test.

**Every conclusion drawn from an interval is checked.** A conclusion is a statement that an interval lies above or below a value, zero for the contrast. For the primary number: the Jeffreys and Clopper-Pearson intervals on the same count, Clopper-Pearson in its Beta-quantile form for a non-integer count, and the hierarchical Beta-Binomial credible interval with the target as cluster and its detected runs binomial over the runs (θ ~ Beta(1, 1), and d, the concentration of the per-target rates around θ, ~ Gamma(shape 1, scale 1), then ~ Gamma(shape 2, scale 2)). For the contrast: the Agresti-Caffo interval, and the difference of the two hierarchical posteriors with one d shared by both sides. Only the Wilson and Newcombe intervals are cited. A conclusion that changes with the method, or that changes when the credits the replay could not check count as misses, is reported as inconclusive, with the intervals that disagree.

**Two primary numbers compare** only under the same run conditions, as paired outcomes on the same targets: a target is gained when its detection share rises and lost when it falls. A target that either of the two did not run leaves the comparison. They never compare by the overlap of two intervals. Under other run conditions, they are reported side by side.

**An audit with a step refused by the model provider and no detection counts as not detected in that run**, and the number of such audits is reported, with the targets they touch. A detection stands whatever step was refused. A refused audit is not attempted again, unlike on the acceptance layer, since a retry until no step is refused would keep the best of several attempts. A failure to launch the fixture, or an audit that ends on any other error, is retried at most 2 times. A target that still fails in any run is reported as not run for the whole holdout run and left out of N, so N is the same in every run. A replay that fails to launch is retried the same way, and a credit still not replayed is kept and reported as unchecked.

## Reading

A holdout target is spent as ADR 015 defines it. So that running the holdout spends nothing, a holdout run writes and prints no proof text (`evidence`), no judge input and no verdict per case, only the statuses, the counts and the places above. The replay keeps the calls and the patched responses in memory only. The run exports no judged case, and refuses to start when `LANGSMITH_TRACING` or `LANGCHAIN_TRACING_V2` is set. Holdout targets stay out of every other instrument: the acceptance gate of ADR 024, the draw of the judge fixture and the probe corpus. Before the draw, the contamination test of ADR 014 is extended to the text the excluded servers produced in the CVE cases of the judge fixture (tool descriptions, responses and errors, the auditor's own payloads echoed back left out), and it passes on the code of that day. The auditor is then not fitted to the text of an excluded server, which a holdout server built on the same framework or the same conventions could also emit.

When the traces of a target feed a decision (a change to a prompt, a guard or the oracle, or a case of the judge fixture), its server is listed in the log as an excluded server the same day. Reading traces without such a decision spends the target read, not its server. A server excluded after a draw, or a package built from a fork of its repository, takes its drawn target out of the holdout, and the target is replaced.

Holdout traces are never read, except for an error analysis: a deliberate act, logged with its reason, that spends the target it reads. Its server is excluded only if the analysis leads to a decision as defined above.

No change to the auditor or to the list of places is made or reverted because of a holdout number. A change made or reverted because of a holdout number is reversed, and the reversal is logged.

A spent target moves to the acceptance layer, with a tools filter. It is replaced by the first flaw of its side, in draw order, that the walk has not yet reached, or of the pre-cutoff side when the post-cutoff side has none left, and the replacement is logged.

## Versioning

This is version 4. Any edit of this file, the list of places included, opens the next version. A new version keeps the salt and the draw order, and applies its criteria again: a target that stays eligible stays drawn, with its calibration, except that a change to the list of places sends the target back to calibration for the places the change adds or removes. A target that is no longer eligible leaves the holdout and is replaced as above. A flaw that becomes eligible enters only to fill such a vacancy. Adding targets, to grow the holdout or to bring the post-cutoff side to the 5 targets its contrast needs, is a deliberate new version, never automatic. It extends the census to the flaws disclosed since, under its own criteria and the same draw order, and sorts every flaw, old and new, into sides on the cutoff of its own draw. Its quotas and replacements count sides on that cutoff, and the targets already drawn stay drawn.
