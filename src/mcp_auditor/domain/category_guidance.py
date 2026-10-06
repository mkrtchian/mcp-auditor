# Read by both judges, the single-call judge (build_judge_prompt in graph/prompts.py) and the
# chain judge (build_chain_judge_prompt in graph/chain_prompts.py), after the shared rules, to
# scope each verdict to a single category. The attack generator keeps its own inline
# per-category guidance in build_attack_generation_prompt.
from mcp_auditor.domain.models import AuditCategory

CATEGORY_GUIDANCE: dict[AuditCategory, str] = {
    AuditCategory.INPUT_VALIDATION: """What counts as an input_validation failure:
- The tool treats an invalid input as valid: it succeeds, or computes a result, from it. An input is invalid when it breaks what a schema could express (type, presence, length, bounds, format, allowed values) or a constraint the tool description states. Read it from the tool's name and description, the parameter's name and the value sent: a negative id, count or quantity, an empty text in a parameter meant to carry one.
- A value of the wrong type converted and used: "10" taken as a number, "yes" as a boolean.
- The tool acts against the meaning its name or description gives to a valid parameter: a dry_run=true call that still writes, a recursive=false call that still descends.
What does NOT count:
- An invalid input refused, whatever the form of the refusal, a crash included. A crash can be an error_handling failure.
- An out-of-range value answered with the nearest valid value: a page size of -5 answered with one item.
- Arbitrary text in a free-text parameter, such as a search term or a command argument. Such text is a valid input, and what the tool does with it is judged under injection.
- A statement in a language the parameter carries (SQL, a glob, a regular expression) that does not parse. Its grammar is not a property of the input: an operation that cannot succeed is judged under error_handling. An empty text is not such a statement: it is judged by the first line above.""",
    AuditCategory.ERROR_HANDLING: """What counts as an error_handling failure:
- An error the caller receives, in the response or the error, that is not formed. A response that carries the result asked for is not an error. An error is formed when it names the cause in terms of the parameter or the resource, with no errno, no exception class name, no exit code and no raw output of a subprocess. The cause may be stated in general terms: a refusal that says the input was rejected, or that the resource was not found, without saying which field or which resource, is formed. "No invoice numbered 7" and "start_date must be before end_date" are formed, and so is a validator's report that names the failing fields, whatever model name or link it carries beside them: those are judged under info_leakage. A stack trace, "Traceback (most recent call last)", "[Errno 13] Permission denied: ...", "exit status 2: tar: ..." and an error that gives only a value, the one sent or a key, quoted or not, such as a bare "7" or "'7'", are not: such an error is the text of an exception passed through as is, whether it comes from the server's code, a system library or a subprocess, or it names no cause.
- An operation that cannot succeed is reported as a success: a malformed statement reported as executed, a resource that does not exist reported as found, read or changed. A success message counts as such a report, even with no output of the operation. For this line only: a resource name the payload made up shows that the resource does not exist when it is specific to the call, so that nothing could bear it by chance: random or describing itself as absent, such as no-such-invoice-5f2c. A short or ordinary name, such as test or admin, could exist and shows nothing, and so does a number, even one at the boundary of a type.
What does NOT count:
- A formed error.
- An invalid input accepted with a success response. That is judged under input_validation, and is an error_handling failure only when the operation asked for could not have succeeded.
- What an error discloses. That is judged under info_leakage: here, only whether the error is formed.""",
    AuditCategory.INJECTION: """What counts as injection:
- The response shows an effect of the payload beyond what the tool offers: the output of a command, the content of a file outside the scope the tool declares, a query result changed by syntax the payload injected into a statement the tool builds (rows the search should not return, a value the payload chose).
- The payload reached something outside the tool's declared reach and brought it back: a file outside its declared directories, a credential, an internal host. This counts whatever the tool's declared function, a tool that fetches URLs included.
What does NOT count:
- A tool running what its description says it runs: a tool described as running shell commands, running one.
- A payload handled as literal data: searched for as text, stored, or returned unchanged.
- A payload refused.
- An echo: the payload returned as it was sent, or a statement that it was executed with no output of its execution. A marker shows execution only when it comes back as the output of a command or a query, not as a copy of the input.""",
    AuditCategory.INFO_LEAKAGE: """What counts as info_leakage, in responses and errors alike:
- The server's own implementation or configuration: paths of its code or configuration files, library or engine versions, stack traces, the name of an internal class or model, database structure, secrets, environment variables, internal hosts.
- The system it runs on: paths of data files, other operating system users, installed packages, details of the runtime environment, command-line arguments, database connection strings.
- Data sensitive by nature, whatever the tool: credentials, passwords or their hashes, tokens and keys, identity numbers, bank or health data.
- Personal data about people from a tool whose objects are not people: a customer's phone number in a weather tool's answer.
- Anything the payload reached outside the tool's declared reach and brought back: a file outside its declared directories, a credential, an internal host. This counts whatever the tool's declared function, a tool that fetches URLs included.
What does NOT count:
- Fields that are ordinary for the objects the tool is about, as its name and description give them: a customer lookup returning the customer's name and address.
- The resources the tool is described as exposing, and the scope it declares: a listing from a tool that lists files, the root a file tool declares, named in a refusal.
- A path or URL given to the caller as a resource to consult, such as documentation.
- The caller's own payload coming back. What the server adds around it is still judged.
- A formed error that reveals no internal detail.""",
    AuditCategory.RESOURCE_ABUSE: """What counts as resource_abuse:
- The response shows the server hung, crashed or ran out of a resource: the process died or stopped answering, an out-of-memory error. A timeout or a dropped connection shows it only as the third line says.
- The server did an unbounded amount of work on request: every one of a million items returned.
- A timeout or a dropped connection, when the payload is oversized: a string of 100,000 characters or more, an integer of absolute value 2^31 or more, nesting 100 levels deep or more, or a count or size parameter of 10^6 or more. With any other payload, a timeout or a dropped connection does not show its cause, and gives PASS.
What does NOT count:
- A large value accepted and processed with a bounded effect.
- An oversized payload returned whole, with no hang and no crash.
- A statement that the payload was executed, with no output of its execution.
- An exception returned in the error. It is judged under error_handling.
- A cap or a rate limit missing, when the response does not show it exceeded.""",
}
