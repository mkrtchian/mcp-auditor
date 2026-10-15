"""The schema bound as a tool, in with_structured_output's include_raw shape.

with_structured_output on a ChatAnthropic with thinking raises out of the call when the
model answers without the tool, before the raw message, and its stop_reason, can be read.
Here a missing tool call parses to None and the raw message is always returned.
"""

from operator import itemgetter
from typing import Any

from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_core.output_parsers.openai_tools import (
    JsonOutputKeyToolsParser,
    PydanticToolsParser,
)
from langchain_core.runnables import Runnable, RunnableMap, RunnablePassthrough
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel


def bind_schema_as_tool(
    model: BaseChatModel,  # pyright: ignore[reportMissingTypeStubs]
    output_schema: type[BaseModel],
    schema_as_dict: bool,
) -> Runnable[str, object]:
    schema: type[BaseModel] | dict[str, Any] = (
        output_schema.model_json_schema() if schema_as_dict else output_schema
    )
    tool_name: str = convert_to_openai_tool(schema)["function"]["name"]
    # bind_tools drops the forced tool_choice itself when thinking is on.
    llm = model.bind_tools([schema], tool_choice=tool_name)
    parser = (
        JsonOutputKeyToolsParser(key_name=tool_name, first_tool_only=True)
        if schema_as_dict
        else PydanticToolsParser(tools=[output_schema], first_tool_only=True)
    )
    parser_assign = RunnablePassthrough.assign(
        parsed=itemgetter("raw") | parser,
        parsing_error=lambda _: None,
    )
    parser_none = RunnablePassthrough.assign(parsed=lambda _: None)
    parser_with_fallback = parser_assign.with_fallbacks(
        [parser_none], exception_key="parsing_error"
    )
    return RunnableMap(raw=llm) | parser_with_fallback
