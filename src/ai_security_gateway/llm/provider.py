"""Opt-in OpenAI Responses adapter, with explicit attempt accounting and redaction."""

import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from threading import Lock
from time import perf_counter, sleep

import httpx
import openai
from pydantic import ValidationError

from ai_security_gateway.core.config import Settings
from ai_security_gateway.llm.models import (
    ClassificationOutcome,
    Classifier,
    ClassifierInput,
    ClassifierResponse,
    LLMStatus,
)
from ai_security_gateway.llm.prompts import CLASSIFIER_SYSTEM_PROMPT

OPENAI_BASE_URL = "https://api.openai.com/v1"


class RequestBudget:
    """Atomic slots: used counts transport handoffs; reserved counts pending slots."""

    def __init__(self, max_requests: int) -> None:
        if type(max_requests) is not int or max_requests < 0:
            raise ValueError("max_requests must be a nonnegative integer")
        self.max_requests = max_requests
        self._used = 0
        self._reserved = 0
        self._lock = Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def reserved(self) -> int:
        with self._lock:
            return self._reserved

    def reserve(self) -> "_Reservation | None":
        with self._lock:
            if self._used + self._reserved >= self.max_requests:
                return None
            self._reserved += 1
            return _Reservation(self)


class _Reservation:
    """One owner can commit or release a slot, including under concurrent cleanup."""

    def __init__(self, budget: RequestBudget) -> None:
        self._budget = budget
        self._pending = True

    def commit(self) -> None:
        with self._budget._lock:
            if not self._pending:
                raise ValueError("Reservation is no longer pending")
            self._budget._reserved -= 1
            self._budget._used += 1
            self._pending = False

    def release(self) -> bool:
        with self._budget._lock:
            if not self._pending:
                return False
            self._budget._reserved -= 1
            self._pending = False
            return True


@dataclass
class _CallState:
    requests: int = 0
    reservations: int = 0
    released_reservations: int = 0


class _LocalRequestError(openai.OpenAIError):
    """SDK propagates OpenAIError unchanged; only a closed diagnostic code is carried."""

    def __init__(self, status: LLMStatus) -> None:
        self.status = status
        super().__init__(status)


class _GuardedTransport(httpx.BaseTransport):
    """Validate the final request after SDK/auth/hooks, then account for the handoff."""

    def __init__(self, owner: "OpenAIClassifier", delegate: httpx.BaseTransport) -> None:
        self._owner = owner
        self._delegate = delegate

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        expected = {
            "Authorization": "Bearer " + self._owner.settings.llm_api_key.get_secret_value(),
            "OpenAI-Project": "",
            "OpenAI-Organization": "",
        }
        # get_list is case-insensitive and retains duplicate values. Even identical
        # duplicates are rejected rather than letting a server choose a credential.
        if any(request.headers.get_list(name) != [value] for name, value in expected.items()):
            raise _LocalRequestError("invalid_headers")
        state = self._owner._call_state.get()
        if state is None:
            raise _LocalRequestError("request_preparation_error")
        reservation = None
        try:
            if self._owner.budget is not None:
                reservation = self._owner.budget.reserve()
                if reservation is None:
                    raise _LocalRequestError("budget_exhausted")
                state.reservations += 1
                reservation.commit()
            # An attempt starts when the completed request reaches the delegate,
            # not when a client is created or a response arrives. No refund on timeout.
            state.requests += 1
            return self._delegate.handle_request(request)
        finally:
            if reservation is not None and reservation.release():
                state.released_reservations += 1

    def close(self) -> None:
        self._delegate.close()


def configuration_status(settings: Settings) -> LLMStatus | None:
    if not settings.enable_llm_analysis:
        return "disabled"
    if not settings.allow_external_llm:
        return "external_not_allowed"
    if settings.llm_provider != "openai":
        return "unsupported_provider"
    if not settings.llm_api_key.get_secret_value().strip():
        return "missing_key"
    if any(not 33 <= ord(c) <= 126 for c in settings.llm_api_key.get_secret_value()):
        return "invalid_configuration"
    if not settings.llm_model:
        return "missing_model"
    return None


def _silence_provider_logs() -> None:
    """SDK/HTTP debug logs can contain payloads; disable those namespaces explicitly.

    This is process-wide, as Python logging is. It intentionally overrides OPENAI_LOG
    without reading or changing the environment or affecting application diagnostics.
    """
    for namespace in ("openai", "httpx", "httpcore"):
        logger = logging.getLogger(namespace)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        logger.disabled = True
        for name in list(logging.Logger.manager.loggerDict):
            if name.startswith(namespace + "."):
                logging.getLogger(name).disabled = True


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_response(
    response: object,
) -> tuple[LLMStatus, ClassifierResponse | None, int | None, int | None]:
    """The provider envelope and model JSON are untrusted; never return their free text."""
    # SDK constructs provider envelopes permissively. Serialization warnings can include
    # their raw values, so suppress those warnings and validate the relevant shape below.
    data = response.model_dump(warnings=False)
    usage = data.get("usage") or {}
    counts = [usage.get("input_tokens"), usage.get("output_tokens")]
    input_tokens, output_tokens = [
        value if type(value) is int and value >= 0 else None for value in counts
    ]
    if data.get("status") == "incomplete":
        return "incomplete", None, input_tokens, output_tokens
    if data.get("status") != "completed" or data.get("error") is not None:
        return "provider_error", None, input_tokens, output_tokens
    if data.get("incomplete_details") is not None:
        return "incomplete", None, input_tokens, output_tokens
    messages = []
    for item in data.get("output", []):
        if item.get("type") == "reasoning":
            continue
        if item.get("type") != "message" or item.get("role") != "assistant":
            return "invalid_response", None, input_tokens, output_tokens
        if item.get("status") != "completed":
            return "incomplete", None, input_tokens, output_tokens
        messages.append(item)
    if any(
        part.get("type") == "refusal" for message in messages for part in message.get("content", [])
    ):
        return "refusal", None, input_tokens, output_tokens
    if len(messages) != 1:
        return "invalid_response", None, input_tokens, output_tokens
    content = messages[0].get("content", [])
    if len(content) != 1 or content[0].get("type") != "output_text":
        return "invalid_response", None, input_tokens, output_tokens
    try:
        raw = json.loads(content[0]["text"], object_pairs_hook=_unique_object)
        result = ClassifierResponse.model_validate(raw)
    except (ValueError, TypeError, KeyError, RecursionError, ValidationError):
        return "invalid_response", None, input_tokens, output_tokens
    status = "uncertain" if result.verdict == "uncertain" else "success"
    return status, result, input_tokens, output_tokens


class DisabledClassifier:
    def __init__(self, status: LLMStatus = "disabled", model: str | None = None) -> None:
        self.status = status
        self.model = model

    @property
    def uses_network(self) -> bool:
        return False

    def classify(self, data: ClassifierInput) -> ClassificationOutcome:
        return ClassificationOutcome(
            status=self.status,
            fallback_reason=None if self.status == "disabled" else self.status,
            model=self.model,
        )

    def close(self) -> None:
        pass


class OpenAIClassifier:
    """Sync SDK calls belong in the existing FastAPI worker-pool routes.

    Inject only a trusted offline httpx transport in tests. No URL, model, credentials,
    provider settings, labels or system messages are accepted from analyzed content.
    """

    def __init__(
        self,
        settings: Settings,
        budget: RequestBudget | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.budget = budget
        self._transport = transport
        self._client: openai.OpenAI | None = None
        self._lock = Lock()
        self._closed = False
        self._call_state: ContextVar[_CallState | None] = ContextVar("llm_call", default=None)
        _silence_provider_logs()

    @property
    def uses_network(self) -> bool:
        """Whether this instance can use network transport.

        Only an explicitly injected MockTransport is recognized as offline. Its
        handler remains trusted code; arbitrary other transports require opt-in.
        """
        return not isinstance(self._transport, httpx.MockTransport)

    def _get_client(self) -> openai.OpenAI:
        with self._lock:
            if self._client is None:
                http_client = httpx.Client(
                    timeout=self.settings.llm_timeout_seconds,
                    trust_env=False,
                    follow_redirects=False,
                    transport=_GuardedTransport(
                        self,
                        self._transport
                        if self._transport is not None
                        else httpx.HTTPTransport(trust_env=False, retries=0),
                    ),
                )
                try:
                    client = openai.OpenAI(
                        api_key=self.settings.llm_api_key.get_secret_value(),
                        base_url=OPENAI_BASE_URL,
                        organization="",
                        project="",
                        max_retries=0,
                        timeout=self.settings.llm_timeout_seconds,
                        http_client=http_client,
                    )
                    # SDK 2.54 merges OPENAI_CUSTOM_HEADERS even with default_headers={}.
                    # Its instance-local mapping is cleared before publication; os.environ
                    # and other SDK clients are untouched. Fail closed on incompatible SDKs.
                    if not isinstance(client._custom_headers, dict):
                        raise _LocalRequestError("request_preparation_error")
                    client._custom_headers = {}
                    self._client = client
                except Exception:
                    http_client.close()
                    raise
            return self._client

    def classify(self, data: ClassifierInput) -> ClassificationOutcome:
        started = perf_counter()
        state = _CallState()
        status = configuration_status(self.settings)
        result = None
        input_tokens = output_tokens = None
        if status is None and self._closed:
            status = "closed"
        if status is None and data.input_chars > self.settings.llm_max_input_chars:
            status = "skipped_too_large"
        if status is None:
            # One classification operation per input; retries are explicit HTTP attempts.
            for retry in range(self.settings.llm_max_retries + 1):
                requests_before = state.requests
                retryable = False
                _silence_provider_logs()
                token = self._call_state.set(state)
                try:
                    response = self._get_client().responses.create(
                        model=self.settings.llm_model,
                        input=[
                            {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
                            {"role": "user", "content": data.model_dump_json(exclude_none=True)},
                        ],
                        text={
                            "format": {
                                "type": "json_schema",
                                "name": "injection_verdict",
                                "strict": True,
                                "schema": ClassifierResponse.model_json_schema(),
                            }
                        },
                        max_output_tokens=self.settings.llm_max_output_tokens,
                        store=False,
                    )
                    status, result, input_tokens, output_tokens = _parse_response(response)
                except _LocalRequestError as error:
                    status = error.status
                except openai.APITimeoutError:
                    retryable = state.requests > requests_before
                    status = "timeout" if retryable else "request_preparation_error"
                except openai.APIConnectionError:
                    retryable = state.requests > requests_before
                    status = "network_error" if retryable else "request_preparation_error"
                except openai.APIStatusError as error:
                    status = {
                        401: "unauthorized",
                        403: "forbidden",
                        429: "rate_limited",
                        408: "timeout",
                    }.get(error.status_code, "provider_error")
                    retryable = error.status_code in {408, 429} or error.status_code >= 500
                except (ValueError, TypeError, AttributeError, KeyError):
                    status = (
                        "invalid_response"
                        if state.requests > requests_before
                        else "request_preparation_error"
                    )
                except Exception:
                    # Provider boundary: SDK/transport failures may contain input in messages.
                    # Keep rules available, with an explicit failure; never log the exception.
                    status = (
                        "provider_error"
                        if state.requests > requests_before
                        else "request_preparation_error"
                    )
                finally:
                    self._call_state.reset(token)
                if not retryable or retry == self.settings.llm_max_retries:
                    break
                if self.budget is None or self.budget.used < self.budget.max_requests:
                    sleep(0.25 * 2**retry)
        return ClassificationOutcome(
            result=result,
            status=status,
            fallback_reason=None if status in {"success", "disabled"} else status,
            model=self.settings.llm_model or None,
            requests=state.requests,
            reservations=state.reservations,
            released_reservations=state.released_reservations,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            elapsed_ms=(perf_counter() - started) * 1000,
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._client is not None:
                self._client.close()


def build_classifier(settings: Settings, budget: RequestBudget | None = None) -> Classifier:
    status = configuration_status(settings)
    if status is not None:
        return DisabledClassifier(status, settings.llm_model or None)
    return OpenAIClassifier(settings, budget)
