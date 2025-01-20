import ssl
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Client(BaseModel):
    """
    A base client for managing API-related configurations and requests.

    Attributes:
        raise_on_unexpected_status (bool): Whether to raise an error for unexpected HTTP status codes.
        _base_url (str): The base URL for the API.
        _cookies (dict[str, str]): Cookies to be sent with requests.
        _headers (dict[str, str]): Headers to be sent with requests.
        _timeout (httpx.Timeout | None): The timeout for requests.
        _verify_ssl (bool): Whether to verify the server's SSL certificate.
        _follow_redirects (bool): Whether to follow HTTP redirects.
        _httpx_args (dict[str, Any]): Additional arguments for the `httpx.Client` or `httpx.AsyncClient`.
        _client (httpx.Client | None): An instance of the `httpx.Client`.
        _async_client (httpx.AsyncClient | None): An instance of the `httpx.AsyncClient`.
    """

    model_config = ConfigDict(extra="allow")

    raise_on_unexpected_status: bool = Field(default=False)
    _base_url: str
    _cookies: dict[str, str] = Field(default_factory=dict)
    _headers: dict[str, str] = Field(default_factory=dict)
    _timeout: httpx.Timeout | None = None
    _verify_ssl: bool = False
    _follow_redirects: bool = False
    _httpx_args: dict[str, Any]
    _client: httpx.Client | None = None
    _async_client: httpx.AsyncClient | None = None

    @model_validator(mode="before")
    def validate_ssl_context(cls, values: dict[str, Any]) -> dict[str, Any]:
        """
        Validates the `_verify_ssl` attribute.

        Args:
            values (dict[str, Any]): The dictionary of attributes to validate.

        Returns:
            dict[str, Any]: The validated attributes.
        """
        if isinstance(values.get("_verify_ssl"), ssl.SSLContext):
            values["_verify_ssl"] = values["_verify_ssl"]
        return values

    def with_headers(self, headers: dict[str, str]) -> "Client":
        """
        Returns a new client instance with additional headers.

        Args:
            headers (dict[str, str]): The additional headers to include.

        Returns:
            Client: A new instance of the client with updated headers.
        """
        updated_headers = {**self._headers, **headers}
        return self.model_copy(update={"_headers": updated_headers})

    def with_cookies(self, cookies: dict[str, str]) -> "Client":
        """
        Returns a new client instance with additional cookies.

        Args:
            cookies (dict[str, str]): The additional cookies to include.

        Returns:
            Client: A new instance of the client with updated cookies.
        """
        updated_cookies = {**self._cookies, **cookies}
        return self.model_copy(update={"_cookies": updated_cookies})

    def with_timeout(self, timeout: httpx.Timeout) -> "Client":
        """
        Returns a new client instance with an updated timeout.

        Args:
            timeout (httpx.Timeout): The timeout to set.

        Returns:
            Client: A new instance of the client with the updated timeout.
        """
        return self.model_copy(update={"_timeout": timeout})

    def set_httpx_client(self, client: httpx.Client) -> "Client":
        """
        Sets the underlying HTTP client instance.

        Args:
            client (httpx.Client): An instance of `httpx.Client`.

        Returns:
            Client: The current client instance with the updated HTTP client.
        """
        self._client = client
        return self

    def get_httpx_client(self) -> httpx.Client:
        """
        Returns the HTTP client instance, creating one if necessary.

        Returns:
            httpx.Client: The HTTP client instance.
        """
        if self._client is None:
            self._client = httpx.Client(
                base_url=self._base_url,
                cookies=self._cookies,
                headers=self._headers,
                timeout=self._timeout,
                verify=self._verify_ssl,
                follow_redirects=self._follow_redirects,
                **self._httpx_args,
            )
        return self._client

    def __enter__(self) -> "Client":
        """
        Enters a context manager for the HTTP client.

        Returns:
            Client: The current client instance.
        """
        self.get_httpx_client().__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        """
        Exits the context manager for the HTTP client.

        Args:
            *args: The context manager arguments.
        """
        self.get_httpx_client().__exit__(*args)

    def set_async_httpx_client(self, async_client: httpx.AsyncClient) -> "Client":
        """
        Sets the underlying asynchronous HTTP client instance.

        Args:
            async_client (httpx.AsyncClient): An instance of `httpx.AsyncClient`.

        Returns:
            Client: The current client instance with the updated async HTTP client.
        """
        self._async_client = async_client
        return self

    def get_async_httpx_client(self) -> httpx.AsyncClient:
        """
        Returns the asynchronous HTTP client instance, creating one if necessary.

        Returns:
            httpx.AsyncClient: The async HTTP client instance.
        """
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self._base_url,
                cookies=self._cookies,
                headers=self._headers,
                timeout=self._timeout,
                verify=self._verify_ssl,
                follow_redirects=self._follow_redirects,
                **self._httpx_args,
            )
        return self._async_client

    async def __aenter__(self) -> "Client":
        """
        Enters an asynchronous context manager for the HTTP client.

        Returns:
            Client: The current client instance.
        """
        await self.get_async_httpx_client().__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """
        Exits the asynchronous context manager for the HTTP client.

        Args:
            *args: The context manager arguments.
        """
        await self.get_async_httpx_client().__aexit__(*args)


class AuthenticatedClient(Client):
    """
    A subclass of `Client` that adds support for authentication.

    Attributes:
        token (str): The authentication token to use.
        prefix (str): The prefix for the authorization header (e.g., "Bearer").
        auth_header_name (str): The name of the authorization header.
    """

    token: str
    prefix: str = "Bearer"
    auth_header_name: str = "Authorization"

    def get_httpx_client(self) -> httpx.Client:
        """
        Returns the HTTP client instance with authentication, creating one if necessary.

        Returns:
            httpx.Client: The authenticated HTTP client instance.
        """
        if self._client is None:
            self._headers[self.auth_header_name] = (
                f"{self.prefix} {self.token}" if self.prefix else self.token
            )
            return super().get_httpx_client()
        return self._client

    def get_async_httpx_client(self) -> httpx.AsyncClient:
        """
        Returns the asynchronous HTTP client instance with authentication, creating one if necessary.

        Returns:
            httpx.AsyncClient: The authenticated async HTTP client instance.
        """
        if self._async_client is None:
            self._headers[self.auth_header_name] = (
                f"{self.prefix} {self.token}" if self.prefix else self.token
            )
            return super().get_async_httpx_client()
        return self._async_client
