import logging
import time
from os import getenv
from typing import Any, Dict, Literal, cast

import jwt
import msal
import requests
from bokeh.models.widgets import Div
from dotenv import load_dotenv
from streamlit import bokeh_chart, session_state, sidebar
from streamlit.web.server.websocket_headers import _get_websocket_headers

logger = logging.getLogger(__name__)
dotenv_location = None

website_hostname = getenv("WEBSITE_HOSTNAME") or getenv("RADIX_PUBLIC_DOMAIN_NAME") or "localhost"
if website_hostname == "localhost":
    load_dotenv(dotenv_location)

verbose = False
tenant_id = "3aa4a235-b6e2-48d5-9195-7fcf05b459b0"
authority = f"https://login.microsoftonline.com/{tenant_id}"
sdf_db_client_id = "fd995666-d037-4964-a554-8a5ab446e508"
sdf_db_client_secret = getenv("arwebappsecret", getenv("sdf-db-client-secret"))
auth_endpoints = {
    "login": "/.auth/login/aad",
    "logout": "/.auth/logout",
    "logout_local": "/common/oauth2/v2.0/logout",
    "me": "/.auth/me",
}
request_timeout = 30


def _on_behalf_of(client_id: str, client_secret: str, user_assertion: str, scopes: list[str]) -> Dict[Any, Any]:
    """
    Acquires a token on behalf of a user using the Microsoft Authentication Library (MSAL).

    Parameters:
    client_id (str): The client ID of the application.
    client_secret (str): The client secret of the application.
    user_assertion (str): The assertion about the user.
    scopes (list[str]): The scopes for which the token is requested.

    Returns:
    Dict[Any, Any]: The result of the token acquisition.
    """
    if verbose:
        logger.info(f"Acquiring token on behalf of user (client_id: {client_id}, scopes: {scopes})")
    app = msal.ConfidentialClientApplication(client_id=client_id, authority=authority, client_credential=client_secret)

    result: dict[Any, Any] = app.acquire_token_on_behalf_of(scopes=scopes, user_assertion=user_assertion)

    return result


def _init_session(key: str) -> None:
    """
    Initializes a session with a given key.

    Parameters:
    key (str): The key for the session to be initialized.
    """
    if key not in session_state:
        session_state[key] = None


def _read_session(key: str) -> Any:
    """
    Reads the value of a given key from the session state.

    Parameters:
    key (str): The key for the session to be read.

    Returns:
    The value associated with the key in the session state.
    """
    return session_state[key]


def _update_session(key: str, value: Any) -> None:
    """
    Updates the session state with a new value for a given key.

    Parameters:
    key (str): The key for the session to be updated.
    value (Any): The new value to be set for the session.
    """
    session_state[key] = value


def _refresh_token(refresh_token: str, client_id: str, client_secret: str, session_name: str) -> None:
    """
    Refreshes an OAuth 2.0 token.

    Parameters:
    refresh_token (str): The refresh token to be used.
    client_id (str): The client ID of the application.
    client_secret (str): The client secret of the application.
    session_name (str): The name of the session to be refreshed.
    """
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "client_id": client_id,
    }
    response = requests.post(token_url, data=data, timeout=request_timeout)

    if response.status_code == 200:
        response_data = response.json()
        _update_session(key=session_name, value=response_data)


def _get_access_token(key: str) -> str:
    """
    Retrieves the access token from the session state for a given key.

    Parameters:
    key (str): The key for the session to be read.

    Returns:
    str: The access token associated with the key in the session state.
    """
    try:
        session = _read_session(key=key)
        access_token: str = session["access_token"]
        return access_token
    except KeyError:
        raise ValueError(f"Could not find access token for {key}")


def _get_refresh_token(key: str) -> str:
    """
    Retrieves the refresh token from the session state for a given key.

    Parameters:
    key (str): The key for the session to be read.

    Returns:
    str: The refresh token associated with the key in the session state.
    """
    try:
        session = _read_session(key=key)
        refresh_token: str = session["refresh_token"]
        return refresh_token
    except KeyError:
        raise ValueError(f"Could not find refresh token for {key}")


def _get_expiration_time(session_name: str) -> int:
    """
    Retrieves the expiration time from the decoded token stored in the session state.

    Parameters:
    session_name (str): The name of the session from which to get the expiration time.

    Returns:
    int: The expiration time of the token.
    """
    try:
        token = jwt.decode(_get_access_token(key=session_name), options={"verify_signature": False})
        expiration: int = token.get("exp")
        return expiration
    except KeyError:
        raise ValueError(f"Could not find expiration for {session_name}")


local_app = None


def _request_tokens() -> tuple[Any, Any]:
    """
    Manages tokens for different services. Initializes sessions for `sdf_db_token`.
    Refreshes or requests new tokens as needed. Retrieves the `access_token` from each session and returns them.

    Returns:
    tuple: The access tokens for the  `sdf_db_token` sessions.
    """
    global local_app
    headers = Headers()
    current_time = time.time()
    session_name_sdf_db = "sdf_db_token"
    session_name_database = "database_token"

    _init_session(key=session_name_sdf_db)
    _init_session(key=session_name_database)

    if _read_session(key=session_name_sdf_db) is None and website_hostname == "localhost":
        if "local_app" not in session_state:
            session_state.local_app = msal.PublicClientApplication(client_id=sdf_db_client_id, authority=authority)
        accounts = session_state.local_app.get_accounts()
        if accounts:
            result = session_state.local_app.acquire_token_silent(
                scopes=[f"api://{sdf_db_client_id}/user_impersonation"],
                account=accounts[0],
            )
        else:
            result = session_state.local_app.acquire_token_interactive(
                scopes=[f"api://{sdf_db_client_id}/user_impersonation"]
            )

        if result is None:
            logger.warning("Failed to acquire token.")
            return None, None

        data = {
            "access_token": result.get("access_token"),
            "refresh_token": result.get("refresh_token"),
        }

        _update_session(key=session_name_sdf_db, value=data)

    elif _read_session(key=session_name_sdf_db) is None:
        data = {
            "access_token": headers.access_token,
            "refresh_token": headers.refresh_token,
        }
        _update_session(key=session_name_sdf_db, value=data)

    if sdf_db_client_secret is not None and _read_session(key=session_name_sdf_db) is not None:
        if _get_expiration_time(session_name=session_name_sdf_db) < current_time:
            _refresh_token(
                client_id=sdf_db_client_id,
                client_secret=sdf_db_client_secret,
                refresh_token=_get_refresh_token(key=session_name_sdf_db),
                session_name=session_name_sdf_db,
            )

        if (
            _read_session(key=session_name_database) is None
            or _get_expiration_time(session_name=session_name_database) <= current_time
        ):
            logger.info("Requesting new database token")
            database_result = _on_behalf_of(
                client_id=sdf_db_client_id,
                client_secret=sdf_db_client_secret,
                user_assertion=_get_access_token(key=session_name_sdf_db),
                scopes=["https://database.windows.net/user_impersonation"],
            )
            _update_session(key=session_name_database, value=database_result)

    sdf_db_token = _get_access_token(key=session_name_sdf_db)
    database_token = _get_access_token(key=session_name_database)

    return sdf_db_token, database_token


def _authenticated() -> bool:
    """
    Checks if the user is authenticated by sending a GET request to the server.

    The server's response is used to determine if the user is authenticated.
    A status code of 200 indicates that the user is authenticated.

    Returns:
    bool: True if the user is authenticated, False otherwise.
    """
    global local_app
    if website_hostname == "localhost":
        if "local_app" not in session_state:
            session_state.local_app = msal.PublicClientApplication(client_id=sdf_db_client_id, authority=authority)

        accounts = session_state.local_app.get_accounts()

        if accounts:
            return True

        return False

    tokens = Tokens()

    headers = {"Authorization": f"Bearer {tokens.sdf_db_token}"}
    response = requests.get(
        f"https://{website_hostname}{auth_endpoints['me']}", headers=headers, timeout=request_timeout
    )
    is_authenticated: bool = response.status_code == 200

    return is_authenticated


def authenticate_button() -> None:
    """
    Checks if the user is authenticated and redirects them to the appropriate route.

    If the user is authenticated, they are redirected to the logout route.
    If the user is not authenticated, they are redirected to the login route.
    """

    def _redirect_button(text: str, route: str, action: str) -> None:
        """
        Creates a button that redirects the user to a specified route when clicked.

        Parameters:
        text (str): The text to display on the button.
        route (str): The route to redirect to when the button is clicked.
        """
        button_type = cast(Literal["primary", "secondary"], "primary" if action == "logout" else "secondary")

        if sidebar.button(text, type=button_type):
            if website_hostname == "localhost":
                global local_app
                if "local_app" in session_state:
                    accounts = session_state.local_app.get_accounts()

                    if accounts:
                        session_state.local_app.remove_account(accounts[0])
                        if action == "logout":
                            js = f"window.location.href = 'https://{website_hostname}{auth_endpoints['logout_local']}'"
                            html = '<img src onerror="{}">'.format(js)
                            div = Div(text=html)
                            bokeh_chart(div)

            else:
                js = f"window.location.href = 'https://{website_hostname}{route}'"
                html = '<img src onerror="{}">'.format(js)
                div = Div(text=html)
                bokeh_chart(div)

    if _authenticated():
        _redirect_button("Logout", auth_endpoints["logout"], action="logout")
    else:
        _redirect_button("Login", auth_endpoints["login"], action="login")


class Headers:
    """
    A class used to manage the headers for a websocket connection.
    """

    def __init__(self) -> None:
        """
        Initializes the Headers class with the principal name, access token,
        and refresh token from the websocket headers.
        Raises an exception if any of these values are None.
        """
        headers = _get_websocket_headers()

        if headers is not None:
            if website_hostname == "localhost":
                return
            self.principal_name = headers.get("X-Ms-Client-Principal-Name") or headers.get("X-Auth-Request-Email")
            self.access_token = headers.get("X-Ms-Token-Aad-Access-Token") or headers.get("X-Auth-Request-Access-Token")
            self.refresh_token = headers.get("X-Ms-Token-Aad-Refresh-Token")

            for k, v in vars(self).items():
                if v is None:
                    logger.info(f"{k} is None")


class Tokens:
    """
    A class used to manage tokens for different services.
    """

    def __init__(self) -> None:
        """
        Initializes the Tokens class with the pdm_token, timeseries_token,
        and sdf_db_token obtained from the request_tokens function.
        """
        self.sdf_db_token, self.database_token = _request_tokens()
